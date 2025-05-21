// ============================================================================
// MetaMask Delegation Toolkit Multisig Example
// ----------------------------------------------------------------------------
// This script demonstrates how to:
// 1. Set up a Hybrid (delegator) smart account.
// 2. Delegate authority from the Hybrid to a TACo EIP-1271 MultiSig contract.
// 3. Have the EIP-1271 MultiSig authorize a call to the DelegationManager to redeem the delegation.
// 4. The redemption instructs the Hybrid account to return funds to a local EOA.
// 5. The transaction to trigger the EIP-1271 MultiSig is sent by the local EOA.
//
// This file is designed as a readable, step-by-step tutorial for developers.
// ============================================================================

import { 
    createDelegation,
    getDeleGatorEnvironment,
    DeleGatorEnvironment,
    Implementation,
    toMetaMaskSmartAccount,
    DelegationFramework,
    SINGLE_DEFAULT_MODE,
    createExecution,
} from '@metamask/delegation-toolkit';
import { ethers } from 'ethers';
import { Address, createPublicClient, Hex, http, parseEther, zeroAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { 
    createPaymasterClient,
    createBundlerClient,
} from 'viem/account-abstraction';
import { baseSepolia } from 'viem/chains';
import * as dotenv from 'dotenv';
import winston, { Logger } from 'winston';

// Import from the new Porter Signer library
import {
    getPorterChecksums as getPorterChecksumsFromLibrary, 
    requestSignaturesFromPorter,
    aggregatePorterSignatures,
    verifySignaturesOnChainViaEIP1271
} from './porter_signer';

// Parse command line arguments
const args = process.argv.slice(2);
const logLevel = args.includes('--debug') ? 'debug' : 
                 args.includes('--verbose') ? 'verbose' :
                 args.includes('--info') ? 'info' : 'info'; // default to info

// Configure logger
const logger: Logger = winston.createLogger({
    level: logLevel,
    levels: {
        error: 0,
        warn: 1,
        info: 2,
        verbose: 3,
        debug: 4
    },
    format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp(),
        winston.format.printf((info) => {
            const { level, message, timestamp } = info;
            return `${timestamp} ${level}: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console()
    ]
});

// Add colors
winston.addColors({
    error: 'red',
    warn: 'yellow',
    info: 'green',
    verbose: 'cyan',
    debug: 'gray'
});

dotenv.config();

const BASE_SEPOLIA_CHAIN_ID = 84532;
const MULTISIG_CONTRACT_THRESHOLD = 2n; 
const MULTISIG_ADDRESS = "0x42F30AEc1A36995eEFaf9536Eb62BD751F982D32" as Address;
const DELEGATION_MANAGER_ADDRESS = "0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3" as Address;
const PORTER_BASE_URL = "https://porter-lynx.nucypher.io";

const MULTISIG_ABI = [
    "function nonce() view returns (uint256)",
    "function getUnsignedTransactionHash(address sender, address destination, uint256 value, bytes memory data, uint256 nonce) view returns (bytes32)",
    "function execute(address destination, uint256 value, bytes memory data, bytes memory signature)"
] as const;

async function getPorterChecksums(): Promise<`0x${string}`[]> {
    return getPorterChecksumsFromLibrary(PORTER_BASE_URL, 3);
}

async function fundAddress(
    provider: ethers.JsonRpcProvider,
    toAddress: string,
    amount: bigint
) {
    const wallet = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);
    logger.info(`Attempting to fund ${toAddress} with ${ethers.formatEther(amount)} ETH from ${wallet.address}...`)
    const tx = {
        to: toAddress,
        value: amount
    };
    const txResponse = await wallet.sendTransaction(tx);
    logger.verbose(`Funding transaction sent: ${txResponse.hash}`);
    logger.verbose(`View on Etherscan: https://sepolia.basescan.org/tx/${txResponse.hash}`);
    await txResponse.wait();
    logger.info('Funding transaction confirmed');
}

async function logBalance(label: string, provider: ethers.JsonRpcProvider, address: string) {
    const balance = await provider.getBalance(address);
    logger.info(`${label} balance: ${ethers.formatEther(balance)} ETH`);
}

async function setupEnvironment() {
    logger.info('--- SETUP ---');
    if (!process.env.RPC_URL) throw new Error('Please set RPC_URL in your .env file');
    if (!process.env.PRIVATE_KEY) throw new Error('Please set PRIVATE_KEY in your .env file');
    if (!process.env.BUNDLER_URL) throw new Error('Please set BUNDLER_URL in your .env file (needed for Pimlico client for gas prices)');

    const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
    const network = await provider.getNetwork();
    if (network.chainId !== BigInt(BASE_SEPOLIA_CHAIN_ID)) {
        throw new Error(`Wrong network. Expected Base Sepolia (${BASE_SEPOLIA_CHAIN_ID}), got chain ID ${network.chainId}`);
    }

    const environment: DeleGatorEnvironment = getDeleGatorEnvironment(BASE_SEPOLIA_CHAIN_ID);
    const publicClient = createPublicClient({
        chain: baseSepolia,
        transport: http(process.env.RPC_URL)
    });
    
    const paymasterClient = createPaymasterClient({ transport: http(process.env.BUNDLER_URL) });
    const { createPimlicoClient } = await import("permissionless/clients/pimlico");
    const pimlicoClient = createPimlicoClient({ transport: http(process.env.BUNDLER_URL) });
    const {fast: fees} = await pimlicoClient.getUserOperationGasPrice();
    
    const bundlerClient = createBundlerClient({
        transport: http(process.env.BUNDLER_URL),
        paymaster: paymasterClient,
        chain: baseSepolia
    });
    const localAccount = privateKeyToAccount(process.env.PRIVATE_KEY as `0x${string}`);
    const eoaWallet = new ethers.Wallet(process.env.PRIVATE_KEY as string, provider);

    const porterChecksums = await getPorterChecksums();
    logger.info("Setup complete. Returning environment...");
    return {
        provider,
        environment,
        publicClient,
        pimlicoClient,
        fees,
        bundlerClient,
        localAccount,
        eoaWallet,
        porterChecksums,
    };
}

async function deployAndSetupSmartAccount({
    publicClient,
    localAccount,
    pimlicoClient, 
    bundlerClient,
}: any) {
    logger.info('--- DEPLOYING USER SMART ACCOUNT & SETTING UP DELEGATION ---');
    const userSmartAccount = await toMetaMaskSmartAccount({
        client: publicClient,
        implementation: Implementation.Hybrid,
        deployParams: [localAccount.address, [], [], []],
        deploySalt: "0x" as Hex,
        signatory: { account: localAccount }
    });

    const userSaCode = await publicClient.getBytecode({address: userSmartAccount.address});
    if (!userSaCode || userSaCode.length <= 2) {
         logger.info(`User Smart Account ${userSmartAccount.address} not yet deployed. Deploying...`);
    const { fast: fee } = await pimlicoClient!.getUserOperationGasPrice();
    const userOperationHash = await bundlerClient!.sendUserOperation({
      account: userSmartAccount,
           calls: [{ to: zeroAddress, value: 0n, data: '0x' }], 
      ...fee,
         });
         logger.verbose(`User Smart Account deployment UserOp sent: ${userOperationHash}. Waiting for receipt...`);
         const { receipt } = await bundlerClient!.waitForUserOperationReceipt({ hash: userOperationHash });
         logger.info(`User Smart Account deployed at: ${userSmartAccount.address}, tx: ${receipt.transactionHash}`);
    } else {
        logger.verbose(`User Smart Account ${userSmartAccount.address} already deployed.`);
    }

    const delegation = createDelegation({
        to: MULTISIG_ADDRESS,
        from: userSmartAccount.address,
        caveats: []
    });
    logger.debug('Delegation created:', JSON.stringify(delegation, null, 2));

    const signature = await userSmartAccount.signDelegation({ delegation });
    const signedDelegation = { ...delegation, signature };
    logger.info('Delegation signed by User Smart Account.');

    return { userSmartAccount, signedDelegation };
}

async function executeRedemptionViaMultisig({
    provider,
    eoaWallet,
    signedDelegation, 
    localAccount,
    porterChecksums,
}: any) {
    logger.info('--- REDEEMING DELEGATION VIA EIP-1271 MULTISIG (Triggered by EOA) ---');

    logger.verbose(`Delegation Manager Address: ${DELEGATION_MANAGER_ADDRESS}`);

    const recipientAddress = localAccount.address;
    const transferAmount = parseEther('0.0001'); 
    const innerExecution = createExecution(recipientAddress, transferAmount, '0x' as Hex);
    logger.debug('Inner execution for fund return to EOA created:', innerExecution);

    const redemptionCalldata = DelegationFramework.encode.redeemDelegations({
        delegations: [[signedDelegation]],
        modes: [SINGLE_DEFAULT_MODE],
        executions: [[innerExecution]]
    });
    logger.debug(`This calldata will instruct userSmartAccount (${signedDelegation.from}) to send ${ethers.formatEther(transferAmount)} ETH to ${recipientAddress}`);
    logger.debug(`The EIP-1271 multisig (${MULTISIG_ADDRESS}) will authorize call to DM: ${DELEGATION_MANAGER_ADDRESS}`);

    // Fetch current nonce from multisig contract
    const multisigContract = new ethers.Contract(MULTISIG_ADDRESS, MULTISIG_ABI, provider);
    const multisigNonce = await multisigContract.nonce();
    logger.verbose(`Current multisig nonce: ${multisigNonce}`);

    const encodedData = ethers.solidityPacked(
        ['address', 'address', 'address', 'uint256', 'bytes', 'uint256'],
        [
            MULTISIG_ADDRESS.toLowerCase(),
            eoaWallet.address.toLowerCase(),
            DELEGATION_MANAGER_ADDRESS.toLowerCase(),
            0n,
            redemptionCalldata,
            multisigNonce
        ]
    ) as Hex;

    const messageHash = ethers.hashMessage(ethers.getBytes(encodedData));
    logger.debug(`Message hash: ${messageHash}`);

    const { signatures: porterSignatures, claimedSigners, messageHash: porterMessageHash } = await requestSignaturesFromPorter(
        PORTER_BASE_URL,
        encodedData,
        porterChecksums,
        Number(MULTISIG_CONTRACT_THRESHOLD) 
    );
    logger.verbose(`Message hash from Porter: ${porterMessageHash}`);
    const combinedSignature = aggregatePorterSignatures(porterSignatures);
    logger.verbose(`Combined Porter signature: ${combinedSignature}`);
    logger.verbose(`Porter claimed signers for this action: ${claimedSigners.join(', ')}`);

    logger.info('Performing EIP-1271 pre-flight check for the Porter signature against the multisig...');
    const isSignatureValid = await verifySignaturesOnChainViaEIP1271(
        provider,
        MULTISIG_ADDRESS, 
        messageHash as `0x${string}`,
        combinedSignature
    );

    if (!isSignatureValid) {
        throw new Error('Porter signature for multisig action FAILED EIP-1271 pre-flight check. Halting.');
    }
    logger.info('SUCCESS: Porter signature for multisig action PASSED EIP-1271 pre-flight check.');

    // Updated to match the multisig's execute function
    const multisigInterface = new ethers.Interface([
        "function execute(address destination, uint256 value, bytes memory data, bytes memory signature)"
    ]);
    const executeCalldata = multisigInterface.encodeFunctionData("execute", [
        DELEGATION_MANAGER_ADDRESS,
        0n,
        redemptionCalldata,
        combinedSignature
    ]);

    logger.info(`Sending transaction from EOA (${eoaWallet.address}) to Multisig (${MULTISIG_ADDRESS}) to execute the redemption...`);
    logger.debug(`Multisig will call DM (${DELEGATION_MANAGER_ADDRESS}) with data: ${redemptionCalldata.substring(0,100)}...`);
    logger.debug(`DM will instruct UserSA (${signedDelegation.delegator}) to send ${ethers.formatEther(transferAmount)} ETH to ${recipientAddress}`);

    try {
        const tx = await eoaWallet.sendTransaction({
            to: MULTISIG_ADDRESS,
            data: executeCalldata as Hex,
            value: 0n,
        });
        logger.verbose(`Transaction sent by EOA to trigger multisig: ${tx.hash}`);
        logger.verbose(`View on Etherscan: https://sepolia.basescan.org/tx/${tx.hash}`);
        const receipt = await tx.wait();
        logger.info('Transaction confirmed!', receipt);
        if (receipt?.status !== 1) {
            logger.error("Transaction to trigger multisig FAILED after being mined.");
            throw new Error("EOA transaction to multisig failed.");
        }
        logger.info("SUCCESS: EOA transaction to multisig confirmed and succeeded.");

    } catch (error: any) {
        logger.error(`Error sending transaction from EOA to multisig: ${error.message}`);
        if (error.data) logger.error(`Error data: ${error.data}`);
        if (error.transaction) logger.error(`Error transaction: ${error.transaction}`);
        throw error;
    }
    await logBalance(`Local EOA (${localAccount.address}) AFTER redemption`, provider, localAccount.address);
    await logBalance('User Smart Account (Delegator) AFTER redemption', provider, signedDelegation.delegator);
}


(async function main() {
    try {
        const env = await setupEnvironment();
        const { userSmartAccount, signedDelegation } = await deployAndSetupSmartAccount(env);
        

        logger.info("--- Funding User Smart Account (Delegator) ---");
        await fundAddress(env.provider, userSmartAccount.address, parseEther('0.0001'));
        await logBalance('User Smart Account (Delegator) before redemption', env.provider, userSmartAccount.address);
        await logBalance(`Local EOA (${env.localAccount.address}) before redemption`, env.provider, env.localAccount.address);


        await executeRedemptionViaMultisig({
            ...env,
            userSmartAccount,
            signedDelegation
        });

        logger.info('--- SCRIPT COMPLETE ---!');
    } catch (error: any) {
        logger.error('Error in main execution flow:', error.message);
        if (error.stack) {
            logger.debug(error.stack);
        }
        if (error.data) logger.error("Main execution error data:", error.data);
        process.exit(1);
    }
})();

