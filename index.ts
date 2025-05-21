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
const multisigAddress = "0x42F30AEc1A36995eEFaf9536Eb62BD751F982D32" as Address;
const delegationManagerAddress = "0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3" as Address;
const porterBaseUrl = "https://porter-lynx.nucypher.io";

const multisigContractABI = [
    "function nonce() view returns (uint256)",
    "function getUnsignedTransactionHash(address sender, address destination, uint256 value, bytes memory data, uint256 nonce) view returns (bytes32)",
    "function execute(address destination, uint256 value, bytes memory data, bytes memory signature)"
] as const;

async function getPorterChecksums(): Promise<`0x${string}`[]> {
    return getPorterChecksumsFromLibrary(porterBaseUrl, 3);
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

async function setup() {
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

async function DelegateAndDeployUserSA({
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
        to: multisigAddress,
        from: userSmartAccount.address,
        caveats: []
    });
    logger.debug('Delegation created:', JSON.stringify(delegation, null, 2));

    const signature = await userSmartAccount.signDelegation({ delegation });
    const signedDelegation = { ...delegation, signature };
    logger.info('Delegation signed by User Smart Account.');

    return { userSmartAccount, signedDelegation };
}


async function executeRedemptionViaEIP1271MultisigByEOA({
    provider,
    eoaWallet,
    signedDelegation, 
    localAccount,
    porterChecksums,
}: any) {
    logger.info('--- REDEEMING DELEGATION VIA EIP-1271 MULTISIG (Triggered by EOA) ---');

    logger.verbose(`Delegation Manager Address: ${delegationManagerAddress}`);

    const to_local_funds_recipient = localAccount.address;
    const value_local_funds = parseEther('0.0001'); 
    const calldata_local_funds = '0x' as Hex;
    const inner_execution = createExecution(to_local_funds_recipient, value_local_funds, calldata_local_funds);
    logger.debug('Inner execution for fund return to EOA created:', inner_execution);

    const calldata_for_dm = DelegationFramework.encode.redeemDelegations({
        delegations: [[signedDelegation]],
        modes: [SINGLE_DEFAULT_MODE],
        executions: [[inner_execution]]
    });
    logger.debug(`This calldata will instruct userSmartAccount (${signedDelegation.from}) to send ${ethers.formatEther(value_local_funds)} ETH to ${to_local_funds_recipient}`);
    logger.debug(`The EIP-1271 multisig (${multisigAddress}) will authorize call to DM: ${delegationManagerAddress}`);

    // Fetch current nonce from multisig contract
    const multisigContract = new ethers.Contract(multisigAddress, multisigContractABI, provider);
    const multisigNonce = await multisigContract.nonce();
    logger.verbose(`Current multisig nonce: ${multisigNonce}`);

    const encodedData = ethers.solidityPacked(
        ['address', 'address', 'address', 'uint256', 'bytes', 'uint256'],
        [
            multisigAddress.toLowerCase(),
            eoaWallet.address.toLowerCase(),
            delegationManagerAddress.toLowerCase(),
            0n,
            calldata_for_dm,
            multisigNonce
        ]
    ) as Hex;

    const ethersHashMessageOutput = ethers.hashMessage(ethers.getBytes(encodedData));
    logger.debug(`ethers hashMessage output: ${ethersHashMessageOutput}`);

    // Verify that our offchain hash matches the contract's getUnsignedTransactionHash
    const contractHash = await multisigContract.getUnsignedTransactionHash(
        eoaWallet.address.toLowerCase(),
        delegationManagerAddress.toLowerCase(),
        0n,
        calldata_for_dm,
        multisigNonce
    );
    logger.debug(`Contract's getUnsignedTransactionHash: ${contractHash}`);

    const { signatures: porterSignaturesForMultisigAction, claimedSigners, messageHash: messageHashFromPorter } = await requestSignaturesFromPorter(
        porterBaseUrl,
        encodedData,
        porterChecksums,
        Number(MULTISIG_CONTRACT_THRESHOLD) 
    );
    logger.verbose(`Message hash from Porter: ${messageHashFromPorter}`);
    const combinedPorterSignature = aggregatePorterSignatures(porterSignaturesForMultisigAction);
    logger.verbose(`Combined Porter signature for multisig action: ${combinedPorterSignature}`);
    logger.verbose(`Porter claimed signers for this action: ${claimedSigners.join(', ')}`);

    logger.info('Performing EIP-1271 pre-flight check for the Porter signature against the multisig...');
    const isActionSignatureValidEIP1271 = await verifySignaturesOnChainViaEIP1271(
        provider,
        multisigAddress, 
        ethersHashMessageOutput as `0x${string}`,
        combinedPorterSignature
    );

    if (!isActionSignatureValidEIP1271) {
        throw new Error('Porter signature for multisig action FAILED EIP-1271 pre-flight check. Halting.');
    }
    logger.info('SUCCESS: Porter signature for multisig action PASSED EIP-1271 pre-flight check.');

    // Updated to match the multisig's execute function
    const multisigContractInterface = new ethers.Interface([
        "function execute(address destination, uint256 value, bytes memory data, bytes memory signature)"
    ]);
    const callDataForMultisigExecute = multisigContractInterface.encodeFunctionData("execute", [
        delegationManagerAddress,
        0n,
        calldata_for_dm,
        combinedPorterSignature
    ]);

    logger.info(`Sending transaction from EOA (${eoaWallet.address}) to Multisig (${multisigAddress}) to execute the redemption...`);
    logger.debug(`Multisig will call DM (${delegationManagerAddress}) with data: ${calldata_for_dm.substring(0,100)}...`);
    logger.debug(`DM will instruct UserSA (${signedDelegation.delegator}) to send ${ethers.formatEther(value_local_funds)} ETH to ${to_local_funds_recipient}`);

    try {
        const tx = await eoaWallet.sendTransaction({
            to: multisigAddress,
            data: callDataForMultisigExecute as Hex,
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
        const setupResult = await setup();
        const { userSmartAccount, signedDelegation } = await DelegateAndDeployUserSA(setupResult);
        

        logger.info("--- Funding User Smart Account (Delegator) ---");
        await fundAddress(setupResult.provider, userSmartAccount.address, parseEther('0.0001'));
        await logBalance('User Smart Account (Delegator) before redemption', setupResult.provider, userSmartAccount.address);
        await logBalance(`Local EOA (${setupResult.localAccount.address}) before redemption`, setupResult.provider, setupResult.localAccount.address);


        await executeRedemptionViaEIP1271MultisigByEOA({
            ...setupResult,
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

