// ============================================================================
// MetaMask MultiSig Smart Account Example
// ----------------------------------------------------------------------------
// This script demonstrates how to:
// 1. Set up a MultiSig smart account with initial signers from a MultiSig contract
// 2. Execute transactions directly on the smart account
// 3. The transaction to trigger the MultiSig is sent by the local EOA
// ============================================================================

import { 
    Implementation,
    toMetaMaskSmartAccount,
} from '@metamask/delegation-toolkit';
import { aggregateSignature } from '@metamask/delegation-utils';
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

// Import from the Porter Signer library
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
const PORTER_BASE_URL = "https://porter-lynx.nucypher.io";

const MULTISIG_ABI = [
    "function nonce() view returns (uint256)",
    "function getUnsignedTransactionHash(address sender, address destination, uint256 value, bytes memory data, uint256 nonce) view returns (bytes32)",
    "function execute(address destination, uint256 value, bytes memory data, bytes memory signature)",
    "function getSigners() view returns (address[])",
    "function threshold() view returns (uint16)"
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

    const publicClient = createPublicClient({
        chain: baseSepolia,
        transport: http(process.env.RPC_URL)
    });
    
    // const paymasterClient = createPaymasterClient({
    //     transport: http(process.env.BUNDLER_URL)
    // });
    
    const { createPimlicoClient } = await import("permissionless/clients/pimlico");
    const pimlicoClient = createPimlicoClient({ transport: http(process.env.BUNDLER_URL) });
    const {fast: fees} = await pimlicoClient.getUserOperationGasPrice();
    
    const bundlerClient = createBundlerClient({
        transport: http(process.env.BUNDLER_URL),
        chain: baseSepolia,
        // paymaster: paymasterClient,
    });
    const localAccount = privateKeyToAccount(process.env.PRIVATE_KEY as `0x${string}`);
    const eoaWallet = new ethers.Wallet(process.env.PRIVATE_KEY as string, provider);

    const porterChecksums = await getPorterChecksums();
    logger.info("Setup complete. Returning environment...");
    return {
        provider,
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
    provider,
    porterChecksums,
}: any) {
    logger.info('--- DEPLOYING USER SMART ACCOUNT ---');

    // Get signers and threshold from MultiSig contract
    const multisigContract = new ethers.Contract(MULTISIG_ADDRESS, MULTISIG_ABI, provider);
    const signers = await multisigContract.getSigners();
    const threshold = await multisigContract.threshold();
    logger.info(`Got ${signers.length} signers from MultiSig contract with threshold ${threshold}`);
    logger.debug(`Signers: ${signers.join(', ')}`);

    const userSmartAccount = await toMetaMaskSmartAccount({
        client: publicClient,
        implementation: Implementation.MultiSig,
        deployParams: [signers, threshold],
        deploySalt: "0x" as Hex,
        signatory: [{
            account: localAccount
        }]
    });

    return { userSmartAccount, threshold };
}

async function executeViaMultisig({
    provider,
    eoaWallet,
    userSmartAccount,
    localAccount,
    porterChecksums,
    bundlerClient,
    pimlicoClient,
    threshold
}: any) {
    logger.info('--- EXECUTING VIA MULTISIG ---');

    const recipientAddress = localAccount.address;
    const transferAmount = parseEther('0.0001'); 

    // Create the execution data
    const executionData = {
        target: recipientAddress,
        value: transferAmount,
        callData: '0x'
    };

    // Prepare the execution UserOperation
    logger.debug(`Preparing user operation with data: target=${recipientAddress}, value=${transferAmount.toString()}, callData=${executionData.callData}`);

    const userOperation = await bundlerClient!.prepareUserOperation({
        account: userSmartAccount,
        calls: [executionData]
    });
    logger.debug(`Prepared user operation: sender=${userOperation.sender}, nonce=${userOperation.nonce.toString()}, initCode=${userOperation.initCode}, callData=${userOperation.callData}, callGasLimit=${userOperation.callGasLimit.toString()}, verificationGasLimit=${userOperation.verificationGasLimit.toString()}, preVerificationGas=${userOperation.preVerificationGas.toString()}, maxFeePerGas=${userOperation.maxFeePerGas.toString()}, maxPriorityFeePerGas=${userOperation.maxPriorityFeePerGas.toString()}, paymasterAndData=${userOperation.paymasterAndData}`);

    // Get the proper typed data hash that the EntryPoint will use
    const userOpHash = await userSmartAccount.getPackedUserOperationTypedDataHash(userOperation);
    logger.verbose(`Got UserOperation typed data hash: ${userOpHash}`);

    // Get signatures from Porter for the execution UserOperation
    logger.debug(`Requesting signatures from Porter...`);
    const { signatures: porterSignatures, claimedSigners } = await requestSignaturesFromPorter(
        PORTER_BASE_URL,
        userOpHash,
        porterChecksums,
        Number(threshold)
    );
    logger.verbose(`Got signatures from Porter for execution`);

    // Aggregate the signatures using the delegation toolkit's format
    const aggregatedSignature = aggregateSignature({
        signatures: Object.entries(porterSignatures).map(([signer, [_, signature]]) => ({
            signer: signer as Address,
            signature: signature as `0x${string}`,
            type: "ECDSA"
        }))
    });
    logger.debug(`Aggregated signature: ${aggregatedSignature}`);

    // Send the UserOperation with the aggregated signature
    logger.debug(`Sending user operation with signature...`);
    const { fast: fee } = await pimlicoClient!.getUserOperationGasPrice();
    logger.debug(`Got gas price: ${JSON.stringify(fee)}`);
    
    const userOperationHash = await bundlerClient!.sendUserOperation({
        ...userOperation,
        signature: aggregatedSignature,
        ...fee,
    });
    logger.verbose(`Execution UserOp sent: ${userOperationHash}. Waiting for receipt...`);
    const { receipt } = await bundlerClient!.waitForUserOperationReceipt({ hash: userOperationHash });
    logger.info(`Execution completed, tx: ${receipt.transactionHash}`);

    await logBalance(`Local EOA (${localAccount.address}) AFTER transfer`, provider, localAccount.address);
    await logBalance('User Smart Account AFTER transfer', provider, userSmartAccount.address);
}

(async function main() {
    try {
        const env = await setupEnvironment();
        const { userSmartAccount, threshold } = await deployAndSetupSmartAccount({
            ...env,
            provider: env.provider,
            porterChecksums: env.porterChecksums
        });
        
        // logger.info("--- Funding User Smart Account ---");
        // await fundAddress(env.provider, userSmartAccount.address, parseEther('0.0001'));
        await logBalance('User Smart Account before transfer', env.provider, userSmartAccount.address);
        await logBalance(`Local EOA (${env.localAccount.address}) before transfer`, env.provider, env.localAccount.address);

        await executeViaMultisig({
            ...env,
            userSmartAccount,
            threshold
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

