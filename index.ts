// ============================================================================
// MetaMask Delegation Toolkit Multisig Example
// ----------------------------------------------------------------------------
// This script demonstrates how to:
// 1. Set up a Hybrid (delegator) and MultiSig (delegatee) smart account
// 2. Delegate authority from the Hybrid to the MultiSig
// 3. Redeem the delegation
// 4. Fund the Hybrid account
// 5. Use the MultiSig to return funds from the Hybrid to a local EOA
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
    SignUserOperationParams,
    MetaMaskSmartAccount,
    SIGNABLE_USER_OP_TYPED_DATA
} from '@metamask/delegation-toolkit';
import { ethers } from 'ethers';
import { Address, concat, createPublicClient, createWalletClient, encodeFunctionData, Hex, http, parseEther, WalletClient, zeroAddress } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { 
    createPaymasterClient,
    createBundlerClient,
    getUserOperationHash,
    toPackedUserOperation
} from 'viem/account-abstraction';
import { baseSepolia } from 'viem/chains';
import * as dotenv from 'dotenv';
import * as fs from 'fs';
import winston, { Logger } from 'winston';

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
const multisigAddress = "0x152aB00413e78be27D86061448B145d98ff7F22d";
const porterBaseUrl = "https://porter-lynx.nucypher.io";

async function getPorterChecksums(): Promise<`0x${string}`[]> {
    // Get signers from Porter
    logger.info('Fetching signers from Porter...');
    const porterResponse = await (await fetch(`${porterBaseUrl}/get_ursulas?quantity=3`)).json();
    const porterChecksums = porterResponse.result.ursulas.map((ursula: any) => ursula.checksum_address.toLowerCase());
    logger.info(`Retrieved ${porterChecksums.length} nodes from Porter: ${porterChecksums.join(', ')}`);
    return porterChecksums as `0x${string}`[];
}

// Get signers from multisig contract
async function getSigners(): Promise<`0x${string}`[]> {
    const abi = [
        "function getSigners() external view returns (address[])"
    ];
    
    const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
    const multisigContract = new ethers.Contract(multisigAddress, abi, provider);
    
    try {
        // Get signers from multisig contract
        const result = await multisigContract.getSigners();
        const signers = result.map((addr: string) => addr.toLowerCase());
        logger.info(`Retrieved ${signers.length} signers from multisig: ${signers.join(', ')}`);
        return signers as `0x${string}`[];
    } catch (error) {
        logger.error('Error fetching signers from multisig:', error);
        throw error;
    }
}

// Function to fund the AA wallet
async function fundAAWallet(
    provider: ethers.JsonRpcProvider,
    toAddress: string,
    amount: bigint
) {
    const wallet = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);
    const tx = {
        to: toAddress,
        value: amount
    };
    const txResponse = await wallet.sendTransaction(tx);
    console.log('Funding transaction sent:', txResponse.hash);
    console.log('View on Etherscan:', `https://baseSepolia.etherscan.io/tx/${txResponse.hash}`);
    await txResponse.wait();
    console.log('Funding transaction confirmed');
}

// Helper to fetch and log ETH balance
async function logBalance(label: string, provider: ethers.JsonRpcProvider, address: string) {
    const balance = await provider.getBalance(address);
    logger.info(`${label} balance: ${ethers.formatEther(balance)} ETH`);
}

// === 1. SETUP ===
/**
 * Sets up all clients, accounts, and environment variables.
 * Returns an object with all necessary handles for the rest of the flow.
 */
async function setup() {
    logger.info('--- SETUP ---');
    if (!process.env.RPC_URL) {
        throw new Error('Please set RPC_URL in your .env file');
    }
    if (!process.env.PRIVATE_KEY) {
        throw new Error('Please set PRIVATE_KEY in your .env file');
    }
    if (!process.env.BUNDLER_URL) {
        throw new Error('Please set BUNDLER_URL in your .env file');
    }

    const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
    const network = await provider.getNetwork();
    if (network.chainId !== BigInt(BASE_SEPOLIA_CHAIN_ID)) {
        throw new Error(`Wrong network. Expected Sepolia (${BASE_SEPOLIA_CHAIN_ID}), got chain ID ${network.chainId}`);
    }

    const environment: DeleGatorEnvironment = getDeleGatorEnvironment(BASE_SEPOLIA_CHAIN_ID);
    const publicClient = createPublicClient({
        chain: baseSepolia,
        transport: http(process.env.RPC_URL)
    });
    const paymasterClient = createPaymasterClient({ 
        transport: http(process.env.BUNDLER_URL), 
    });
    const { createPimlicoClient } = await import("permissionless/clients/pimlico");
    const pimlicoClient = createPimlicoClient({
        transport: http(process.env.BUNDLER_URL),
    });
    const {fast: fees} = await pimlicoClient.getUserOperationGasPrice();
    const bundlerClient = createBundlerClient({
        transport: http(process.env.BUNDLER_URL),
        paymaster: paymasterClient,
        chain: baseSepolia
    });
    const localAccount = privateKeyToAccount(process.env.PRIVATE_KEY as `0x${string}`);

    const signers = await getSigners();
    const porterChecksums = await getPorterChecksums();

    return {
        provider,
        environment,
        publicClient,
        paymasterClient,
        pimlicoClient,
        fees,
        bundlerClient,
        localAccount,
        signers,
        porterChecksums,
    };
}

// === 2. DELEGATION & REDEEM ===
/**
 * Creates the Hybrid (delegator) and MultiSig (delegatee) smart accounts, sets up delegation, and redeems it.
 * Returns the smart accounts and signed delegation.
 */
async function Delegate({
    publicClient,
    localAccount,
    pimlicoClient,
    bundlerClient,
    paymasterClient,
    signers
}: any) {
    logger.info('--- DELEGATION & REDEEM ---');
    // Create delegator account (Hybrid implementation)
    const userSmartAccount = await toMetaMaskSmartAccount({
        client: publicClient,
        implementation: Implementation.Hybrid,
        deployParams: [localAccount.address, [], [], []],
        deploySalt: "0x",
        signatory: { account: localAccount }
    });
    const { fast: fee } = await pimlicoClient!.getUserOperationGasPrice();

    const userOperationHash = await bundlerClient!.sendUserOperation({
      account: userSmartAccount,
      calls: [
        {
          to: zeroAddress,
        },
      ],
      paymaster: paymasterClient,
      ...fee,
    });

    const { receipt } = await bundlerClient!.waitForUserOperationReceipt({
      hash: userOperationHash,
    });
    logger.info(`User Smart Account created and deployed at: ${userSmartAccount.address}`);

    const threshold = BigInt(2);
    
    // Create wallet clients for each signer
    const walletClients = signers.map((address: `0x${string}`) => createWalletClient({
        account: { address, type: 'json-rpc' },
        chain: baseSepolia,
        transport: http()
    }));

    const multisigSmartAccount = await toMetaMaskSmartAccount({
        client: publicClient,
        implementation: Implementation.MultiSig,
        deployParams: [signers, threshold],
        signatory: walletClients.map((walletClient: WalletClient) => ({ walletClient })),
        deploySalt: "0x",
    });
    logger.info(`Multisig Smart Account created and deployed at: ${multisigSmartAccount.address}`);

    // Create delegation from delegator to delegatee
    const delegation = createDelegation({
        to: multisigSmartAccount.address,
        from: userSmartAccount.address,
        caveats: []
    });
    logger.verbose('Delegation created:', JSON.stringify(delegation, null, 2));

    // Sign the delegation
    const signature = await userSmartAccount.signDelegation({ delegation });
    const signedDelegation = { ...delegation, signature };

    return { userSmartAccount, multisigSmartAccount, signedDelegation };
}

// Constants for signature handling
const SIGNATURE_LENGTH = 65; // Standard Ethereum signature length (r: 32, s: 32, v: 1)

const aggregateSignature = (
    signaturesWithAddress: { [checksumAddress: string]: [string, string] }
) => {
    // Convert object to array of [signer_address, signature] pairs and sort by signer address
    const sortedSignaturePairs = Object.entries(signaturesWithAddress)
        .sort(([_, [addr1]], [__, [addr2]]) => 
            addr1.toLowerCase().localeCompare(addr2.toLowerCase())
        );

    logger.debug(`Sorted signature pairs: ${JSON.stringify(sortedSignaturePairs, null, 2)}`);

    // Convert base64 signatures to properly formatted hex signatures
    const sortedHexSignatures = sortedSignaturePairs.map(([_, [__, signature]]) => {
        // Convert base64 to buffer
        const signatureBuffer = Buffer.from(signature, 'base64');
        
        // Ensure the signature is the correct length
        if (signatureBuffer.length !== SIGNATURE_LENGTH) {
            throw new Error(`Invalid signature length. Expected ${SIGNATURE_LENGTH} bytes, got ${signatureBuffer.length} bytes`);
        }

        // Convert to hex with 0x prefix
        return ('0x' + signatureBuffer.toString('hex')) as Hex;
    });

    logger.debug(`Sorted hex signatures: ${JSON.stringify(sortedHexSignatures, null, 2)}`);

    // Concatenate all signatures
    const combinedSignature = concat(sortedHexSignatures);
    logger.verbose(`Combined signature (${combinedSignature.length} bytes): ${combinedSignature}`);

    // Verify the combined signature length matches threshold * SIGNATURE_LENGTH
    const expectedLength = sortedHexSignatures.length * SIGNATURE_LENGTH * 2 + 2; // *2 for hex encoding, +2 for '0x'
    if (combinedSignature.length !== expectedLength) {
        throw new Error(`Invalid combined signature length. Expected ${expectedLength} chars, got ${combinedSignature.length} chars`);
    }

    return combinedSignature;
};

async function getThresholdSignatures(
    userOp: any,
    ursulaChecksums: `0x${string}`[],
    cohortId: number,
    threshold: number
): Promise<{ [checksumAddress: string]: [string, string] }> {
    // Deep clone and convert all BigInts to strings and ensure proper hex formatting
    function convertBigInts(obj: any): any {
        if (typeof obj === 'bigint') {
            return obj.toString();
        }
        if (typeof obj === 'string' && obj.startsWith('0x')) {
            // Ensure hex strings have even length by padding with 0 if needed
            return obj.length % 2 === 1 ? obj + '0' : obj;
        }
        if (Array.isArray(obj)) {
            return obj.map(convertBigInts);
        }
        if (obj !== null && typeof obj === 'object') {
            return Object.fromEntries(
                Object.entries(obj).map(([key, value]) => [key, convertBigInts(value)])
            );
        }
        return obj;
    }

    // Convert BigInt values to strings and format hex values in the user operation
    const serializableUserOp = convertBigInts(userOp);
    logger.debug('UserOp structure:', JSON.stringify(serializableUserOp, null, 2));

    // Convert to hex
    const hexData = Buffer.from(JSON.stringify(serializableUserOp)).toString('hex');
    
    const requestData = {
        data_to_sign: hexData,
        cohort_id: cohortId,
        context: {}
    };

    // Convert to base64
    const requestB64 = Buffer.from(JSON.stringify(requestData)).toString('base64');

    const signingRequests: { [key: string]: string } = {};
    for (const address of ursulaChecksums) {
        signingRequests[address] = requestB64;
    }

    const requestBody = {
        signing_requests: signingRequests,
        threshold: threshold,
    };

    // Log request size
    const requestBodySize = Buffer.from(JSON.stringify(requestBody)).length;
    logger.verbose(`Request size: ${(requestBodySize / 1024).toFixed(2)} KB`);

    logger.info(`Making request to: ${porterBaseUrl}/sign with ${Object.keys(signingRequests).length} signing requests`);
    
    const response = await fetch(`${porterBaseUrl}/sign`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
        const errorText = await response.text();
        logger.error('Error response body:', errorText);
        throw new Error(`HTTP error! status: ${response.status}, body: ${errorText}`);
    }

    const data = await response.json();
    logger.debug(`Response data: ${JSON.stringify(data, null, 2)}`);

    if (!data.result?.signing_results?.signatures) {
        throw new Error('Invalid response format from Porter: missing signatures');
    }

    return data.result.signing_results.signatures;
}

// === 3. FUNDING & RETURNING ===
/**
 * Funds the Hybrid account and uses the MultiSig to return funds to the local EOA via the delegation framework.
 */
async function fundingAndReturning({
    provider,
    userSmartAccount,
    multisigSmartAccount,
    signedDelegation,
    localAccount,
    bundlerClient,
    pimlicoClient,
    signers,
    porterChecksums,
}: any) {
    logger.info('--- FUNDING & RETURNING ---');
    await logBalance('User Smart Account (after funding)', provider, userSmartAccount.address);
    logger.info('Returning funds through delegation...');
    const executions = [{
        target: localAccount.address,  
        value: parseEther('0.0001'),
        callData: '0x' as `0x${string}`
    }];
    const returnFundsCalldata = DelegationFramework.encode.redeemDelegations({
      delegations: [[signedDelegation]],
      modes: [SINGLE_DEFAULT_MODE],
      executions: [executions]
    });
    const { fast: newFees } = await pimlicoClient.getUserOperationGasPrice();
    const returnFundsUserOp = await bundlerClient.prepareUserOperation({
      account: multisigSmartAccount,
      calls: [
        {
          to: multisigSmartAccount.address,
          data: returnFundsCalldata
        }
      ],
      verificationGasLimit: BigInt(500_000),
      ...newFees
    });


    const returnFundsSig = await getThresholdSignatures(returnFundsUserOp, porterChecksums, 0, 2);
    logger.verbose(`Return funds signatures: ${JSON.stringify(returnFundsSig, null, 2)}`);
    const combinedSignature = aggregateSignature(returnFundsSig);

    // Send the UserOperation with all required fields
    const userOpHash = await bundlerClient.sendUserOperation({
      ...returnFundsUserOp,
      signature: combinedSignature as `0x${string}`
    });
    logger.info(`Return funds UserOperation hash: ${userOpHash}`);
    // Wait for the UserOperation to be mined
    const receipt = await bundlerClient.waitForUserOperationReceipt({
        hash: userOpHash,
        pollingInterval: 1000,
        retryCount: 100
    });
    logger.info(`Return funds transaction hash: ${receipt.receipt.transactionHash}`);
    logger.info(`View on Etherscan: https://baseSepolia.etherscan.io/tx/${receipt.receipt.transactionHash}`);
    // Log balance after return
    await logBalance('User Smart Account (after return)', provider, userSmartAccount.address);
}

// === MAIN FLOW ===
(async function main() {
    try {
        const setupResult = await setup();
        const { userSmartAccount, multisigSmartAccount, signedDelegation } = await Delegate(setupResult);
        await fundingAndReturning({
            ...setupResult,
            userSmartAccount,
            multisigSmartAccount,
            signedDelegation
        });
        logger.info('All done!');
    } catch (error) {
        logger.error('Error:', error);
        process.exit(1);
    }
})();
