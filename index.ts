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
import { ethers, TypedDataDomain as EthersTypedDataDomain, TypedDataField, TypedDataEncoder } from 'ethers';
import { Address, concat, createPublicClient, createWalletClient, encodeFunctionData, Hex, toHex, http, parseEther, WalletClient, zeroAddress, hashTypedData, TypedDataDomain as ViemTypedDataDomain, recoverMessageAddress, hashMessage, recoverAddress, keccak256, fromHex } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { 
    createPaymasterClient,
    createBundlerClient,
    getUserOperationHash,
    toPackedUserOperation,
    type UserOperation
} from 'viem/account-abstraction';
import { baseSepolia } from 'viem/chains';
import * as dotenv from 'dotenv';
import * as fs from 'fs';
import winston, { Logger } from 'winston';

// Import from the new Porter Signer library
import {
    getPorterChecksums as getPorterChecksumsFromLibrary, // Alias to avoid immediate name clash
    requestSignaturesFromPorter,
    aggregatePorterSignatures,
    verifySignaturesLocally,
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
const MULTISIG_CONTRACT_THRESHOLD = 2n; // Define global threshold for the contract
const multisigAddress = "0x152aB00413e78be27D86061448B145d98ff7F22d";
const porterBaseUrl = "https://porter-lynx.nucypher.io";

// Replace original getPorterChecksums with a wrapper around the library function or use directly
// For now, let's keep the existing structure in setup() which calls a global getPorterChecksums
// So, we redefine it to use the library one.
async function getPorterChecksums(): Promise<`0x${string}`[]> {
    // Uses the library function internally
    return getPorterChecksumsFromLibrary(porterBaseUrl, 3);
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

    const thresholdForContract = MULTISIG_CONTRACT_THRESHOLD; // Use global constant for clarity
    
    // Create wallet clients for each signer
    const walletClients = signers.map((address: `0x${string}`) => createWalletClient({
        account: { address, type: 'json-rpc' },
        chain: baseSepolia,
        transport: http()
    }));

    const multisigSmartAccount = await toMetaMaskSmartAccount({
        client: publicClient,
        implementation: Implementation.MultiSig,
        deployParams: [signers, thresholdForContract],
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
// const SIGNATURE_LENGTH = 65; // REMOVED - Handled by library

// const aggregateSignature = (...) // REMOVED - Replaced by library's aggregatePorterSignatures

async function getThresholdSignatures(
    userOp: UserOperation,
    multisigSmartAccount: MetaMaskSmartAccount,
    ursulaChecksumsForRequest: `0x${string}`[],
    porterThreshold: number
): Promise<{ porterSignatures: { [checksumAddress: string]: [string, string] }; digestToVerify: Hex; porterClaimedSigners: Address[] }> {
    const packedUserOp = toPackedUserOperation(userOp);

    const viemDomain: ViemTypedDataDomain = {
        name: 'MultiSigDeleGator',
        version: '1',
        chainId: BigInt(BASE_SEPOLIA_CHAIN_ID),
        verifyingContract: multisigSmartAccount.address
    };

    const metamaskToolkitTypes = { ...SIGNABLE_USER_OP_TYPED_DATA } as const;
    const DEFAULT_ENTRY_POINT_ADDRESS = '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789' as Address;

    const messageForSigning = {
        ...packedUserOp,
        entryPoint: DEFAULT_ENTRY_POINT_ADDRESS,
        signature: '0x' as Hex
    };

    const ethersDomain: EthersTypedDataDomain = {
        name: viemDomain.name,
        version: viemDomain.version,
        chainId: Number(viemDomain.chainId),
        verifyingContract: viemDomain.verifyingContract,
    };

    const ethersTypes: Record<string, Array<TypedDataField>> = {
        PackedUserOperation: metamaskToolkitTypes.PackedUserOperation.map(f => ({ name: f.name, type: f.type }))
    };

    const finalEip712EncodedPayload = await getEIP712EncodedPayloadEthers(
        ethersDomain,
        ethersTypes,
        messageForSigning
    );
    logger.info(`Encoded Payload: ${finalEip712EncodedPayload}`);

    // To mimic sign_test.ts: convert the hex payload to string, then hashMessage that string.

    const payloadAsHex = toHex(finalEip712EncodedPayload);
    logger.info(`Payload as Hex: ${payloadAsHex}`);
    
    const digestForVerification = hashMessage(finalEip712EncodedPayload);
    // Use library function to get signatures from Porter
    const { signatures: receivedPorterSignatures, claimedSigners: porterClaimedSigners } = await requestSignaturesFromPorter(
        porterBaseUrl,
        payloadAsHex, // Send the full encoded payload (0x1901...) to Porter
        ursulaChecksumsForRequest,
        porterThreshold,
    );

    return {
        porterSignatures: receivedPorterSignatures,
        digestToVerify: digestForVerification, // Return the keccak256 hash for verification procedures
        porterClaimedSigners
    };
}

// New function for local signature verification
// async function localVerifyCombinedSignature(...) // REMOVED - Replaced by library's verifySignaturesLocally

// New function for programmatic on-chain EIP-1271 verification
// const EIP1271_MAGIC_VALUE = "0x1626ba7e"; // REMOVED - Handled by library
// async function programmaticOnChainVerification(...) // REMOVED - Replaced by library's verifySignaturesOnChainViaEIP1271

// New function using ethers.js to get the EIP-712 encoded payload (pre-image of final hash)
async function getEIP712EncodedPayloadEthers(
    domain: EthersTypedDataDomain,
    types: Record<string, Array<TypedDataField>>,
    message: Record<string, any>
): Promise<string> {
    const typesForMessage = { ...types };
    delete typesForMessage.EIP712Domain;
    return TypedDataEncoder.encode(domain, typesForMessage, message);
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

    const { porterSignatures, digestToVerify, porterClaimedSigners } = await getThresholdSignatures(
        returnFundsUserOp, 
        multisigSmartAccount, 
        porterChecksums,
        Number(MULTISIG_CONTRACT_THRESHOLD)
    );
    const combinedSignature = aggregatePorterSignatures(porterSignatures);

    logger.info(`Digest for Verification (used for local & on-chain checks): ${digestToVerify}`);
    logger.info(`Combined Signature: ${combinedSignature}`);
    logger.info(`Porter claimed signers for this op: ${porterClaimedSigners.join(', ')}`);

    const isOnChainValid = await verifySignaturesOnChainViaEIP1271(
        provider, 
        multisigAddress,
        digestToVerify,   // Use the keccak256 hash of the EIP-712 encoded payload
        combinedSignature
    );

    if (!isOnChainValid) {
        // Keep this critical log, but the library function also logs errors
        logger.error('CRITICAL: Programmatic ON-CHAIN verification returned INVALID (as per library). ');
    }

    logger.info('Attempting local verification (verifying digest against Porter claimed signers)...');
    const isSignatureLocallyValid = await verifySignaturesLocally(
        digestToVerify, // Use the keccak256 hash of the EIP-712 encoded payload
        combinedSignature,
        MULTISIG_CONTRACT_THRESHOLD, 
        porterClaimedSigners,
    );

    if (!isSignatureLocallyValid ) {
        throw new Error('Local signature verification failed. Halting before sending UserOperation.');
    }
    if (!isOnChainValid) {
        throw new Error('On-chain signature verification failed. Halting before sending UserOperation.');
    }

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
        // await fundAAWallet(setupResult.provider, userSmartAccount.address, parseEther('0.001')); // Fund SA
        await logBalance('User Smart Account (before return)', setupResult.provider, userSmartAccount.address);
        await fundingAndReturning({
            ...setupResult,
            userSmartAccount,
            multisigSmartAccount,
            signedDelegation
        });
        logger.info('All done!');
    } catch (error) {
        logger.error('Error in main execution:', error);
        process.exit(1);
    }
})();

