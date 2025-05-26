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
import { ethers, TypedDataEncoder, keccak256, AbiCoder } from 'ethers';
import { Address, createPublicClient, Hex, http, parseEther, zeroAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { 
    createPaymasterClient,
    createBundlerClient,
} from 'viem/account-abstraction';
import { baseSepolia } from 'viem/chains';
import * as dotenv from 'dotenv';
import winston, { Logger } from 'winston';
import { getUserOperationHash } from 'viem/account-abstraction';

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

// toggle this flag accordingly
const USE_OLD_ENTRY_POINT = false;
var ENTRY_POINT_ADDRESS = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';
if (USE_OLD_ENTRY_POINT) {
    ENTRY_POINT_ADDRESS = '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789';
}

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
    
    // Create bundler client with proper configuration
    const bundlerClient = createBundlerClient({
        transport: http(process.env.BUNDLER_URL),
        chain: baseSepolia,
    });

    // Verify bundler is working
    try {
        await bundlerClient.getSupportedEntryPoints();
        logger.info('Bundler connection successful');
    } catch (error: any) {
        logger.error('Failed to connect to bundler. Please ensure you are using a valid ERC-4337 bundler endpoint');
        logger.error(`Error: ${error.message}`);
        throw new Error('Invalid bundler configuration');
    }
    
    const { createPimlicoClient } = await import("permissionless/clients/pimlico");
    const pimlicoClient = createPimlicoClient({ transport: http(process.env.BUNDLER_URL) });
    const {fast: fees} = await pimlicoClient.getUserOperationGasPrice();
    
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
    threshold,
    publicClient
}: any) {
    logger.info('--- EXECUTING VIA MULTISIG ---');

    const recipientAddress = localAccount.address;
    const transferAmount = parseEther('0.0001'); 

    // Create the execution data
    const executionData = {
        target: recipientAddress,
        value: transferAmount,
        callData: '0x' as `0x${string}`
    };

    // Prepare the execution UserOperation
    logger.debug(`Preparing user operation with data: target=${recipientAddress}, value=${transferAmount.toString()}, callData=${executionData.callData}`);

    try {
        // Get gas parameters first
        const { fast: fee } = await pimlicoClient!.getUserOperationGasPrice();
        logger.debug(`Got gas price: maxFeePerGas=${fee.maxFeePerGas.toString()}, maxPriorityFeePerGas=${fee.maxPriorityFeePerGas.toString()}`);

        // Check if the account is deployed
        const code = await publicClient.getBytecode({ address: userSmartAccount.address });
        const isDeployed = code !== '0x';
        logger.debug(`Smart account ${userSmartAccount.address} is ${isDeployed ? 'deployed' : 'not deployed'}`);
        logger.debug(`EntryPoint contract ${ENTRY_POINT_ADDRESS}`);

        // Get nonce (0 if not deployed)
        let nonce: bigint;
        if (isDeployed) {
            try {
                nonce = await publicClient.readContract({
                    address: userSmartAccount.address,
                    abi: [{
                        name: 'nonce',
                        type: 'function',
                        stateMutability: 'view',
                        inputs: [],
                        outputs: [{ type: 'uint256' }]
                    }],
                    functionName: 'nonce',
                });
            } catch (error) {
                logger.warn('Failed to read nonce from contract, defaulting to 0');
                nonce = 0n;
            }
        } else {
            nonce = 0n;
            logger.debug(`Using initCode: ${userSmartAccount.initCode}`);
        }

        // Manually construct the user operation
        const userOperation = {
            sender: userSmartAccount.address,
            nonce,
            initCode: isDeployed ? '0x' as `0x${string}` : userSmartAccount.initCode,
            callData: executionData.callData,
            callGasLimit: 500000n,
            verificationGasLimit: 500000n,
            preVerificationGas: 500000n,
            ...fee,
            paymasterAndData: '0x' as `0x${string}`,
            signature: '0x' as `0x${string}` // Placeholder, will be replaced after signing
        };

        // Create EIP-712 typed data for signing
        const domain = {
            name: "MultiSigDeleGator",
            version: "1",
            chainId: BASE_SEPOLIA_CHAIN_ID,
            verifyingContract: userSmartAccount.address
        };

        const types = {
            PackedUserOperation: [
                { name: "sender", type: "address" },
                { name: "nonce", type: "uint256" },
                { name: "initCode", type: "bytes" },
                { name: "callData", type: "bytes" },
                { name: "accountGasLimits", type: "bytes32" },
                { name: "preVerificationGas", type: "uint256" },
                { name: "gasFees", type: "bytes32" },
                { name: "paymasterAndData", type: "bytes" },
                { name: "signature", type: "bytes"}
            ]
        };

        // Encode gas limits and fees
        const abiCoder = new AbiCoder();
        const accountGasLimits = keccak256(
            abiCoder.encode(
                ["uint256", "uint256"],
                [userOperation.callGasLimit, userOperation.verificationGasLimit]
            )
        ) as `0x${string}`;

        const gasFees = keccak256(
            abiCoder.encode(
                ["uint256", "uint256"],
                [userOperation.maxFeePerGas, userOperation.maxPriorityFeePerGas]
            )
        ) as `0x${string}`;

        const packedUserOp = {
            sender: userSmartAccount.address,
            nonce,
            initCode: userOperation.initCode,
            callData: userOperation.callData,
            accountGasLimits,
            preVerificationGas: userOperation.preVerificationGas,
            gasFees,
            paymasterAndData: userOperation.paymasterAndData,
            signature: userOperation.signature
        };

        var userOpDigest = '0x';
        if(USE_OLD_ENTRY_POINT) {
            // User op hash
            userOpDigest = keccak256(abiCoder.encode(
                [
                  "address", "uint256", "bytes32", "bytes32",
                  "uint256", "uint256", "uint256", "uint256", "uint256",
                  "bytes32"
                ],
                [
                  userOperation.sender,
                  userOperation.nonce,
                  keccak256(userOperation.initCode),
                  keccak256(userOperation.callData),
                  userOperation.callGasLimit,
                  userOperation.verificationGasLimit,
                  userOperation.preVerificationGas,
                  userOperation.maxFeePerGas,
                  userOperation.maxPriorityFeePerGas,
                  keccak256(userOperation.paymasterAndData),
                ]
            ));
        } else {
            // packedUserOp
            userOpDigest = keccak256(abiCoder.encode(
                [
                  "address", "uint256", "bytes32", "bytes32",
                  "bytes32", "uint256", "bytes32", "bytes32"
                ],
                [
                  packedUserOp.sender,
                  packedUserOp.nonce,
                  keccak256(packedUserOp.initCode),
                  keccak256(packedUserOp.callData),
                  packedUserOp.accountGasLimits,
                  packedUserOp.preVerificationGas,
                  packedUserOp.gasFees,
                  keccak256(packedUserOp.paymasterAndData),
                ]
            ));
        }
        const localDigest = keccak256(
            abiCoder.encode([
                "bytes32", "address", "uint256"],
                [userOpDigest, ENTRY_POINT_ADDRESS, BASE_SEPOLIA_CHAIN_ID]
            )
        );
        logger.debug(`Generated local hash: ${localDigest}`);

        const digest = TypedDataEncoder.hash(domain, types, packedUserOp) as `0x${string}`;
        logger.debug(`Generated EIP-712 hash: ${digest}`);

        // Get signatures from Porter for the execution UserOperation
        logger.debug(`Requesting signatures from Porter...`);
        const { signatures: porterSignatures, claimedSigners, messageHash: porterHash } = await requestSignaturesFromPorter(
            PORTER_BASE_URL,
            digest,
            porterChecksums,
            Number(threshold),
            BASE_SEPOLIA_CHAIN_ID
        );
        logger.debug(`Got signatures from Porter: ${JSON.stringify(porterSignatures)}`);
        logger.debug(`Claimed signers: ${claimedSigners.join(', ')}`);
        logger.debug(`Porter hash: ${porterHash}`);

        // Verify the hash with EntryPoint contract
        const entryPointContract = new ethers.Contract(ENTRY_POINT_ADDRESS, [
            USE_OLD_ENTRY_POINT ?
            "function getUserOpHash(tuple(address sender, uint256 nonce, bytes initCode, bytes callData, uint256 callGasLimit, uint256 verificationGasLimit, uint256 preVerificationGas, uint256 maxFeePerGas, uint256 maxPriorityFeePerGas, bytes paymasterAndData, bytes signature) userOp) view returns (bytes32)"
            : "function getUserOpHash(tuple(address sender, uint256 nonce, bytes initCode, bytes callData, bytes32 accountGasLimits, uint256 preVerificationGas, bytes32 gasFees, bytes paymasterAndData, bytes signature) userOp) view returns (bytes32)"
        ], provider);
        
        const onChainHash = await entryPointContract.getUserOpHash(USE_OLD_ENTRY_POINT ? userOperation : packedUserOp);
        logger.debug(`EntryPoint hash: ${onChainHash}`);

        // Verify all hashes match
        if (onChainHash !== localDigest) {
            throw new Error(`Hash mismatch: local=${localDigest}, onchain=${onChainHash}`);
        }
        if (onChainHash !== digest) {
            throw new Error(`Hash mismatch: EIP-712=${digest}, onchain=${onChainHash}`);
        }
        if (porterHash !== digest) {
            throw new Error(`Hash mismatch: porter=${porterHash}, EIP-712=${digest}`);
        }
        logger.info('All hashes verified: Local, EIP-712, EntryPoint, and Porter match');

        // Verify we have enough signatures
        if (Object.keys(porterSignatures).length < Number(threshold)) {
            throw new Error(`Not enough signatures. Required: ${threshold}, Got: ${Object.keys(porterSignatures).length}`);
        }

        // Aggregate the signatures using the MetaMask Delegation Toolkit
        const signatureObjects = Object.entries(porterSignatures).map(([_, [signer, signature]]) => ({
            signer: signer as `0x${string}`,
            signature: signature as `0x${string}`,
            type: "ECDSA" as const
        }));

        const aggregatedSignature = aggregateSignature({
            signatures: signatureObjects
        });
        logger.debug(`Aggregated signature: ${aggregatedSignature}`);

        // Send the UserOperation with the aggregated signature
        logger.debug(`Sending user operation with signature...`);
        
        try {
            const userOperationHash = await bundlerClient!.sendUserOperation({
                ...userOperation,
                signature: aggregatedSignature,
            });
            logger.verbose(`Execution UserOp sent: ${userOperationHash}. Waiting for receipt...`);
            const { receipt } = await bundlerClient!.waitForUserOperationReceipt({ hash: userOperationHash });
            logger.info(`Execution completed, tx: ${receipt.transactionHash}`);

            // Verify the signature after the operation is sent
            try {
                const isValid = await verifySignaturesOnChainViaEIP1271(
                    provider,
                    userSmartAccount.address,
                    digest,
                    aggregatedSignature
                );
                if (!isValid) {
                    logger.warn('Signature verification failed after operation was sent');
                } else {
                    logger.info('Signature verification successful');
                }
            } catch (error: any) {
                logger.warn('Failed to verify signature after operation was sent');
                logger.warn(`Error: ${error.message}`);
            }

            await logBalance(`Local EOA (${localAccount.address}) AFTER transfer`, provider, localAccount.address);
            await logBalance('User Smart Account AFTER transfer', provider, userSmartAccount.address);
        } catch (error: any) {
            logger.error('Failed to send user operation to bundler');
            logger.error(`Error: ${error.message}`);
            if (error.details) {
                logger.error(`Error details: ${JSON.stringify(error.details, null, 2)}`);
            }
            throw new Error('Failed to send user operation');
        }
    } catch (error: any) {
        logger.error(`Error during user operation: ${error.message}`);
        if (error.details) {
            logger.error(`Error details: ${JSON.stringify(error.details, null, 2)}`);
        }
        throw error;
    }
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
            threshold,
            publicClient: env.publicClient
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

