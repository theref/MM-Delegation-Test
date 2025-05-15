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
import { Address, concat, createPublicClient, createWalletClient, encodeFunctionData, Hex, http, parseEther, WalletClient, zeroAddress, hashTypedData, TypedDataDomain as ViemTypedDataDomain, recoverMessageAddress, hashMessage } from 'viem';
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
const SIGNATURE_LENGTH = 65; // Standard Ethereum signature length (r: 32, s: 32, v: 1)

const aggregateSignature = (
    signaturesWithAddress: { [checksumAddress: string]: [string, string] }
) => {
    // Convert object to array of [signer_address, signature] pairs and sort by signer address
    const sortedSignaturePairs = Object.entries(signaturesWithAddress)
        .sort(([_, [addr1]], [__, [addr2]]) => 
            addr1.toLowerCase().localeCompare(addr2.toLowerCase())
        );

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
    userOp: UserOperation,
    multisigSmartAccount: MetaMaskSmartAccount,
    ursulaChecksums: `0x${string}`[],
    cohortId: number,
    porterThreshold: number
): Promise<{ porterSignatures: { [checksumAddress: string]: [string, string] }; payloadData: string }> {
    const packedUserOp = toPackedUserOperation(userOp);

    const viemDomain: ViemTypedDataDomain = {
        name: 'MultiSigDeleGator',
        version: '1',
        chainId: BigInt(BASE_SEPOLIA_CHAIN_ID),
        verifyingContract: multisigSmartAccount.address
    };

    // Note: `types` here is using SIGNABLE_USER_OP_TYPED_DATA from @metamask/delegation-toolkit
    // Ensure its structure is compatible with ethers.js if primaryType determination becomes an issue.
    const metamaskToolkitTypes = { ...SIGNABLE_USER_OP_TYPED_DATA } as const;

    // Default EntryPoint v0.6 address, verify if this is correct for your setup
    const DEFAULT_ENTRY_POINT_ADDRESS = '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789' as Address;

    const messageForSigning = {
        ...packedUserOp,
        entryPoint: DEFAULT_ENTRY_POINT_ADDRESS, 
        signature: '0x' as Hex
    };

    // --- Prepare data for EIP-712 payload encoding using ethers.js ---
    const ethersDomain: EthersTypedDataDomain = {
        name: viemDomain.name,
        version: viemDomain.version,
        chainId: Number(viemDomain.chainId),
        verifyingContract: viemDomain.verifyingContract,
    };

    // Map Metamask Toolkit types to ethers.js TypedDataField format
    const ethersTypes: Record<string, Array<TypedDataField>> = {
        PackedUserOperation: metamaskToolkitTypes.PackedUserOperation.map(f => ({ name: f.name, type: f.type }))
    };

    let eip712Payload: string;
    try {
        eip712Payload = await getEIP712EncodedPayloadEthers(
            ethersDomain,
            ethersTypes, // Contains only PackedUserOperation definition
            messageForSigning
        );
        logger.info(`EIP-712 Encoded Payload (this will be sent to Porter in data_to_sign): ${eip712Payload}`);
    } catch (e: any) {
        logger.error("Error getting EIP-712 encoded payload with ethers: ", e.message);
        throw new Error(`Failed to generate EIP-712 payload for Porter: ${e.message}`);
    }

    // Send the raw EIP-712 payload string to Porter
    const requestData = { data_to_sign: eip712Payload, cohort_id: cohortId, context: {} };
    const requestB64 = Buffer.from(JSON.stringify(requestData)).toString('base64');

    const signingRequests: { [key: string]: string } = {};
    for (const address of ursulaChecksums) { 
        if (address && typeof address === 'string') { 
            signingRequests[address] = requestB64; 
        } else { 
            logger.warn('Skipping invalid Ursula address for signing request: ', address); 
        } 
    }
    
    const requestBody = { signing_requests: signingRequests, threshold: porterThreshold };
    const response = await fetch(`${porterBaseUrl}/sign`, { 
        method: 'POST', 
        headers: {'Content-Type':'application/json'}, 
        body: JSON.stringify(requestBody) 
    });

    if (!response.ok) { 
        const errorText = await response.text(); 
        logger.error('Porter error response body:', errorText); 
        throw new Error(`Porter HTTP error! status: ${response.status}, details: ${errorText}`); 
    }
    
    const data = await response.json();
    logger.debug(`Response data from Porter: ${JSON.stringify(data, null, 2)}`);

    if (!data.result?.signing_results?.signatures) { 
        logger.error('Invalid response format from Porter: missing signatures. Response data:', data);
        throw new Error('Invalid response format from Porter: missing signatures'); 
    }

    // Return signatures and hashMessage(eip712Payload)
    return { porterSignatures: data.result.signing_results.signatures, payloadData: requestB64 };
}

// New function for local signature verification
async function localVerifyCombinedSignature({
    hashToVerify,
    combinedSignature,
    contractThreshold, 
    expectedSigners,
    signatureLength = SIGNATURE_LENGTH
}: {
    hashToVerify: Hex;
    combinedSignature: Hex;
    contractThreshold: bigint; 
    expectedSigners: readonly Address[];
    signatureLength?: number;
}): Promise<boolean> {
    const numSignaturesRequired = Number(contractThreshold);

    // Check 1: Combined signature must have a total length that's a multiple of individual signature lengths.
    if ((combinedSignature.length - 2) % (signatureLength * 2) !== 0) {
        return false; 
    }
    const actualNumSignatures = (combinedSignature.length - 2) / (signatureLength * 2);

    // Check 2: The number of signatures found must match the required threshold.
    if (actualNumSignatures >= numSignaturesRequired) {
        return false;
    }

    let lastRecoveredSigner: Address = zeroAddress;
    const recoveredSignersInThisSet = new Set<Address>();
    const lowerCaseExpectedSigners = expectedSigners.map(s => s.toLowerCase() as Address);

    for (let i = 0; i < numSignaturesRequired; i++) {
        const sigOffset = 2 + i * signatureLength * 2;
        const individualSignature = `0x${combinedSignature.substring(sigOffset, sigOffset + signatureLength * 2)}` as Hex;

        try {
            const recoveredAddress = await recoverMessageAddress({
                message: { raw: hashToVerify },
                signature: individualSignature
            });
            const lowerCaseRecoveredAddress = recoveredAddress.toLowerCase() as Address;

            // Check 3: Recovered signer must be in the expected list.
            if (!lowerCaseExpectedSigners.includes(lowerCaseRecoveredAddress)) {
                return false;
            }

            // Check 4: Signers must be in strictly ascending order.
            // This also implies the first recovered address cannot be zeroAddress if lastRecoveredSigner was zeroAddress.
            if (lowerCaseRecoveredAddress.localeCompare(lastRecoveredSigner) <= 0) {
                return false;
            }

            recoveredSignersInThisSet.add(lowerCaseRecoveredAddress);
            lastRecoveredSigner = lowerCaseRecoveredAddress;
        } catch (e) {
            return false; // Error during signature recovery means invalid.
        }
    }

    return true; // All checks passed for all required signatures.
}

// New function for programmatic on-chain EIP-1271 verification
const EIP1271_MAGIC_VALUE = "0x1626ba7e";
async function programmaticOnChainVerification(
    provider: ethers.JsonRpcProvider,
    contractAddress: Address,
    hashToVerify: Hex,
    combinedSignature: Hex
): Promise<boolean> {
    logger.info(`--- Verifying on-chain (EIP-1271) sig for contract ${contractAddress}, hash ${hashToVerify} ---`);

    const contractAbi = [
        "function isValidSignature(bytes32 _hash, bytes _signature) external view returns (bytes4)"
    ];

    const contract = new ethers.Contract(contractAddress, contractAbi, provider);

    try {
        const result: string = await contract.isValidSignature(hashToVerify, combinedSignature);
        logger.debug(`On-chain isValidSignature for ${contractAddress} (hash: ${hashToVerify}) returned: ${result}`);
        if (result.toLowerCase() === EIP1271_MAGIC_VALUE.toLowerCase()) {
            logger.info(`SUCCESS: On-chain verification for ${contractAddress} PASSED.`);
            return true;
        } else {
            logger.error(`FAILURE: On-chain verification for ${contractAddress} FAILED. Expected ${EIP1271_MAGIC_VALUE}, got ${result}.`);
            return false;
        }
    } catch (error: any) {
        logger.error(`ERROR during on-chain verification for ${contractAddress} (hash: ${hashToVerify}):`, error);
        return false;
    }
}

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

    const { porterSignatures, payloadData } = await getThresholdSignatures(
        returnFundsUserOp, 
        multisigSmartAccount, 
        porterChecksums, 
        0, 
        Number(MULTISIG_CONTRACT_THRESHOLD)
    );
    const combinedSignature = aggregateSignature(porterSignatures);
    const hashActuallySignedByPorter = hashMessage(payloadData);
    logger.info(`Hash actually signed by Porter: ${hashActuallySignedByPorter}`);
    logger.info(`Combined Signature: ${combinedSignature}`);

    const isOnChainValid = await programmaticOnChainVerification(
        provider, 
        multisigSmartAccount.address, // Target the actual smart account address for this UserOp
        hashActuallySignedByPorter,   // Use the hash that Porter actually signed
        combinedSignature
    );

    if (!isOnChainValid) {
        logger.error('CRITICAL: Programmatic ON-CHAIN verification returned INVALID.');
    }

    logger.info('Attempting local verification using the hash actually signed by Porter...');
    const isSignatureLocallyValid = await localVerifyCombinedSignature({
        hashToVerify: hashActuallySignedByPorter, // Use the hash that Porter actually signed
        combinedSignature,
        contractThreshold: MULTISIG_CONTRACT_THRESHOLD, 
        expectedSigners: signers, 
    });

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

