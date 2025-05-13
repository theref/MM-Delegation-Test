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

dotenv.config();

// Sepolia network configuration
const BASE_SEPOLIA_CHAIN_ID = 84532;
const multisigAddress = "0x152aB00413e78be27D86061448B145d98ff7F22d";

  
const aggregateSignature = (
    signaturesWithAddress: { signature: Hex; address: Address }[],
) => {
    // signatures need to be sorted by address!
    signaturesWithAddress.sort((a, b) => a.address.localeCompare(b.address));

    return concat(signaturesWithAddress.map(({ signature }) => signature));
};

async function getThresholdSignatures(
    userOp: any,
    ursulaMetadata: { checksum_address: string }[],
    cohortId: number,
    threshold: number,
    porterBaseUrl: string
): Promise<{ [key: string]: string }> {
    // Convert BigInt values to strings before serialization
    const serializableUserOp = {
        ...userOp,
        nonce: userOp.nonce.toString(),
        callGasLimit: userOp.callGasLimit.toString(),
        verificationGasLimit: userOp.verificationGasLimit.toString(),
        preVerificationGas: userOp.preVerificationGas.toString(),
        maxFeePerGas: userOp.maxFeePerGas.toString(),
        maxPriorityFeePerGas: userOp.maxPriorityFeePerGas.toString()
    };

    // Convert userOp to bytes directly
    const userOpBytes = new TextEncoder().encode(JSON.stringify(serializableUserOp));
    
    // Create the request data matching the Python implementation
    const requestData = {
        data_to_sign: Buffer.from(userOpBytes).toString('hex'),
        cohort_id: cohortId,
        context: {}
    };

    // Convert to base64 exactly like the Python implementation
    const requestB64 = Buffer.from(JSON.stringify(requestData)).toString('base64');

    // Create signing requests object
    const signingRequests: { [key: string]: string } = {};
    for (const u of ursulaMetadata) {
        signingRequests[u.checksum_address] = requestB64;
    }

    const requestBody = {
        signing_requests: signingRequests,
        threshold: threshold,
    };

    console.log('Making request to:', `${porterBaseUrl}/sign`);
    const response = await fetch(`${porterBaseUrl}/sign`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
        const errorText = await response.text();
        console.error('Error response body:', errorText);
        throw new Error(`HTTP error! status: ${response.status}, body: ${errorText}`);
    }

    const data = await response.json();
    return data.result.signing_results;
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
    console.log('View on Etherscan:', `https://sepolia.etherscan.io/tx/${txResponse.hash}`);
    await txResponse.wait();
    console.log('Funding transaction confirmed');
}

// Helper to fetch and log ETH balance
async function logBalance(label: string, provider: ethers.JsonRpcProvider, address: string) {
    const balance = await provider.getBalance(address);
    console.log(`${label} balance:`, ethers.formatEther(balance), 'ETH');
}

// === 1. SETUP ===
/**
 * Sets up all clients, accounts, and environment variables.
 * Returns an object with all necessary handles for the rest of the flow.
 */
async function setup() {
    console.log('--- SETUP ---');
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
        throw new Error(`Wrong network. Expected Base Sepolia (${BASE_SEPOLIA_CHAIN_ID}), got chain ID ${network.chainId}`);
    }

    const environment: DeleGatorEnvironment = getDeleGatorEnvironment(BASE_SEPOLIA_CHAIN_ID);
    const publicClient = createPublicClient({
        chain: baseSepolia,
        transport: http(process.env.RPC_URL)
    });
    const paymasterClient = createPaymasterClient({ 
        transport: http('https://public.pimlico.io/v2/84532/rpc')
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
    return {
        provider,
        environment,
        publicClient,
        paymasterClient,
        pimlicoClient,
        fees,
        bundlerClient,
        localAccount,
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
    paymasterClient
}: any) {
    console.log('\n--- DELEGATION & REDEEM ---');
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
    console.log('User Smart Account created:', userSmartAccount.address);

    // Create delegation from delegator to delegatee
    const delegation = createDelegation({
        to: multisigAddress,
        from: userSmartAccount.address,
        caveats: []
    });
    console.log('Delegation created:', JSON.stringify(delegation, null, 2));

    // Sign the delegation
    const signature = await userSmartAccount.signDelegation({ delegation });
    const signedDelegation = { ...delegation, signature };
    return { userSmartAccount, signedDelegation };
}

// === 3. FUNDING & RETURNING ===
/**
 * Funds the Hybrid account and uses the MultiSig to return funds to the local EOA via the delegation framework.
 */
async function fundingAndReturning({
    provider,
    userSmartAccount,
    signedDelegation,
    localAccount,
    bundlerClient,
    pimlicoClient,
    publicClient,
    paymasterClient
}: any) {
    console.log('\n--- FUNDING & RETURNING ---');
    // Log balance before funding
    // await logBalance('User Smart Account (before funding)', provider, userSmartAccount.address);
    // // Fund the delegator smart account
    // console.log('Funding the User Smart Account wallet...');
    // await fundAAWallet(
    //     provider,
    //     userSmartAccount.address,
    //     parseEther('0.001')
    // );
    // // Log balance after funding
    await logBalance('User Smart Account (after funding)', provider, userSmartAccount.address);
    console.log('Returning funds through delegation...');
    const executions = [{
        target: localAccount.address,  
        value: parseEther('0.0005'),
        callData: '0x' as `0x${string}`
    }];
    const returnFundsCalldata = DelegationFramework.encode.redeemDelegations({
      delegations: [[signedDelegation]],
      modes: [SINGLE_DEFAULT_MODE],
      executions: [executions]
    });
    const { fast: newFees } = await pimlicoClient.getUserOperationGasPrice();
    console.log('New fees:', newFees);
    
    // Create user operation with default gas values
    const userOp = {
        sender: multisigAddress as `0x${string}`,
        nonce: BigInt(await publicClient.getTransactionCount({ address: multisigAddress })),
        initCode: '0x' as `0x${string}`,
        callData: returnFundsCalldata,
        callGasLimit: BigInt(100000),
        verificationGasLimit: BigInt(500000),
        preVerificationGas: BigInt(21000),
        maxFeePerGas: newFees.maxFeePerGas,
        maxPriorityFeePerGas: newFees.maxPriorityFeePerGas,
        paymasterAndData: '0x' as `0x${string}`,
        signature: '0x' as `0x${string}`
    } as const;

    // Get paymaster data with proper type handling
    const paymasterData = await paymasterClient.getPaymasterData({
        sender: userOp.sender,
        nonce: userOp.nonce,
        initCode: userOp.initCode,
        callData: userOp.callData,
        callGasLimit: userOp.callGasLimit,
        verificationGasLimit: userOp.verificationGasLimit,
        preVerificationGas: userOp.preVerificationGas,
        maxFeePerGas: userOp.maxFeePerGas,
        maxPriorityFeePerGas: userOp.maxPriorityFeePerGas,
        paymasterAndData: userOp.paymasterAndData,
        signature: userOp.signature,
        chainId: BASE_SEPOLIA_CHAIN_ID,
        entryPointAddress: '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789' // Base Sepolia EntryPoint
    });

    // Update user operation with paymaster data
    const finalUserOp = {
        ...userOp,
        paymasterAndData: paymasterData
    };
    const userOpSignature = await getThresholdSignatures(finalUserOp, [
        { checksum_address: multisigAddress }
    ], 0, 2, "https://porter-lynx.nucypher.community");
    console.log('User operation signature:', userOpSignature);
    const userOpHash = await bundlerClient.sendUserOperation({
        ...finalUserOp,
        signature: userOpSignature[multisigAddress]
    });
    console.log('Return funds UserOperation hash:', userOpHash);
    // Wait for the UserOperation to be mined
    const receipt = await bundlerClient.waitForUserOperationReceipt({
        hash: userOpHash,
        pollingInterval: 1000,
        retryCount: 100
    });
    console.log('Return funds transaction hash:', receipt.receipt.transactionHash);
    console.log('View on Etherscan:', `https://sepolia.etherscan.io/tx/${receipt.receipt.transactionHash}`);
    // Log balance after return
    await logBalance('User Smart Account (after return)', provider, userSmartAccount.address);

}

interface ContextDict {
    [key: string]: any;
}

class ThresholdSignatureRequest {
    data_to_sign: Uint8Array;
    cohort_id: number;
    context: ContextDict;

    constructor(
        data_to_sign: Uint8Array,
        cohort_id: number,
        context: ContextDict = {}
    ) {
        this.data_to_sign = data_to_sign;
        this.cohort_id = cohort_id;
        this.context = context;
    }

    toBytes(): Uint8Array {
        const data = {
            data_to_sign: Buffer.from(this.data_to_sign).toString('hex'),
            cohort_id: this.cohort_id,
            context: this.context,
        };
        return new TextEncoder().encode(JSON.stringify(data));
    }

    static fromBytes(requestData: Uint8Array): ThresholdSignatureRequest {
        const result = JSON.parse(new TextDecoder().decode(requestData));
        const data_to_sign = Buffer.from(result.data_to_sign, 'hex');
        const cohort_id = result.cohort_id;
        const context = result.context;
        return new ThresholdSignatureRequest(
            new Uint8Array(data_to_sign),
            cohort_id,
            context
        );
    }
}

// === MAIN FLOW ===
(async function main() {
    try {
        const setupResult = await setup();
        const { userSmartAccount, signedDelegation } = await Delegate(setupResult);
        await fundingAndReturning({
            ...setupResult,
            userSmartAccount,
            signedDelegation
        });
        console.log('\nAll done!');
    } catch (error) {
        console.error('Error:', error);
        process.exit(1);
    }
})();
