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
import { sepolia } from 'viem/chains';
import * as dotenv from 'dotenv';

dotenv.config();

// Sepolia network configuration
const SEPOLIA_CHAIN_ID = 11155111;


const signUserOperation = async (params: SignUserOperationParams, owner: WalletClient, smartAccount: MetaMaskSmartAccount) => {
    const { chainId } = params;
  
    const packedUserOp = toPackedUserOperation({
      sender: smartAccount.address,
      ...params,
    });
  
    const signature = await owner.signTypedData({
      account: owner.account!,
      domain: {
        chainId: chainId || sepolia.id,
        // This should be HyridDeleGator for Implementation.hybrid
        name: 'MultiSigDeleGator',
        version: '1',
        verifyingContract: smartAccount.address,
      },
      types: SIGNABLE_USER_OP_TYPED_DATA,
      primaryType: 'PackedUserOperation',
      message: { ...packedUserOp, entryPoint: smartAccount.entryPoint.address as `0x${string}` },
    });
  
    return signature;
};
  
const aggregateSignature = (
    signaturesWithAddress: { signature: Hex; address: Address }[],
  ) => {
    // signatures need to be sorted by address!
    signaturesWithAddress.sort((a, b) => a.address.localeCompare(b.address));
  
    return concat(signaturesWithAddress.map(({ signature }) => signature));
};

// Helper function to sign a user operation with multiple signers and aggregate the signatures
async function signUserOperationWithMultisig(
    userOperation: any,
    signers: { walletClient: WalletClient, account: any }[],
    smartAccount: MetaMaskSmartAccount
): Promise<Hex> {
    const signaturesWithAddress = [];
    for (const { walletClient, account } of signers) {
        const signature = await signUserOperation(userOperation, walletClient, smartAccount);
        signaturesWithAddress.push({ signature, address: account.address });
    }
    return aggregateSignature(signaturesWithAddress);
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
    if (network.chainId !== BigInt(SEPOLIA_CHAIN_ID)) {
        throw new Error(`Wrong network. Expected Sepolia (${SEPOLIA_CHAIN_ID}), got chain ID ${network.chainId}`);
    }

    const environment: DeleGatorEnvironment = getDeleGatorEnvironment(SEPOLIA_CHAIN_ID);
    const publicClient = createPublicClient({
        chain: sepolia,
        transport: http(process.env.RPC_URL)
    });
    const paymasterClient = createPaymasterClient({ 
        transport: http('https://public.pimlico.io/v2/11155111/rpc'), 
    });
    const { createPimlicoClient } = await import("permissionless/clients/pimlico");
    const pimlicoClient = createPimlicoClient({
        transport: http(process.env.BUNDLER_URL),
    });
    const {fast: fees} = await pimlicoClient.getUserOperationGasPrice();
    const bundlerClient = createBundlerClient({
        transport: http(process.env.BUNDLER_URL),
        paymaster: paymasterClient,
        chain: sepolia
    });
    const localAccount = privateKeyToAccount(process.env.PRIVATE_KEY as `0x${string}`);
    const walletClientPivatekey1 = generatePrivateKey(); 
    const walletClientAccount1 = privateKeyToAccount(walletClientPivatekey1);
    const walletClientPivatekey2 = generatePrivateKey(); 
    const walletClientAccount2 = privateKeyToAccount(walletClientPivatekey2);
    const walletClient1 = createWalletClient({
        account: walletClientAccount1,
        chain: sepolia,
        transport: http(process.env.RPC_URL)
    });
    const walletClient2 = createWalletClient({
        account: walletClientAccount2,
        chain: sepolia,
        transport: http(process.env.RPC_URL)
    });
    return {
        provider,
        environment,
        publicClient,
        paymasterClient,
        pimlicoClient,
        fees,
        bundlerClient,
        localAccount,
        walletClientAccount1,
        walletClientAccount2,
        walletClient1,
        walletClient2
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
    walletClientAccount1,
    walletClientAccount2,
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

    // Create delegatee account (MultiSig implementation)
    const signers = [walletClientAccount1.address, walletClientAccount2.address];
    const threshold = BigInt(2);
    const signatory = [
        { account: walletClientAccount1 },
        { account: walletClientAccount2 }
    ];
    const multisigSmartAccount = await toMetaMaskSmartAccount({
        client: publicClient,
        implementation: Implementation.MultiSig,
        deployParams: [signers, threshold],
        deploySalt: "0x",
        signatory
    });
    console.log('Multisig Smart Account created:', multisigSmartAccount.address);

    // Create delegation from delegator to delegatee
    const delegation = createDelegation({
        to: multisigSmartAccount.address,
        from: userSmartAccount.address,
        caveats: []
    });
    console.log('Delegation created:', JSON.stringify(delegation, null, 2));

    // Sign the delegation
    const signature = await userSmartAccount.signDelegation({ delegation });
    const signedDelegation = { ...delegation, signature };
    return { userSmartAccount, multisigSmartAccount, signedDelegation };
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
    walletClient1,
    walletClient2,
    walletClientAccount1,
    walletClientAccount2,
    pimlicoClient
}: any) {
    console.log('\n--- FUNDING & RETURNING ---');
    // Log balance before funding
    await logBalance('User Smart Account (before funding)', provider, userSmartAccount.address);
    // Fund the delegator smart account
    console.log('Funding the User Smart Account wallet...');
    await fundAAWallet(
        provider,
        userSmartAccount.address,
        parseEther('0.001')
    );
    // Log balance after funding
    await logBalance('User Smart Account (after funding)', provider, userSmartAccount.address);
    console.log('Returning funds through delegation...');
    const executions = [{
        target: localAccount.address,  
        value: parseEther('0.005'),
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
    const returnFundsSig = await signUserOperationWithMultisig(
      returnFundsUserOp,
      [
        { walletClient: walletClient1, account: walletClientAccount1 },
        { walletClient: walletClient2, account: walletClientAccount2 }
      ],
      multisigSmartAccount
    );
    console.log('Return funds user operation sent!');
    const userOpHash = await bundlerClient.sendUserOperation({
      ...returnFundsUserOp,
      signature: returnFundsSig
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
        console.log('\nAll done!');
    } catch (error) {
        console.error('Error:', error);
        process.exit(1);
    }
})();
