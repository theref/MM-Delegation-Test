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

// Example recipient address for the transaction
const RECIPIENT_ADDRESS = '0x2215a197a32834ef93C4D1029551bB8D3B924DCc' as `0x${string}`;

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
async function delegationAndRedeem({
    publicClient,
    localAccount,
    walletClientAccount1,
    walletClientAccount2,
    walletClient1,
    walletClient2,
    bundlerClient,
    fees
}: any) {
    console.log('\n--- DELEGATION & REDEEM ---');
    // Create delegator account (Hybrid implementation)
    const delegatorSmartAccount = await toMetaMaskSmartAccount({
        client: publicClient,
        implementation: Implementation.Hybrid,
        deployParams: [localAccount.address, [], [], []],
        deploySalt: "0x",
        signatory: { account: localAccount }
    });
    console.log('Delegator Smart Account created:', delegatorSmartAccount.address);

    // Create delegatee account (MultiSig implementation)
    const signers = [walletClientAccount1.address, walletClientAccount2.address];
    const threshold = BigInt(2);
    const signatory = [
        { account: walletClientAccount1 },
        { account: walletClientAccount2 }
    ];
    const delegateeSmartAccount = await toMetaMaskSmartAccount({
        client: publicClient,
        implementation: Implementation.MultiSig,
        deployParams: [signers, threshold],
        deploySalt: "0x",
        signatory
    });
    console.log('Delegate Smart Account created:', delegateeSmartAccount.address);

    // Create delegation from delegator to delegatee
    const delegation = createDelegation({
        to: delegateeSmartAccount.address,
        from: delegatorSmartAccount.address,
        caveats: []
    });
    console.log('Delegation created:', JSON.stringify(delegation, null, 2));

    // Sign the delegation
    const signature = await delegatorSmartAccount.signDelegation({ delegation });
    const signedDelegation = { ...delegation, signature };

    // Encode the redeem delegation call with empty execution
    const executions = [{
        target: zeroAddress,  
        value: 0n, 
        callData: '0x' as `0x${string}`
    }];
    const redeemDelegationCalldata = DelegationFramework.encode.redeemDelegations({
        delegations: [[signedDelegation]],
        modes: [SINGLE_DEFAULT_MODE],
        executions: [executions]
    });

    // Send user operation to redeem delegation
    const userOperation = await bundlerClient.prepareUserOperation({
        account: delegateeSmartAccount,
        calls: [
            {
                to: delegatorSmartAccount.address,
                data: redeemDelegationCalldata
            }
        ],
        ...fees,
    });
    const combinedSignature = await signUserOperationWithMultisig(
        userOperation,
        [
            { walletClient: walletClient1, account: walletClientAccount1 },
            { walletClient: walletClient2, account: walletClientAccount2 }
        ],
        delegateeSmartAccount
    );
    const signedUserOperation = {
        ...userOperation,
        signature: combinedSignature
    };
    const userOpHash = await bundlerClient.sendUserOperation(signedUserOperation);
    console.log('Redemption UserOperation hash:', userOpHash);
    // Wait for the UserOperation to be mined
    const receipt = await bundlerClient.waitForUserOperationReceipt({
        hash: userOpHash,
        pollingInterval: 1000,
        retryCount: 10
    });
    console.log('Redemption transaction hash:', receipt.receipt.transactionHash);
    console.log('View on Etherscan:', `https://sepolia.etherscan.io/tx/${receipt.receipt.transactionHash}`);
    return { delegatorSmartAccount, delegateeSmartAccount, signedDelegation };
}

// === 3. FUNDING & RETURNING ===
/**
 * Funds the Hybrid account and uses the MultiSig to return funds to the local EOA via the delegation framework.
 */
async function fundingAndReturning({
    provider,
    delegatorSmartAccount,
    delegateeSmartAccount,
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
    await logBalance('Delegator (before funding)', provider, delegatorSmartAccount.address);
    // Fund the delegator smart account
    console.log('Funding the AA wallet...');
    await fundAAWallet(
        provider,
        delegatorSmartAccount.address,
        parseEther('0.001')
    );
    // Log balance after funding
    await logBalance('Delegator (after funding)', provider, delegatorSmartAccount.address);

    // Return funds through delegation
    await logBalance('Delegator (before return)', provider, delegatorSmartAccount.address);
    console.log('Returning funds through delegation...');
    const encodedCall = encodeFunctionData({
        abi: [{
          type: 'function',
          name: 'execute',
          stateMutability: 'payable',
          inputs: [
            { name: 'target', type: 'address' },
            { name: 'value', type: 'uint256' },
            { name: 'data', type: 'bytes' },
          ],
          outputs: []
        }],
        functionName: 'execute',
        args: [localAccount.address, parseEther('0.001'), '0x'],
    });
    const executions = [{
        target: delegatorSmartAccount.address,
        value: 0n, // The Hybrid delegator sends, not the Delegatee
        callData: encodedCall
    }];
    const returnFundsCalldata = DelegationFramework.encode.redeemDelegations({
      delegations: [[signedDelegation]],
      modes: [SINGLE_DEFAULT_MODE],
      executions: [executions]
    });
    const { fast: newFees } = await pimlicoClient.getUserOperationGasPrice();
    const returnFundsUserOp = await bundlerClient.prepareUserOperation({
      account: delegateeSmartAccount,
      calls: [
        {
          to: delegatorSmartAccount.address,
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
      delegateeSmartAccount
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
        retryCount: 10
    });
    console.log('Return funds transaction hash:', receipt.receipt.transactionHash);
    console.log('View on Etherscan:', `https://sepolia.etherscan.io/tx/${receipt.receipt.transactionHash}`);
    // Log balance after return
    await logBalance('Delegator (after return)', provider, delegatorSmartAccount.address);

}

// === MAIN FLOW ===
(async function main() {
    try {
        const setupResult = await setup();
        const { delegatorSmartAccount, delegateeSmartAccount, signedDelegation } = await delegationAndRedeem(setupResult);
        await fundingAndReturning({
            ...setupResult,
            delegatorSmartAccount,
            delegateeSmartAccount,
            signedDelegation
        });
        console.log('\nAll done!');
    } catch (error) {
        console.error('Error:', error);
        process.exit(1);
    }
})();
