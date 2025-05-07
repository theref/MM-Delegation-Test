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
import { Address, concat, createPublicClient, createWalletClient, Hex, http, parseEther, WalletClient, zeroAddress } from 'viem';
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

async function main() {
    try {
        // Initialize provider using JSON RPC URL
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
        
        // Verify we're on Sepolia
        const network = await provider.getNetwork();
        if (network.chainId !== BigInt(SEPOLIA_CHAIN_ID)) {
            throw new Error(`Wrong network. Expected Sepolia (${SEPOLIA_CHAIN_ID}), got chain ID ${network.chainId}`);
        }

        // Get the delegator environment for Sepolia
        const environment: DeleGatorEnvironment = getDeleGatorEnvironment(SEPOLIA_CHAIN_ID);
        console.log('Delegator environment:', environment);
        
        // Create public client for Sepolia
        const publicClient = createPublicClient({
            chain: sepolia,
            transport: http(process.env.RPC_URL)
        });

        const paymasterClient = createPaymasterClient({ 
            transport: http('https://public.pimlico.io/v2/11155111/rpc'), 
        })

        const { createPimlicoClient } = await import("permissionless/clients/pimlico");
        const pimlicoClient = createPimlicoClient({
            transport: http(process.env.BUNDLER_URL),
        });
        const {fast: fees} = await pimlicoClient.getUserOperationGasPrice();

        // Create bundler client
        const bundlerClient = createBundlerClient({
            transport: http(process.env.BUNDLER_URL),
            paymaster: paymasterClient,
            chain: sepolia
        });

        // Create delegator account (Hybrid implementation)
        const localAccount = privateKeyToAccount(process.env.PRIVATE_KEY as `0x${string}`);
        console.log('Creating delegator account with address:', localAccount.address);
        
        const delegatorSmartAccount = await toMetaMaskSmartAccount({
            client: publicClient,
            implementation: Implementation.Hybrid,
            deployParams: [localAccount.address, [], [], []],
            deploySalt: "0x",
            signatory: { account: localAccount }
        });
        console.log('Delegator Smart Account created:', delegatorSmartAccount.address);

        // Create delegatee account (MultiSig implementation)
        console.log('Creating delegatee account with signers:');
        const walletClientPivatekey1 = generatePrivateKey(); 
        const walletClientAccount1 = privateKeyToAccount(walletClientPivatekey1);
        console.log('Signer 1:', walletClientAccount1.address);
        
        const walletClientPivatekey2 = generatePrivateKey(); 
        const walletClientAccount2 = privateKeyToAccount(walletClientPivatekey2);
        console.log('Signer 2:', walletClientAccount2.address);

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
        console.log('Creating delegation...');
        const delegation = createDelegation({
            to: delegateeSmartAccount.address,
            from: delegatorSmartAccount.address,
            caveats: [] // Empty caveats array - we recommend adding appropriate restrictions
        });
        console.log('Delegation created:', JSON.stringify(delegation, null, 2));

        // Sign the delegation
        console.log('Signing delegation...');
        try {
            const signature = await delegatorSmartAccount.signDelegation({
                delegation
            });
            console.log('Delegation signed with signature:', signature);

            const signedDelegation = {
                ...delegation,
                signature
            };

            // Encode the redeem delegation call with empty execution
            console.log('Encoding redeem delegation call...');
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
            console.log('Redeem delegation calldata:', redeemDelegationCalldata);

            // Send user operation to redeem delegation
            console.log('Sending user operation to redeem delegation...');
            try {
                // Create the user operation
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

                // Get the user operation hash
                // const userOperationHash = getUserOperationHash({
                //     userOperation,
                //     entryPointAddress: environment.EntryPoint as `0x${string}`,
                //     chainId: SEPOLIA_CHAIN_ID,
                //     entryPointVersion: '0.6'
                // });

                // Sign with both signers
                console.log('Signing user operation with both signers...');
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
                  
                const signature1 = await signUserOperation(userOperation, walletClient1, delegateeSmartAccount);
                const signature2 = await signUserOperation(userOperation, walletClient2, delegateeSmartAccount);
                
                const combinedSignature = aggregateSignature([
                    { signature: signature1, address: walletClientAccount1.address },
                    { signature: signature2, address: walletClientAccount2.address },
                ]);

                // Add signature to user operation
                const signedUserOperation = {
                    ...userOperation,
                    signature: combinedSignature
                };

                // Send the signed user operation
                const hash = await bundlerClient.sendUserOperation(signedUserOperation);
                
                console.log('User operation sent!');
                console.log('User operation hash:', hash);
            } catch (error) {
                console.error('Error sending user operation:', error);
                if (error instanceof Error) {
                    console.error('Error details:', error.message);
                    console.error('Error stack:', error.stack);
                }
            }
        } catch (error) {
            console.error('Error signing delegation:', error);
            if (error instanceof Error) {
                console.error('Error details:', error.message);
                console.error('Error stack:', error.stack);
            }
        }
    } catch (error) {
        console.error('Error:', error);
        process.exit(1);
    }
}

// Run the demo
main();
