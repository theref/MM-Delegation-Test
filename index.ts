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
import { SigningCoordinator, SigningCoordinatorAgent } from '@nucypher/shared';
import { initialize, domains, signUserOp } from '@nucypher/taco';


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
var ENTRY_POINT_ADDRESS = "0x0000000071727De22E5E9d8BAf0edAc6f37da032" as Address; // v_0_7 (currently used by MDT)

const BASE_SEPOLIA_CHAIN_ID = 84532;
const COHORT_ID = 1;
const TACO_DOMAIN = domains.DEVNET;
const ETH_PROVIDER = new ethers.providers.JsonRpcProvider("https://sepolia.drpc.org");

async function logBalance(label: string, provider: ethers.providers.JsonRpcProvider, address: string) {
    const balance = await provider.getBalance(address);
    logger.info(`${label} balance: ${ethers.utils.formatEther(balance)} ETH`);
}

async function setupEnvironment() {
    await initialize();

    logger.info('--- SETUP ---');
    if (!process.env.RPC_URL) throw new Error('Please set RPC_URL in your .env file');
    if (!process.env.PRIVATE_KEY) throw new Error('Please set PRIVATE_KEY in your .env file');
    if (!process.env.BUNDLER_URL) throw new Error('Please set BUNDLER_URL in your .env file (needed for Pimlico client for gas prices)');

    const provider = new ethers.providers.JsonRpcProvider(process.env.RPC_URL);
    const network = await provider.getNetwork();
    if (network.chainId !== BASE_SEPOLIA_CHAIN_ID) {
        throw new Error(`Wrong network. Expected Base Sepolia (${BASE_SEPOLIA_CHAIN_ID}), got chain ID ${network.chainId}`);
    }

    const publicClient = createPublicClient({
        chain: baseSepolia,
        transport: http(process.env.RPC_URL)
    });

    const paymasterClient = createPaymasterClient({
        transport: http(process.env.BUNDLER_URL)
    });
    
    // Create bundler client with proper configuration
    const bundlerClient = createBundlerClient({
        // client: publicClient,
        transport: http(process.env.BUNDLER_URL),
        paymaster: paymasterClient,
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

    logger.info("Setup complete. Returning environment...");
    return {
        provider: provider,
        publicClient,
        pimlicoClient,
        fees,
        bundlerClient,
        localAccount,
    };
}

async function deployAndSetupSmartAccount({
    publicClient,
    localAccount,
    provider,
}: any) {
    logger.info('--- DEPLOYING USER SMART ACCOUNT ---');

    // Get signers and threshold from SigningCoordinator
    const participants = await SigningCoordinatorAgent.getParticipants(ETH_PROVIDER, TACO_DOMAIN, COHORT_ID)
    const signers = participants.map(p => p.signerAddress as Address);

    const threshold = await SigningCoordinatorAgent.getThreshold(ETH_PROVIDER, TACO_DOMAIN, COHORT_ID);

    logger.info(`Got ${signers.length} signers from MultiSig contract with threshold ${threshold}`);
    logger.debug(`Signers: ${signers.join(', ')}`);

    const userSmartAccount = await toMetaMaskSmartAccount({
        client: publicClient,
        implementation: Implementation.MultiSig,
        deployParams: [signers, BigInt(threshold)],
        deploySalt: "0x" as Hex,
        signatory: [{
            account: localAccount
        }]
    });

    return userSmartAccount;
}

async function executeViaMultisig({
    provider,
    userSmartAccount,
    localAccount,
    bundlerClient,
    pimlicoClient,
    publicClient,
}: any) {
    logger.info('--- EXECUTING VIA MULTISIG ---');

    const recipientAddress = localAccount.address;
    const transferAmount = parseEther('0'); // 0 ETH for testing

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
        let nonce: number;
        if (isDeployed) {
            try {
                nonce = await publicClient.readContract({
                    address: userSmartAccount.address,
                    abi: [{
                        name: 'getNonce',
                        type: 'function',
                        stateMutability: 'view',
                        inputs: [],
                        outputs: [{ type: 'uint256' }]
                    }],
                    functionName: 'getNonce',
                });
            } catch (error) {
                logger.warn('Failed to read nonce from contract, defaulting to 0');
                nonce = 0;
            }
        } else {
            nonce = 0;
            logger.debug(`Using initCode: ${userSmartAccount.initCode}`);
        }
        logger.debug(`Using nonce: ${nonce}`);

        // Construct the user operation
        const userOperation = await bundlerClient!.prepareUserOperation({
            account: userSmartAccount,
            calls: [
                executionData,
              ],
            ...fee,
            verificationGasLimit: 500_000
        });

        // Get signatures from Porter for the execution UserOperation
        logger.debug(`Requesting signatures from TACo...`);
        const result = await signUserOp(
            ETH_PROVIDER,
            TACO_DOMAIN,
            COHORT_ID,
            BASE_SEPOLIA_CHAIN_ID,
            userOperation,
            'mdt',
        );
        logger.debug(`Message hash: ${result.messageHash}`);
        logger.debug(`Aggregated signature: ${result.aggregatedSignature}`);

        try {
            const userOperationHash = await bundlerClient!.sendUserOperation({
                ...userOperation,
                signature: result.aggregatedSignature,
            });
            logger.verbose(`Execution UserOp sent: ${userOperationHash}. Waiting for receipt...`);
            const { receipt } = await bundlerClient!.waitForUserOperationReceipt({ hash: userOperationHash });
            logger.info(`Execution completed, tx: ${receipt.transactionHash}`);

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
        const userSmartAccount = await deployAndSetupSmartAccount({
            ...env,
            provider: env.provider,
        });
        
        await logBalance('User Smart Account before transfer', env.provider, userSmartAccount.address);
        await logBalance(`Local EOA (${env.localAccount.address}) before transfer`, env.provider, env.localAccount.address);

        await executeViaMultisig({
            ...env,
            userSmartAccount,
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

