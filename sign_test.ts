import { ethers } from 'ethers';
import { Address, Hex, hashMessage, toHex } from 'viem';
import * as dotenv from 'dotenv';
import winston, { Logger } from 'winston';
// Import functions from the new library
import {
    getPorterChecksums,
    requestSignaturesFromPorter,
    aggregatePorterSignatures,
    verifySignaturesLocally,
    verifySignaturesOnChainViaEIP1271,
    // SIGNATURE_LENGTH, // Already used by library, not directly needed here unless for specific checks
    // EIP1271_MAGIC_VALUE // Same as above
} from './porter_signer'; // Assuming porter_signer.ts is in the same directory

dotenv.config();

// --- Constants ---
const RPC_URL = process.env.RPC_URL;
const MULTISIG_CONTRACT_ADDRESS = process.env.MULTISIG_CONTRACT_ADDRESS || "0x152aB00413e78be27D86061448B145d98ff7F22d";
const PORTER_BASE_URL = process.env.PORTER_BASE_URL || "https://porter-lynx.nucypher.io";
const CONTRACT_THRESHOLD = BigInt(process.env.CONTRACT_THRESHOLD || 2);
// SIGNATURE_LENGTH is now imported or implicitly handled by library functions

// --- Logger Setup ---
const logger: Logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'debug', // Ensure sign_test can also have its own log level
    levels: { error: 0, warn: 1, info: 2, verbose: 3, debug: 4 },
    format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp(),
        winston.format.printf((info) => `${info.timestamp} ${info.level}: [SignTest] ${info.message}`)
    ),
    transports: [new winston.transports.Console()]
});
winston.addColors({ error: 'red', warn: 'yellow', info: 'green', verbose: 'cyan', debug: 'gray' });

// --- Helper Functions (Originals removed as they are now in porter_signer.ts) ---
// getPorterChecksums - REMOVED (use library)
// aggregatePorterSignatures - REMOVED (use library)
// localVerifySignatures - REMOVED (use library)
// verifyOnChain - REMOVED (use library)

// --- Main Test Logic ---
async function main() {
    if (!RPC_URL) {
        logger.error("RPC_URL is not set in .env file.");
        process.exit(1);
    }
    if (!MULTISIG_CONTRACT_ADDRESS) {
        logger.error("MULTISIG_CONTRACT_ADDRESS is not set in .env file or as a default.");
        process.exit(1);
    }
    if (!PORTER_BASE_URL) {
        logger.error("PORTER_BASE_URL is not set in .env file or as a default.");
        process.exit(1);
    }

    const provider = new ethers.JsonRpcProvider(RPC_URL);
    
    const originalMessageString = "test_data";
    const messageAsHex = toHex(originalMessageString);
    logger.info(`Original message string: "${originalMessageString}"`);
    logger.info(`Message as hex (to be sent in data_to_sign): ${messageAsHex}`);

    // This is the digest that our EIP-1271 contract and local recovery will expect.
    // Porter signs the raw messageAsHex, but the EIP-191 prefix is applied *before* hashing for verification.
    const digestToVerify = hashMessage(originalMessageString);
    logger.info(`Digest for verification (hashMessage("${originalMessageString}")): ${digestToVerify}`);

    try {
        // Use library function
        const ursulaChecksums = await getPorterChecksums(PORTER_BASE_URL, 3); 
        if (ursulaChecksums.length < Number(CONTRACT_THRESHOLD)) {
            logger.error(`Not enough Ursulas (${ursulaChecksums.length}) to meet threshold (${CONTRACT_THRESHOLD}). Halting.`);
            return;
        }

        // Use library function
        const { signatures: porterSignatures, claimedSigners: porterClaimedSigners } = await requestSignaturesFromPorter(
            PORTER_BASE_URL,
            messageAsHex, // Send the raw hex data to Porter
            ursulaChecksums,
            Number(CONTRACT_THRESHOLD)
            // cohortId and context can be omitted if defaults (0 and {}) are fine
        );
        logger.info(`Porter claimed signers for this operation: ${porterClaimedSigners.join(',')}`);

        // Use library function
        const combinedSignature = aggregatePorterSignatures(porterSignatures);

        // Use library function (verifySignaturesLocally)
        const localVerificationSuccess = await verifySignaturesLocally(
            digestToVerify, // Verify against the EIP-191 prefixed hash
            combinedSignature,
            CONTRACT_THRESHOLD,
            porterClaimedSigners // Verify against the signers Porter claimed made these exact signatures
        );
        logger.info(`Local Verification Result: ${localVerificationSuccess ? 'PASSED' : 'FAILED'}`);

        if (localVerificationSuccess) {
            // Use library function (verifySignaturesOnChainViaEIP1271)
            const onChainVerificationSuccess = await verifySignaturesOnChainViaEIP1271(
                provider,
                MULTISIG_CONTRACT_ADDRESS as Address,
                digestToVerify, // Verify against the EIP-191 prefixed hash
                combinedSignature
            );
            logger.info(`On-chain Verification Result: ${onChainVerificationSuccess ? 'PASSED' : 'FAILED'}`);
        } else {
            logger.warn("Skipping on-chain verification because local verification failed.");
        }
    } catch (error: any) {
        // Adding more context to the error log
        logger.error(`Sign test failed: ${error.message}`, { stack: error.stack });
    }
}

main().catch(error => {
    logger.error("Unhandled error in main execution:", { message: error.message, stack: error.stack });
    process.exit(1);
});
