import { ethers } from 'ethers';
import { Address, Hex, concat, hashMessage, recoverAddress, toHex } from 'viem';
import * as dotenv from 'dotenv';
import winston, { Logger } from 'winston';
import { Buffer } from 'buffer';

dotenv.config();

// --- Constants ---
export const SIGNATURE_LENGTH = 65;
export const EIP1271_MAGIC_VALUE = "0x1626ba7e";

// --- Logger Setup ---
// Logger configuration can be made more flexible (e.g., passed in) if needed.
const logger: Logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info', // Default to 'info', can be overridden by .env
    levels: { error: 0, warn: 1, info: 2, verbose: 3, debug: 4 },
    format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp(),
        winston.format.printf((info) => `${info.timestamp} ${info.level}: [PorterSignerLib] ${info.message}`)
    ),
    transports: [new winston.transports.Console()]
});
winston.addColors({ error: 'red', warn: 'yellow', info: 'green', verbose: 'cyan', debug: 'gray' });

// --- Library Functions ---

/**
 * Fetches Ursula checksums from Porter.
 * @param porterBaseUrl The base URL for the Porter service.
 * @param quantity Optional number of Ursulas to fetch. Defaults to 3.
 * @returns A promise that resolves to an array of Ursula checksum addresses.
 */
export async function getPorterChecksums(porterBaseUrl: string, quantity: number = 3): Promise<Address[]> {
    logger.info(`Fetching ${quantity} Ursula checksums from Porter at ${porterBaseUrl}...`);
    try {
        const response = await fetch(`${porterBaseUrl}/get_ursulas?quantity=${quantity}`);
        if (!response.ok) {
            const errorText = await response.text();
            logger.error(`Failed to fetch Ursulas: ${response.status} ${errorText}`);
            throw new Error(`Failed to fetch Ursulas: ${response.status} ${errorText}`);
        }
        const data = await response.json();
        if (!data.result || !data.result.ursulas) {
            logger.error('Invalid response structure from Porter /get_ursulas. Response:', data);
            throw new Error('Invalid response structure from Porter /get_ursulas');
        }
        const checksums = data.result.ursulas.map((ursula: any) => ursula.checksum_address.toLowerCase() as Address);
        logger.info(`Retrieved ${checksums.length} Ursula nodes from Porter: ${checksums.join(',')}`);
        return checksums;
    } catch (error: any) {
        logger.error(`Error fetching Ursulas from Porter: ${error.message}`);
        throw error;
    }
}

/**
 * Requests signatures from Porter for a given piece of data.
 * @param porterBaseUrl The base URL for the Porter service.
 * @param dataToSign The hex string of the data to be signed by Porter.
 * @param ursulaChecksums An array of Ursula checksum addresses to request signatures from.
 * @param porterThreshold The number of signatures required from Porter.
 * @param cohortId The cohort ID for the signing request.
 * @param context Optional context object for the signing request.
 * @returns A promise that resolves to an object containing the signatures and claimed signer addresses.
 */
export async function requestSignaturesFromPorter(
    porterBaseUrl: string,
    dataToSign: Hex,
    ursulaChecksums: Address[],
    porterThreshold: number,
    cohortId: number = 0,
    context: object = {}
): Promise<{ signatures: { [checksumAddress: string]: [string, string] }; claimedSigners: Address[] }> {
    logger.debug(`Ursulas for request: ${ursulaChecksums.join(', ')}`);

    const requestData = { data_to_sign: dataToSign, cohort_id: cohortId, context: context };
    const requestB64 = Buffer.from(JSON.stringify(requestData)).toString('base64');

    const signingRequests: { [key: string]: string } = {};
    // Ensure we only request from available Ursulas, up to the number available if less than threshold
    // Or, if more Ursulas are available than threshold, it's usually fine to send to all of them,
    // as Porter will manage the threshold. For this version, let's send to all provided checksums.
    ursulaChecksums.forEach(checksum => {
        if (checksum && typeof checksum === 'string') {
            signingRequests[checksum] = requestB64;
        } else {
            logger.warn(`Skipping invalid Ursula address for signing request: ${checksum}`);
        }
    });
    
    if (Object.keys(signingRequests).length < porterThreshold) {
        const errMsg = `Not enough valid Ursula checksums (${Object.keys(signingRequests).length}) provided to meet Porter threshold (${porterThreshold}).`;
        logger.error(errMsg);
        throw new Error(errMsg);
    }

    const requestBody = { signing_requests: signingRequests, threshold: porterThreshold };
    logger.debug(`Request body for Porter /sign: ${JSON.stringify(requestBody, null, 2)}`);

    const response = await fetch(`${porterBaseUrl}/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
        const errorText = await response.text();
        logger.error(`Porter /sign HTTP error! Status: ${response.status}, Details: ${errorText}`);
        throw new Error(`Porter /sign HTTP error! Status: ${response.status}, Details: ${errorText}`);
    }

    const result = await response.json();
    logger.debug(`Response data from Porter /sign: ${JSON.stringify(result, null, 2)}`);

    if (!result.result?.signing_results?.signatures || Object.keys(result.result.signing_results.signatures).length === 0) {
        logger.error("No signatures found in Porter response or invalid format.", result);
        throw new Error("No signatures found in Porter response or invalid format.");
    }
    
    const receivedSignatures: { [checksumAddress: string]: [string, string] } = result.result.signing_results.signatures;
    const claimedSigners = Object.values(receivedSignatures)
        .map((sigInfo: [string, string]) => sigInfo[0].toLowerCase() as Address);
    logger.info(`Porter claimed signers for this operation: ${claimedSigners.join(',')}`);
    
    if (claimedSigners.length < porterThreshold) {
        const errMsg = `Porter returned fewer signatures (${claimedSigners.length}) than the required threshold (${porterThreshold}).`;
        logger.error(errMsg);
        // Potentially still return what was received, but log an error. Or throw, depending on desired strictness.
        // For now, let's throw if the threshold isn't met by the *returned* signatures.
        throw new Error(errMsg);
    }

    return { signatures: receivedSignatures, claimedSigners };
}

/**
 * Aggregates signatures received from Porter into a single combined hex string.
 * Signatures are sorted by the signer's address before concatenation.
 * @param signaturesWithAddress An object where keys are Ursula checksums and values are [signer_address, base64_signature] tuples.
 * @returns The combined signature as a hex string.
 */
export function aggregatePorterSignatures(
    signaturesWithAddress: { [checksumAddress: string]: [string, string] }
): Hex {
    logger.debug('Aggregating Porter signatures...');
    const sortedSignaturePairs = Object.entries(signaturesWithAddress)
        .sort(([_, [addr1]], [__, [addr2]]) => // Sort by the *signer address* returned by Porter
            addr1.toLowerCase().localeCompare(addr2.toLowerCase())
        );

    const sortedHexSignatures = sortedSignaturePairs.map(([ursulaAddress, [signerAddress, signatureB64]]) => {
        logger.debug(`Processing signature from Ursula ${ursulaAddress} (signer: ${signerAddress})`);
        const signatureBuffer = Buffer.from(signatureB64, 'base64');
        if (signatureBuffer.length !== SIGNATURE_LENGTH) {
            logger.error(`Invalid signature length for signer ${signerAddress}. Expected ${SIGNATURE_LENGTH}, got ${signatureBuffer.length}`);
            throw new Error(`Invalid signature length for signer ${signerAddress}. Expected ${SIGNATURE_LENGTH}, got ${signatureBuffer.length}`);
        }
        return ('0x' + signatureBuffer.toString('hex')) as Hex;
    });

    logger.debug(`Sorted hex signatures for aggregation: ${JSON.stringify(sortedHexSignatures)}`);
    const combined = concat(sortedHexSignatures);
    logger.info(`Combined signature (${combined.length / 2 -1} bytes): ${combined}`); // length includes '0x'
    return combined;
}

/**
 * Verifies a combined signature locally against a digest and a list of expected signers.
 * @param digestToVerify The hash/digest that was signed.
 * @param combinedSignature The aggregated signature string.
 * @param threshold The minimum number of valid signatures required.
 * @param expectedSigners An array of addresses that are expected to have signed.
 * @returns A promise that resolves to true if verification is successful, false otherwise.
 */
export async function verifySignaturesLocally(
    digestToVerify: Hex,
    combinedSignature: Hex,
    threshold: bigint,
    expectedSigners: readonly Address[]
): Promise<boolean> {
    logger.info(`Attempting local verification for digest: ${digestToVerify}`);
    const numSignaturesRequired = Number(threshold);

    // Check 1: Combined signature must have a total length that's a multiple of individual signature lengths.
    if ((combinedSignature.length - 2) % (SIGNATURE_LENGTH * 2) !== 0) {
        logger.error(`Local verify fail: Invalid combined sig length. Got ${combinedSignature.length}, expected multiple of ${SIGNATURE_LENGTH * 2}.`);
        return false;
    }
    const actualNumSignatures = (combinedSignature.length - 2) / (SIGNATURE_LENGTH * 2);

    // Check 2: The number of signatures found must be at least the required threshold.
    // Note: The combinedSignature might contain more signatures than the threshold if Porter returned more.
    // We only need to verify `numSignaturesRequired` of them.
    if (actualNumSignatures < numSignaturesRequired) {
        logger.error(`Local verify fail: Not enough sigs in combined sig. Found ${actualNumSignatures}, need at least ${numSignaturesRequired}.`);
        return false;
    }

    let lastRecoveredSigner: Address = '0x0000000000000000000000000000000000000000'; // zeroAddress
    const lowerCaseExpectedSigners = expectedSigners.map(s => s.toLowerCase() as Address);
    const recoveredSignersInThisSet = new Set<Address>();

    // We iterate through the signatures in the combinedSignature.
    // Since aggregatePorterSignatures sorts them by signer address, these checks should pass.
    for (let i = 0; i < actualNumSignatures; i++) { // Iterate over all actual signatures
        const sigOffset = 2 + i * SIGNATURE_LENGTH * 2;
        const individualSignature = `0x${combinedSignature.substring(sigOffset, sigOffset + SIGNATURE_LENGTH * 2)}` as Hex;

        try {
            const recoveredAddress = await recoverAddress({ hash: digestToVerify, signature: individualSignature });
            const lowerCaseRecoveredAddress = recoveredAddress.toLowerCase() as Address;

            // Check 3: Recovered signer must be in the expected list (Porter claimed signers).
            if (!lowerCaseExpectedSigners.includes(lowerCaseRecoveredAddress)) {
                logger.error(`Local verify fail: Recovered signer ${lowerCaseRecoveredAddress} not in expected list: [${lowerCaseExpectedSigners.join(',')}]`);
                // If any signature is from an unexpected signer, this is a problem.
                return false;
            }

            // Check 4: Signers must be in strictly ascending order.
            if (lowerCaseRecoveredAddress.localeCompare(lastRecoveredSigner) <= 0) {
                logger.error(`Local verify fail: Signer order invalid. Current ${lowerCaseRecoveredAddress}, previous ${lastRecoveredSigner}.`);
                return false;
            }
            
            // Check 5: No duplicate signers in the set being verified.
            if (recoveredSignersInThisSet.has(lowerCaseRecoveredAddress)) {
                logger.error(`Local verify fail: Duplicate signer ${lowerCaseRecoveredAddress} found.`);
                return false;
            }

            recoveredSignersInThisSet.add(lowerCaseRecoveredAddress);
            lastRecoveredSigner = lowerCaseRecoveredAddress;
            logger.debug(`Locally verified signature ${i + 1} from ${lowerCaseRecoveredAddress}`);
        } catch (e: any) {
            logger.error(`Local verify fail: Error during sig recovery for ${individualSignature}. Error: ${e.message}`);
            return false;
        }
    }
    
    // After verifying all individual signatures in the combined set,
    // ensure that the count of unique, valid, ordered signers meets the threshold.
    if (recoveredSignersInThisSet.size < numSignaturesRequired) {
        logger.error(`Local verify fail: Number of unique valid signers (${recoveredSignersInThisSet.size}) is less than threshold (${numSignaturesRequired}).`);
        return false;
    }

    logger.info("SUCCESS: Local signature verification PASSED.");
    return true;
}

/**
 * Verifies a signature on-chain using EIP-1271.
 * @param provider An ethers.js JsonRpcProvider.
 * @param contractAddress The address of the smart contract implementing EIP-1271.
 * @param hashToVerify The hash/digest that was signed.
 * @param signature The combined signature string.
 * @returns A promise that resolves to true if on-chain verification is successful, false otherwise.
 */
export async function verifySignaturesOnChainViaEIP1271(
    provider: ethers.JsonRpcProvider,
    contractAddress: Address,
    hashToVerify: Hex,
    signature: Hex
): Promise<boolean> {
    logger.info(`Attempting on-chain EIP-1271 verification for contract ${contractAddress}, hash ${hashToVerify}`);
    const contractAbi = ["function isValidSignature(bytes32 _hash, bytes _signature) external view returns (bytes4)"];
    const contract = new ethers.Contract(contractAddress, contractAbi, provider);
    try {
        const result: string = await contract.isValidSignature(hashToVerify, signature);
        logger.debug(`On-chain isValidSignature for ${contractAddress} returned: ${result}`);
        if (result.toLowerCase() === EIP1271_MAGIC_VALUE.toLowerCase()) {
            logger.info("SUCCESS: On-chain EIP-1271 verification PASSED.");
            return true;
        } else {
            logger.error(`FAILURE: On-chain EIP-1271 verification FAILED for ${contractAddress}. Expected ${EIP1271_MAGIC_VALUE}, got ${result}.`);
            return false;
        }
    } catch (error: any) {
        // Log the full error if available, especially for contract reverts
        const revertReason = error.reason || (error.data ? ethers.toUtf8String(error.data) : null) || error.message;
        logger.error(`ERROR during on-chain verification for ${contractAddress} (hash: ${hashToVerify}): ${revertReason}`, error);
        return false;
    }
} 