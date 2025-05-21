import { ethers } from 'ethers';
import { Address, Hex, concat, hashMessage, recoverAddress, toHex } from 'viem';
import * as dotenv from 'dotenv';
import winston, { Logger } from 'winston';
import { Buffer } from 'buffer';

dotenv.config();

// --- Constants ---
const SIGNATURE_LENGTH = 65;
const EIP1271_MAGIC_VALUE = "0x1626ba7e";

// --- Logger Setup ---
const logger: Logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    levels: { error: 0, warn: 1, info: 2, verbose: 3, debug: 4 },
    format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp(),
        winston.format.printf(({ level, message, timestamp }) => 
            `${timestamp} ${level}: [PorterSignerLib] ${message}`
        )
    ),
    transports: [new winston.transports.Console()]
});
winston.addColors({ error: 'red', warn: 'yellow', info: 'green', verbose: 'cyan', debug: 'gray' });

export async function getPorterChecksums(porterBaseUrl: string, quantity: number = 3): Promise<Address[]> {
    logger.verbose(`Fetching ${quantity} Ursula checksums from Porter at ${porterBaseUrl}...`);
    
    try {
        const response = await fetch(`${porterBaseUrl}/get_ursulas?quantity=${quantity}`);
        if (!response.ok) {
            const errorText = await response.text();
            logger.error(`Failed to fetch Ursulas: ${response.status} ${errorText}`);
            throw new Error(`Failed to fetch Ursulas: ${response.status} ${errorText}`);
        }
        const data = await response.json();
        if (!data.result?.ursulas) {
            logger.error('Invalid response structure from Porter /get_ursulas. Response:', data);
            throw new Error('Invalid response structure from Porter /get_ursulas');
        }

        const checksums = data.result.ursulas.map((ursula: any) => 
            ursula.checksum_address.toLowerCase() as Address
        );
        
        logger.verbose(`Retrieved ${checksums.length} Ursula nodes: ${checksums.join(',')}`);
        return checksums;
    } catch (error: any) {
        logger.error(`Error fetching Ursulas: ${error.message}`);
        throw error;
    }
}

export async function requestSignaturesFromPorter(
    porterBaseUrl: string,
    dataToSign: Hex,
    ursulaChecksums: Address[],
    porterThreshold: number,
    cohortId: number = 0,
    context: object = {}
): Promise<{ 
    signatures: { [checksumAddress: string]: [string, string] }; 
    claimedSigners: Address[]; 
    messageHash: string 
}> {
    logger.debug(`Requesting signatures from Ursulas: ${ursulaChecksums.join(', ')}`);

    const requestData = { data_to_sign: dataToSign, cohort_id: cohortId, context };
    const requestB64 = Buffer.from(JSON.stringify(requestData)).toString('base64');

    const signingRequests = ursulaChecksums.reduce((acc, checksum) => {
        if (checksum && typeof checksum === 'string') {
            acc[checksum] = requestB64;
        } else {
            logger.warn(`Skipping invalid Ursula address: ${checksum}`);
        }
        return acc;
    }, {} as { [key: string]: string });
    
    if (Object.keys(signingRequests).length < porterThreshold) {
        const errMsg = `Not enough valid Ursula checksums (${Object.keys(signingRequests).length}) for threshold (${porterThreshold})`;
        logger.error(errMsg);
        throw new Error(errMsg);
    }

    const requestBody = { signing_requests: signingRequests, threshold: porterThreshold };
    logger.debug(`Porter /sign request body: ${JSON.stringify(requestBody, null, 2)}`);

    const response = await fetch(`${porterBaseUrl}/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
        const errorText = await response.text();
        logger.error(`Porter /sign HTTP error: ${response.status} - ${errorText}`);
        throw new Error(`Porter /sign HTTP error: ${response.status} - ${errorText}`);
    }

    const result = await response.json();
    logger.debug(`Porter /sign response: ${JSON.stringify(result, null, 2)}`);

    if (!result.result?.signing_results?.signatures || Object.keys(result.result.signing_results.signatures).length === 0) {
        logger.error("No signatures in Porter response", result);
        throw new Error("No signatures in Porter response");
    }
    
    const receivedSignatures: { [checksumAddress: string]: [string, string] } = {};
    let messageHash: string | undefined;

    for (const [ursulaAddress, [signerAddress, signatureB64]] of Object.entries(result.result.signing_results.signatures) as [string, [string, string]][]) {
        const decodedData = JSON.parse(Buffer.from(signatureB64, 'base64').toString()) as { 
            message_hash: string; 
            signature: string 
        };
        
        if (!messageHash) {
            messageHash = decodedData.message_hash;
        } else if (messageHash !== decodedData.message_hash) {
            logger.warn(`Message hash mismatch for ${ursulaAddress}. Expected ${messageHash}, got ${decodedData.message_hash}`);
        }
        
        const formattedSignature = `0x${decodedData.signature}`;
        logger.debug(`Signature from ${ursulaAddress}: ${formattedSignature}`);
        
        receivedSignatures[ursulaAddress] = [signerAddress, formattedSignature];
    }

    if (!messageHash) {
        throw new Error("No message hash in Porter response");
    }

    const claimedSigners = Object.values(receivedSignatures)
        .map(([signerAddress]) => signerAddress.toLowerCase() as Address);
    
    logger.verbose(`Porter claimed signers: ${claimedSigners.join(',')}`);
    
    if (claimedSigners.length < porterThreshold) {
        const errMsg = `Insufficient signatures (${claimedSigners.length}) for threshold (${porterThreshold})`;
        logger.error(errMsg);
        throw new Error(errMsg);
    }

    logger.verbose(`Message hash: ${messageHash}`);
    return { signatures: receivedSignatures, claimedSigners, messageHash };
}

export function aggregatePorterSignatures(
    signaturesWithAddress: { [checksumAddress: string]: [string, string] }
): Hex {
    logger.debug('Aggregating Porter signatures...');
    
    const sortedSignaturePairs = Object.entries(signaturesWithAddress)
        .sort(([_, [addr1]], [__, [addr2]]) => 
            addr1.toLowerCase().localeCompare(addr2.toLowerCase())
        );

    const sortedSignatures = sortedSignaturePairs.map(([ursulaAddress, [signerAddress, signature]]) => {
        logger.debug(`Processing signature from ${ursulaAddress} (signer: ${signerAddress})`);
        return signature as Hex;
    });

    logger.debug(`Sorted signatures: ${JSON.stringify(sortedSignatures)}`);
    const combined = concat(sortedSignatures);
    logger.verbose(`Combined signature (${combined.length / 2 - 1} bytes): ${combined}`);
    return combined;
}

export async function verifySignaturesLocally(
    digestToVerify: Hex,
    combinedSignature: Hex,
    threshold: bigint,
    expectedSigners: readonly Address[]
): Promise<boolean> {
    logger.verbose(`Verifying signatures for digest: ${digestToVerify}`);
    const numSignaturesRequired = Number(threshold);

    if ((combinedSignature.length - 2) % (SIGNATURE_LENGTH * 2) !== 0) {
        logger.error(`Invalid signature length: ${combinedSignature.length}, expected multiple of ${SIGNATURE_LENGTH * 2}`);
        return false;
    }
    const actualNumSignatures = (combinedSignature.length - 2) / (SIGNATURE_LENGTH * 2);

    // Check 2: The number of signatures found must be at least the required threshold.
    if (actualNumSignatures < numSignaturesRequired) {
        logger.error(`Insufficient signatures: ${actualNumSignatures}, need ${numSignaturesRequired}`);
        return false;
    }

    let lastRecoveredSigner: Address = '0x0000000000000000000000000000000000000000';
    const lowerCaseExpectedSigners = expectedSigners.map(s => s.toLowerCase() as Address);
    const recoveredSigners = new Set<Address>();

    for (let i = 0; i < actualNumSignatures; i++) {
        const sigOffset = 2 + i * SIGNATURE_LENGTH * 2;
        const individualSignature = `0x${combinedSignature.substring(sigOffset, sigOffset + SIGNATURE_LENGTH * 2)}` as Hex;

        try {
            const recoveredAddress = await recoverAddress({ hash: digestToVerify, signature: individualSignature });
            const lowerCaseRecoveredAddress = recoveredAddress.toLowerCase() as Address;

            if (!lowerCaseExpectedSigners.includes(lowerCaseRecoveredAddress)) {
                logger.error(`Unexpected signer: ${lowerCaseRecoveredAddress}`);
                return false;
            }

            if (lowerCaseRecoveredAddress.localeCompare(lastRecoveredSigner) <= 0) {
                logger.error(`Invalid signer order: ${lowerCaseRecoveredAddress} after ${lastRecoveredSigner}`);
                return false;
            }
            
            if (recoveredSigners.has(lowerCaseRecoveredAddress)) {
                logger.error(`Duplicate signer: ${lowerCaseRecoveredAddress}`);
                return false;
            }

            recoveredSigners.add(lowerCaseRecoveredAddress);
            lastRecoveredSigner = lowerCaseRecoveredAddress;
            logger.debug(`Verified signature ${i + 1} from ${lowerCaseRecoveredAddress}`);
        } catch (e: any) {
            logger.error(`Signature recovery failed: ${e.message}`);
            return false;
        }
    }
    
    if (recoveredSigners.size < numSignaturesRequired) {
        logger.error(`Insufficient unique signers: ${recoveredSigners.size}, need ${numSignaturesRequired}`);
        return false;
    }

    logger.info("Local signature verification PASSED");
    return true;
}

export async function verifySignaturesOnChainViaEIP1271(
    provider: ethers.JsonRpcProvider,
    contractAddress: Address,
    hashToVerify: Hex,
    signature: Hex
): Promise<boolean> {
    logger.verbose(`Verifying EIP-1271 signature for contract ${contractAddress}`);
    
    const contractAbi = ["function isValidSignature(bytes32 _hash, bytes _signature) external view returns (bytes4)"];
    const contract = new ethers.Contract(contractAddress, contractAbi, provider);
    
    try {
        const result: string = await contract.isValidSignature(hashToVerify, signature);
        logger.debug(`Contract response: ${result}`);
        
        if (result.toLowerCase() === EIP1271_MAGIC_VALUE.toLowerCase()) {
            logger.info("On-chain EIP-1271 verification PASSED");
            return true;
        }
        
        logger.error(`Invalid magic value: expected ${EIP1271_MAGIC_VALUE}, got ${result}`);
        return false;
    } catch (error: any) {
        const revertReason = error.reason || (error.data ? ethers.toUtf8String(error.data) : null) || error.message;
        logger.error(`On-chain verification failed: ${revertReason}`, error);
        return false;
    }
} 