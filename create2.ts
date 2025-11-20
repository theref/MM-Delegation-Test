import {
  Implementation,
  toMetaMaskSmartAccount,
} from "@metamask/delegation-toolkit";
import { ethers } from "ethers";
import { createPublicClient, Hex, http, Address } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { baseSepolia } from "viem/chains";
import {
  createBundlerClient,
  createPaymasterClient,
} from "viem/account-abstraction";
import * as dotenv from "dotenv";

dotenv.config();

const MULTISIG_ADDRESS =
  "0x42F30AEc1A36995eEFaf9536Eb62BD751F982D32" as Address;
const FACTORY_ADDRESS = "0x69Aa2f9fe1572F1B640E1bbc512f5c3a734fc77c" as Address;
const MULTISIG_ABI = [
  "function getSigners() view returns (address[])",
  "function threshold() view returns (uint16)",
];
const FACTORY_ABI = [
  {
    type: "function",
    name: "computeAddress",
    stateMutability: "view",
    inputs: [
      { name: "_bytecodeHash", type: "bytes32" },
      { name: "_salt", type: "bytes32" },
    ],
    outputs: [{ name: "addr_", type: "address" }],
  },
] as const;

const SALTS = [
  "0x0000000000000000000000000000000000000000000000000000000000000000",
  "0x0000000000000000000000000000000000000000000000000000000000000001",
  "0x0000000000000000000000000000000000000000000000000000000000000002",
] as Hex[];

interface VerifyResult {
  salt: Hex;
  sdkAddress: Address;
  factoryAddress: Address;
  match: boolean;
}

async function verifyAddress(
  salt: Hex,
  signers: string[],
  threshold: bigint,
  bytecodeHash: Hex,
  publicClient: any,
  localAccount: any
): Promise<VerifyResult> {
  const account = await toMetaMaskSmartAccount({
    client: publicClient,
    implementation: Implementation.MultiSig,
    deployParams: [signers as any, threshold],
    deploySalt: salt,
    signatory: [{ account: localAccount }],
  });

  const factoryAddress = await publicClient.readContract({
    address: FACTORY_ADDRESS,
    abi: FACTORY_ABI,
    functionName: "computeAddress",
    args: [bytecodeHash, salt],
  });

  return {
    salt,
    sdkAddress: account.address,
    factoryAddress,
    match: account.address.toLowerCase() === factoryAddress.toLowerCase(),
  };
}

async function main() {
  const provider = new ethers.providers.JsonRpcProvider(process.env.RPC_URL!);
  const publicClient = createPublicClient({
    chain: baseSepolia,
    transport: http(process.env.RPC_URL),
  });
  const localAccount = privateKeyToAccount(
    process.env.PRIVATE_KEY as `0x${string}`
  );

  const multisigContract = new ethers.Contract(
    MULTISIG_ADDRESS,
    MULTISIG_ABI,
    provider
  );
  const signers = await multisigContract.getSigners();
  const threshold = await multisigContract.threshold();

  console.log("Configuration:");
  console.log(`  Multisig: ${MULTISIG_ADDRESS}`);
  console.log(`  Factory: ${FACTORY_ADDRESS}`);
  console.log(`  Signers: ${signers.length}`);
  console.log(`  Threshold: ${threshold}\n`);

  const tempSalt =
    "0x0000000000000000000000000000000000000000000000000000000000000999" as Hex;
  const tempAccount = await toMetaMaskSmartAccount({
    client: publicClient,
    implementation: Implementation.MultiSig,
    deployParams: [signers as any, threshold],
    deploySalt: tempSalt,
    signatory: [{ account: localAccount }],
  });

  const paymasterClient = createPaymasterClient({
    transport: http(process.env.BUNDLER_URL),
  });
  const bundlerClient = createBundlerClient({
    transport: http(process.env.BUNDLER_URL),
    paymaster: paymasterClient,
    chain: baseSepolia,
  });
  const { createPimlicoClient } = await import(
    "permissionless/clients/pimlico"
  );
  const pimlicoClient = createPimlicoClient({
    transport: http(process.env.BUNDLER_URL),
  });
  const { fast: fees } = await pimlicoClient.getUserOperationGasPrice();

  const tempUserOp = await bundlerClient.prepareUserOperation({
    account: tempAccount,
    calls: [{ target: localAccount.address, value: 0n, data: "0x" }],
    ...fees,
  });

  if (!tempUserOp.factoryData) throw new Error("Could not get factory data");

  const iface = new ethers.utils.Interface(["function deploy(bytes,bytes32)"]);
  const [bytecode] = iface.decodeFunctionData("deploy", tempUserOp.factoryData);
  const bytecodeHash = ethers.utils.keccak256(bytecode as string) as Hex;

  console.log(`Bytecode Hash: ${bytecodeHash}\n`);
  console.log("Verifying addresses...\n");

  const results: VerifyResult[] = [];
  for (const salt of SALTS) {
    const result = await verifyAddress(
      salt,
      signers,
      threshold,
      bytecodeHash,
      publicClient,
      localAccount
    );
    results.push(result);
  }

  for (const result of results) {
    console.log(`Salt: ${result.salt}`);
    console.log(`  SDK:     ${result.sdkAddress}`);
    console.log(`  Factory: ${result.factoryAddress}`);
    console.log(`  ${result.match ? "MATCH" : "❌ MISMATCH"}\n`);
  }

  const allMatch = results.every((r) => r.match);
  if (allMatch) {
    console.log("All addresses match!\n");
    console.log("TACo Condition Parameters:");
    console.log(`  Contract: ${FACTORY_ADDRESS}`);
    console.log(`  Function: computeAddress(bytes32,bytes32)`);
    console.log(`  Param 1 (bytecodeHash): ${bytecodeHash}`);
  } else {
    console.log("❌ Some addresses do not match!");
  }
}

main().catch(console.error);
// > ts-node create2.ts

// Configuration:
//   Multisig: 0x42F30AEc1A36995eEFaf9536Eb62BD751F982D32
//   Factory: 0x69Aa2f9fe1572F1B640E1bbc512f5c3a734fc77c
//   Signers: 3
//   Threshold: 2

// Bytecode Hash: 0x9a8bb655e7dad888fdd42ff207691435e25810e1407db5527bffd58f374a2684

// Verifying addresses...

// Salt: 0x0000000000000000000000000000000000000000000000000000000000000000
//   SDK:     0xBF151420A84A6Bb7b1213d8269a5F1fe43FC3276
//   Factory: 0xBF151420A84A6Bb7b1213d8269a5F1fe43FC3276
//   MATCH

// Salt: 0x0000000000000000000000000000000000000000000000000000000000000001
//   SDK:     0x3A4F7eee50c19e8F288Bdd8e9D202e98Cfe4821d
//   Factory: 0x3A4F7eee50c19e8F288Bdd8e9D202e98Cfe4821d
//   MATCH

// Salt: 0x0000000000000000000000000000000000000000000000000000000000000002
//   SDK:     0x819138e5EDC37CA684Da5a7faf6e0Aaa80b16141
//   Factory: 0x819138e5EDC37CA684Da5a7faf6e0Aaa80b16141
//   MATCH

// All addresses match!

// TACo Condition Parameters:
//   Contract: 0x69Aa2f9fe1572F1B640E1bbc512f5c3a734fc77c
//   Function: computeAddress(bytes32,bytes32)
//   Param 1 (bytecodeHash): 0x9a8bb655e7dad888fdd42ff207691435e25810e1407db5527bffd58f374a2684
