# MetaMask Delegation Toolkit MultiSig Demo

This project demonstrates the integration of MetaMask's Delegation Toolkit with a TACo EIP-1271 MultiSig contract, showcasing distributed signature collection and delegation management.

## Technical Architecture

### System Components

1. **Hybrid Smart Account (Delegator)**
   - Implements MetaMask's Delegation Toolkit
   - Acts as the source of authority
   - Can hold and transfer funds
   - Controlled through delegations

2. **TACo EIP-1271 MultiSig (Delegatee)**
   - Implements EIP-1271 for signature verification
   - Requires threshold number of signatures
   - Authorizes actions on behalf of the delegator
   - Contract address: `0x42F30AEc1A36995eEFaf9536Eb62BD751F982D32`

3. **Delegation Manager**
   - Handles delegation creation and redemption
   - Manages execution of delegated actions
   - Contract address: `0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3`

4. **TACo Signer System**
   - Distributed network of Ursula nodes
   - Provides threshold-based signatures
   - Implements secure signature aggregation

### Detailed Flow

1. **Initialization and Setup**
   ```typescript
   // Environment setup
   const environment = getDeleGatorEnvironment(BASE_SEPOLIA_CHAIN_ID);
   const publicClient = createPublicClient({ chain: baseSepolia, ... });
   const bundlerClient = createBundlerClient({ ... });
   ```

2. **Smart Account Deployment**
   - Creates a Hybrid smart account
   - Deploys if not already deployed
   - Sets up initial configuration
   ```typescript
   const userSmartAccount = await toMetaMaskSmartAccount({
       implementation: Implementation.Hybrid,
       deployParams: [localAccount.address, [], [], []],
       ...
   });
   ```

3. **Delegation Creation**
   - Creates delegation from smart account to MultiSig
   - Signs delegation with smart account
   - Stores signed delegation for later use
   ```typescript
   const delegation = createDelegation({
       to: MULTISIG_ADDRESS,
       from: userSmartAccount.address,
       caveats: []
   });
   const signature = await userSmartAccount.signDelegation({ delegation });
   ```

4. **TACo Signature Collection**
   - Fetches available Ursula nodes
   - Requests signatures from multiple nodes
   - Aggregates signatures based on threshold
   ```typescript
   const { signatures, claimedSigners } = await requestSignaturesFromPorter(
       PORTER_BASE_URL,
       encodedData,
       porterChecksums,
       MULTISIG_CONTRACT_THRESHOLD
   );
   ```

5. **Signature Verification**
   - Verifies signatures locally
   - Performs on-chain EIP-1271 verification
   - Ensures threshold requirements are met
   ```typescript
   const isSignatureValid = await verifySignaturesOnChainViaEIP1271(
       provider,
       MULTISIG_ADDRESS,
       messageHash,
       combinedSignature
   );
   ```

6. **Delegation Redemption**
   - Creates redemption execution
   - Collects required signatures
   - Executes through MultiSig
   - Transfers funds back to EOA
   ```typescript
   const redemptionCalldata = DelegationFramework.encode.redeemDelegations({
       delegations: [[signedDelegation]],
       modes: [SINGLE_DEFAULT_MODE],
       executions: [[innerExecution]]
   });
   ```



## Prerequisites

- Node.js (v16 or higher)
- A Base Sepolia RPC URL
- A private key with test ETH on Base Sepolia
- A bundler URL (for Pimlico client)

## Configuration

Create a `.env` file with:
```env
RPC_URL=<your-base-sepolia-rpc-url>
PRIVATE_KEY=<your-private-key>
BUNDLER_URL=<your-bundler-url>
```

## Key Components

### Smart Account
- Hybrid implementation of MetaMask's Delegation Toolkit
- Acts as the delegator in the system
- Can be funded and controlled through delegations

### MultiSig Contract
- TACo EIP-1271 implementation
- Requires threshold number of signatures
- Authorizes delegation redemptions

### TACo Signer
- Distributed signature collection system
- Manages Ursula nodes for signing
- Aggregates and verifies signatures

## Running the Demo

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Run with Different Log Levels**
   ```bash
   # Basic information
   node index.ts --info

   # Detailed logging
   node index.ts --verbose

   # Full debugging information
   node index.ts --debug
   ```

## Resources

- [Base Sepolia Explorer](https://sepolia.basescan.org)
- [MetaMask Delegation Toolkit Documentation](https://docs.metamask.io/guide/delegation-toolkit)
- [EIP-1271 Specification](https://eips.ethereum.org/EIPS/eip-1271)

## License

MIT 