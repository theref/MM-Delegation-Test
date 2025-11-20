# MetaMask Delegation Toolkit MultiSig Demo

This project demonstrates the integration of MetaMask's Delegation Toolkit with a TACo EIP-1271 MultiSig contract, showcasing distributed signature collection and delegation management.

## Technical Architecture

### System Components

1. **Hybrid Smart Account (Delegator)**
   - Implements MetaMask's Delegation Toolkit
   - Acts as the source of authority
   - Can hold and transfer funds
   - Controlled through delegations
   - Uses TACo signers and threshold

2. **TACo Signer System**
   - Distributed network of Ursula nodes on `lynx` testnet
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

3. **TACo Signature Collection**
   - Fetches available Ursula nodes
   - Requests signatures from multiple nodes
   - Aggregates signatures based on threshold
   ```typescript
         const result = await signUserOp(
            ETH_PROVIDER,
            TACO_DOMAIN,
            COHORT_ID,
            BASE_SEPOLIA_CHAIN_ID,
            userOperation,
            'mdt',
        );
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

### TACo Signers
- Distributed signature collection system
- Manages TACo nodes for signing
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