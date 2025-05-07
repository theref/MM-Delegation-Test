# MetaMask Delegation Multisig Test

This project demonstrates how to use the MetaMask Delegation Toolkit to:
- Set up a delegator smart account (Hybrid implementation)
- Set up a delegatee multisig smart account (MultiSig implementation)
- Create and sign a delegation from the delegator to the delegatee
- Redeem the delegation
- Fund the delegator smart account
- Use the delegatee (multisig) to send ETH from the delegator back to a local wallet

## Prerequisites
- Node.js (v18 or later recommended)
- An Ethereum Sepolia RPC URL
- A funded Sepolia private key for the local wallet

## Setup
1. **Clone the repository**
2. **Install dependencies:**
   ```bash
   npm install
   ```
3. **Create a `.env` file** in the project root with the following variables:
   ```env
   RPC_URL=YOUR_SEPOLIA_RPC_URL
   PRIVATE_KEY=YOUR_FUNDED_SEPOLIA_PRIVATE_KEY
   BUNDLER_URL=YOUR_PIMLICO_BUNDLER_URL
   ```

## Running the Script

```bash
npm run build
npm run start
```

The script will:
- Set up the accounts and delegation
- Redeem the delegation
- Fund the delegator smart account
- Use the multisig to send ETH back to the local wallet

## Notes
- This is a test/demo for MetaMask's Delegation Toolkit and multisig flows on Sepolia.
- All addresses and keys are for testnet use only.
- Make sure your local wallet is funded with Sepolia ETH for gas and funding operations.

## License
MIT 