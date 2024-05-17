# COTI V2 Confidential Smart Contracts | SDKs and Examples

All repositories specified below contain smart contracts that implement confidentiality features using the COTI V2 protocol.
The contracts provide examples for various use cases, such as Non-Fungible Tokens (NFTs), ERC20 tokens, Auction, and Identity management.

These contracts demonstrate how to leverage the confidentiality features of the COTI V2 protocol to enhance privacy and security in decentralized applications.
The contracts are of Solidity and can be compiled and deployed using popular development tools like Hardhat and Foundry (Work in progress).

#### Important Links:

[Docs](https://docs.coti.io) | [Devnet Explorer](https://explorer-devnet.coti.io) | [Faucet](https://faucet.coti.io)

Interact with the contract using any of the following:

1. [Python SDK](https://github.com/coti-io/coti-sdk-python)
2. [Typescript SDK](https://github.com/coti-io/coti-sdk-typescript) | [Typescript SDK Examples](https://github.com/coti-io/coti-sdk-typescript-examples)
3. [Hardhat Dev Environment](https://github.com/coti-io/confidentiality-contracts)

The following contracts are available in each of the packages:

| Contract                       |            | python sdk  | hardhat sdk | typescript sdk | Contract Description                                                                                                                          |
|--------------------------------|------------|-------------|-------------|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| `AccountOnboard`               | deployment | ✅ *        | ✅           | ❌              | Onboard a EOA account - During onboard network creates AES unique for that EOA which is used for decrypting values sent back from the network |
| `AccountOnboard`               | execution  | ✅          | ✅           | ✅              | "                                                                                                                                             |
| `ERC20Example`                 | deployment | ✅          | ✅           | ❌              | Confidential ERC20 - deploy and transfer encrypted amount of funds                                                                            |
| `ERC20Example`                 | execution  | ✅          | ✅           | ✅              | "                                                                                                                                             |
| `NFTExample`                   | deployment | ❌          | ✅           | ❌              | Confidential NFT example - saving encrypted data                                                                                              |
| `NFTExample`                   | execution  | ❌          | ✅           | ❌              | "                                                                                                                                             |
| `ConfidentialAuction`          | deployment | ❌          | ✅           | ❌              | Confidential auction - encrypted bid amount                                                                                                   |
| `ConfidentialAuction`          | execution  | ❌          | ✅           | ❌              | "                                                                                                                                             |
| `ConfidentialIdentityRegistry` | deployment | ❌          | ✅           | ❌              | Confidential Identity Registry - Encrypted identity data                                                                                      |
| `ConfidentialIdentityRegistry` | execution  | ❌          | ✅           | ❌              | "                                                                                                                                             |
| `DataOnChain`                  | deployment | ✅          | ❌           | ❌              | Basic encryption and decryption - Good place to start explorining network capabilties                                                         |
| `DataOnChain`                  | execution  | ✅          | ❌           | ✅              | "                                                                                                                                             |
| `Precompile`                   | deployment | ✅          | ✅           | ❌              | Thorough examples of the precompile functionality                                                                                             |
| `Precompile`                   | execution  | ✅          | ✅           | ❌              | "                                                                                                                                             |-              |              

(*) no deployment needed (system contract)

> [!NOTE]  
> Due to the nature of ongoing development, future version might break existing functionality

### Faucet

🤖 To request devnet/testnet funds use our [faucet](https://faucet.coti.io)

# Hardhat ([confidential-contracts](https://github.com/coti-io/confidentiality-contracts))

The `confidential-contracts` project is comprised of three main components:

1. **Reference libraries** (located in `contracts/lib`): containts the `MpcCore` and `MpcInterface` libraries referenced by all other SDKs. These libraries contain instructions for methods which the gcEVM handles as bytecode. For a full description of the libraries visit the [libraries readme](contracts/lib/lib_readme.md).

2. **gcEVM Precompiles** (located in `contracts/examples/precompiles`): These are a set of examples that make use of the reference libraries mentioned above. For a full description of these precompiles visit the [precompiles readme](contracts/examples/precompiles/precompiles_readme.md).

3. **Example contracts** (located in `contracts/examples`): the examples folder contain Solidity contracts that perform various use cases, such as Non-Fungible Tokens (NFTs), ERC20 tokens, Auction, and Identity management. It contains smart contracts that implement confidentiality features using the COTI V2 protocol.

The following example contracts are available for Hardhat Runtime Environment for deployment and execution:

| Contract                     | Contract Description                                                                                                                          |
|------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| AccountOnboard               | Onboard a EOA account - During onboard network creates AES unique for that EOA which is used for decrypting values sent back from the network |
| ERC20Example                 | Confidential ERC20 - deploy and transfer encrypted amount of funds                                                                            |
| NFTExample                   | Confidential NFT example - saving encrypted data                                                                                              |
| ConfidentialAuction          | Confidential auction - encrypted bid amount                                                                                                   |
| ConfidentialIdentityRegistry | Confidential Identity Registry - Encrypted identity data                                                                                      |
| Precompile                   | Thorough examples of the precompile functionality                                                                                             |

## Usage

1. Install dependencies

   ```
   yarn
   ```

3. Build and compile contracts

   ```
   yarn build
   ```

5. Run tests

   ```
   yarn test
   ```

7. Run specific tests

   ```
   yarn test-nft
   ```

   or

   ```
   yarn test-erc20
   ```

   or

   ```
   yarn test-auction
   ```

   or

   ```
   yarn test-identity
   ```

> [!NOTE]  
> Runnning tests will create an account automatically. The account will be saved to the `.env` file and will need to be funded. Use the COTI faucet to request devnet/testnet funds.

### Add contracts to your Hardhat project

```shell
yarn add git@github.com:coti-io/confidentiality-contracts.git
```

This command installs the confidentiality contracts from the specified Git repository using the Yarn package manager for Hardhat projects. After installation, you can import and use the contracts in your Solidity code.

#### To report issues, please create a [github issue](https://github.com/coti-io/confidentiality-contracts/issues)