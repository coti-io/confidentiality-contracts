# COTI V2 Confidential Smart Contracts with examples

All repositories specified below contains smart contracts that implement confidentiality features using the COTI V2 protocol.
The contracts provide examples for various use cases, such as Non-Fungible Tokens (NFTs), ERC20 tokens, Auction, and Identity management.

These contracts demonstrate how to leverage the confidentiality features of the COTI V2 protocol to enhance privacy and security in decentralized applications.
The contracts are of Solidity and can be compiled and deployed using popular development tools like Hardhat and Foundry (Work in progress).

There are a few different ways to interact with the contracts:

1. Using the [python-sdk](https://github.com/coti-io/coti-sdk-python)
2. Using the [typescript-sdk](https://github.com/coti-io/coti-sdk-typescript-examples)
3. Using [hardhat development environment](https://github.com/coti-io/confidentiality-contracts)

| Contract                       |            | python-sdk | hardhat sdk | typescrypt sdk | Contract Description                                                                                                                          |
|--------------------------------|------------|------------|-------------|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
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
| `Precompile`                   | execution  | ✅          | ✅           | ❌              | "                                                                                                                                             |-              |                                                                                |

(\*) no deployment needed (system contract)

> [!NOTE]  
> Due to the nature of ongoing development, future version might break existing functionality

## Using the faucet to request funds

A BOT faucet is not yet available. To request funds send a telegram message to [@gmesika](https://t.me/gmesika) with the following message:

`please send devnet COTI to account <<your_eoa_address>>`

## Python SDK ([coti-sdk-python](https://github.com/coti-io/coti-sdk-python))
### Usage

The examples described above reside in [coti-sdk-python/examples](https://github.com/coti-io/coti-sdk-python/tree/main/examples), the solidity contracts are located in the [confidentiality-contracts](https://github.com/coti-io/confidentiality-contracts) repo, which is imported as a git submodule.

When `data_on_chain.py` is executed, it will deploy the contract and create a json file with the details of the deployed contract under the [compiled_contracts] directory.

Check out the .env file for more details.

The python examples use primitive deployment management that mostly checks if there is a json file under the `compiled_contracts` directory and doesn't deploy when one exists. If such json file does not exist, the contract will be deployed.

### Getting Started

**1. Generate EOA**

Run the `native_transfer.py` script, it will transfer a small amount to a random address - demonstrating standard native transfer.

It will create a new EOA (you will see your public address in the script output), and an `ACCOUNT_PRIVATE_KEY` will be recorded in the `.env` file.

It will fail on first deploy since the account doesn't have any funds. Refer to the faucet section above

**2. Generate Encryption Key**

Run the `onboard_account.py` script, it will request an AES encryption key from the network, specific for this account and it will log it in the `.env` file (mandatory for every action that does COTI v2 on-chain computation)

**3. Execute**

Now you can run any other example, e.g. `precompiles_examples.py` (see above for complete list)

In order to follow the transactions sent to the node, use the `web_socket.py` script to be notified and see their on-chain details.

Pending enhancements:

- Versioned pypi library
- Extending examples such as confidential ERC20 minting, confidential NFT (deployment and actions) and more.

#### To report issues, please create a [github issue](https://github.com/coti-io/coti-sdk-python/issues)

## Typescript SDK ([coti-sdk-typescript](https://github.com/coti-io/coti-sdk-typescript))
### Usage

The examples described above reside in [coti-sdk-typescript/src/examples](https://github.com/coti-io/coti-sdk-typescript/tree/main/src/examples), the solidity contracts are in the [confidentiality-contracts](https://github.com/coti-io/confidentiality-contracts) repo which is imported as a git submodule.

1. Install dependencies

   ```
   yarn
   ```

3. Run ERC20 test

   ```
   yarn erc20
   ```

> [!NOTE]  
> Runnning tests will create an account automatically. The account will be saved to the `.env` file and will need to be funded. Use the COTI faucet to request devnet/testnet funds.

#### Pending enhancements

- Versioned library
- Extending examples such as confidential ERC20 minting, confidential NFT (deployment and actions) and more.

#### To report issues, please create a [github issue](https://github.com/coti-io/coti-sdk-typescript/issues)

## Hardhat ([confidential-contracts](https://github.com/coti-io/confidentiality-contracts))
### Usage

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

### Add contracts to your project

This section provides instructions on how to add the confidentiality contracts to your project using popular development tools like Forge and Hardhat.

### Hardhat

```shell
yarn add git@github.com:coti-io/confidentiality-contracts.git
```

This command installs the confidentiality contracts from the specified Git repository using the Yarn package manager for Hardhat projects. After installation, you can import and use the contracts in your Solidity code.

#### To report issues, please create a [github issue](https://github.com/coti-io/confidentiality-contracts/issues)