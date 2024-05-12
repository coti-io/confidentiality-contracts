# COTI V2 Confidential Smart Contracts with examples

All repositories specified below contains smart contracts that implement confidentiality features using the COTI V2 protocol.
The contracts provide examples for various use cases, such as Non-Fungible Tokens (NFTs), ERC20 tokens, Auction, and Identity management.

These contracts demonstrate how to leverage the confidentiality features of the COTI V2 protocol to enhance privacy and security in decentralized applications.
The contracts are of Solidity and can be compiled and deployed using popular development tools like Hardhat and Foundry (Work in progress).

Important Links:

[COTI](https://coti.io) / [GitBook](https://docs.coti.io) / [Explorer-DevNet](https://explorer-devnet.coti.io) / [Faucet](https://faucet.coti.io)

There are a few different ways to interact with the contracts:

1. [python-sdk](https://github.com/coti-io/coti-sdk-python)
2. [typescript-sdk](https://github.com/coti-io/coti-sdk-typescript) / [typescript-sdk-examples](https://github.com/coti-io/coti-sdk-typescript-examples)
3. [hardhat development environment](https://github.com/coti-io/confidentiality-contracts)

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

## Faucet to request funds

🤖 Faucet BOT is available!  To request devnet/testnet coins funding use: [faucet](https://faucet.coti.io)

## Python SDK ([coti-sdk-python](https://github.com/coti-io/coti-sdk-python))
### Usage

The examples described above reside in [coti-sdk-python/examples](https://github.com/coti-io/coti-sdk-python/tree/main/examples), the solidity contracts are located in the [confidentiality-contracts](https://github.com/coti-io/confidentiality-contracts) repository, which is imported as a git submodule part of the python sdk.

Check out the .env file for more details - The python examples use primitive deployment management that mostly checks if there is a json file under the `compiled_contracts` directory and doesn't deploy when one exists. If such json file does not exist, the contract will be deployed.

### Getting Started

**1. Generate EOA**

Run the `native_transfer.py` script, it will transfer a small amount of coins to a random address - demonstrating standard native transfer.

During that process, it will create a new EOA (you will see your public address in the script output), and an `ACCOUNT_PRIVATE_KEY` will be saved into the `.env` file.

It will of course fail on first attempt of execution since the newly created account doesn't have any funds. Refer to the faucet section above to transfer funds into that account and try again.

**2. Generate Encryption Key**

Run the `onboard_account.py` script, it will request an AES encryption key from the network, that is specific for the account and it will save the AES key into the `.env` file,
That value is mandatory for every action that involves computation using COTI v2 on-chain.

**3. Execute**

Now you can run any other example, e.g. `precompiles_examples.py` (see above for complete list).
We recommend that you get familiar with `data_on_chain.py`, it best descibes the basics of keeping data encrypted on-chain and doing simple actions (encryption, decryption, computation, verification...)

In order to follow the transactions sent to the node, use the `web_socket.py` script to be notified and see their on-chain details.

Pending enhancements:

- Versioned pypi library (seperating the library repository from the examples repository)
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

- Publishing SDK via npmjs
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