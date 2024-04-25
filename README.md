# Coti V2 Confidential Smart Contracts with examples

This repository contains smart contracts that implement confidentiality features using the Coti V2 protocol. The contracts provide examples for various use cases, such as Non-Fungible Tokens (NFTs), ERC20 tokens, auction, and identity management.

These contracts demonstrate how to leverage the confidentiality features of the Coti V2 protocol to enhance privacy and security in decentralized applications.
The contracts are written in Solidity and can be compiled and deployed using popular development tools like Hardhat and Foundry(Work in progress).

There are a few different ways to interact with the contracts:

1. Using the [python-sdk](https://github.com/coti-io/coti-sdk-python)
2. Using the [typescript-sdk](https://github.com/coti-io/coti-sdk-typescript)
3. Using [hardhat development environment](https://github.com/coti-io/confidentiality-contracts)

|                              | python-sdk   | hardhat    | sdk-typescript | Description                                              |
| ---------------------------- | ------------ | ---------- | -------------- | -------------------------------------------------------- |
| AccountOnboard               | deployment\* | deployment | -              | Onboard to an account - used for decrypting and signing  |
|                              | execution    | execution  | execution      |                                                          |
| ERC20Example                 | deployment   | deployment | -              | Confidential ERC20 example - sending encrypted amount    |
|                              | execution    | execution  | execution      |                                                          |
| NFTExample                   | -            | deployment | -              | Confidential NFT example - saving encrypted data         |
|                              | -            | execution  | -              |                                                          |
| ConfidentialAuction          | -            | deployment | -              | Confidential auction - encripted bid amount              |
|                              | -            | execution  | -              |                                                          |
| ConfidentialIdentityRegistry | -            | deployment | -              | Confidential identity registry - encrypted identity data |
|                              | -            | execution  | -              |                                                          |
| DataOnChain                  | deployment   | -          | -              | Basic encryption example                                 |
|                              | execution    | -          | -              |                                                          |
| Precompile                   | deployment   | deployment | -              | Thorough tests of the precompile functionality           |
|                              | execution    | execution  | -              |                                                          |

\* no deployment needed (system contract)

## Getting initial funds (Faucet)

To get the initial funds send a telegram message to @<<telegram_account>> with the following message: please send me devnet ETH to account <<your_eoa_address>>

## Python SDK ([coti-sdk-python](https://github.com/coti-io/coti-sdk-python)) - Usage

## Typescript SDK ([coti-sdk-typescript](https://github.com/coti-io/coti-sdk-typescript)) - Usage

1. Install dependencies `yarn`
2. Run ERC20 test `yarn erc20`

- \*Runnning test will create an account automatically, that will be saved into .env file and will need to be funded using a faucet

## Hardhat ([confidential-contracts](https://github.com/coti-io/confidentiality-contracts)) - Usage

1. Install dependencies `yarn`
2. Build and compile contracts `yarn build`
3. Run tests `yarn test`
4. Run specific tests `yarn test-nft` or `yarn test-erc20` or `yarn test-auction` or `yarn test-identity`

- \*Runnning any test will create an account automatically, that will be saved into .env file and will need to be funded using a faucet

## Add contracts to your project

This section provides instructions on how to add the confidentiality contracts to your project using popular development tools like Forge and Hardhat.

### Hardhat

```shell
$ yarn add git@github.com:coti-io/confidentiality-contracts.git
```

This command installs the confidentiality contracts from the specified Git repository using the Yarn package manager for Hardhat projects. After installation, you can import and use the contracts in your Solidity code.
