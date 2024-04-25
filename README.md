# Coti V2 Confidential Smart Contracts

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

- no deployment needed (system contract)

## Confidentiality contracts for Coti V2 with examples

This repository contains smart contracts that implement confidentiality features using the Coti V2 protocol. The contracts provide examples for various use cases, such as Non-Fungible Tokens (NFTs), ERC20 tokens, auctions, and identity management.

These contracts demonstrate how to leverage the confidentiality features of the Coti V2 protocol to enhance privacy and security in decentralized applications.

The contracts are written in Solidity and can be compiled and deployed using popular development tools like Hardhat and Foundry(Work in progress).

## Hardhat - Usage

```shell
$ yarn # install dependencies

$ yarn build # compile

$ yarn test # run tests on all contract

$ yarn test-nft # run NFT example tests
$ yarn test-erc20 # run ERC20 example tests
$ yarn test-auction # run Auction example tests
$ yarn test-identity # run Identity example tests
```

## Add contracts to your project

This section provides instructions on how to add the confidentiality contracts to your project using popular development tools like Forge and Hardhat.

### Hardhat

```shell
$ yarn add git@github.com:coti-io/confidentiality-contracts.git
```

This command installs the confidentiality contracts from the specified Git repository using the Yarn package manager for Hardhat projects. After installation, you can import and use the contracts in your Solidity code.
