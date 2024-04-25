# COTI V2 Confidential Smart Contracts with examples

All repositories specified below contains smart contracts that implement confidentiality features using the COTI V2 protocol.
The contracts provide examples for various use cases, such as Non-Fungible Tokens (NFTs), ERC20 tokens, Auction, and Identity management.

These contracts demonstrate how to leverage the confidentiality features of the COTI V2 protocol to enhance privacy and security in decentralized applications.
The contracts are of Solidity and can be compiled and deployed using popular development tools like Hardhat and Foundry (Work in progress).

There are a few different ways to interact with the contracts:

1. Using the [python-sdk](https://github.com/coti-io/coti-sdk-python)
2. Using the [typescript-sdk](https://github.com/coti-io/coti-sdk-typescript)
3. Using [hardhat development environment](https://github.com/coti-io/confidentiality-contracts)

|                              | python-sdk    | hardhat    | sdk-typescript | Description                                                                    |
| ---------------------------- |---------------| ---------- | -------------- |--------------------------------------------------------------------------------|
| AccountOnboard               | deployment(*) | deployment | -              | Onboard a EOA account - During onboard network creates AES unique for that EOA |
|                              | execution     | execution  | execution      | which is used for decrypting values sent back from the network                 |
| ERC20Example                 | deployment    | deployment | -              | Confidential ERC20 - deploy and transfer encrypted amount of funds             |
|                              | execution     | execution  | execution      |                                                                                |
| NFTExample                   | -             | deployment | -              | Confidential NFT example - saving encrypted data                               |
|                              | -             | execution  | -              |                                                                                |
| ConfidentialAuction          | -             | deployment | -              | Confidential auction - encrypted bid amount                                    |
|                              | -             | execution  | -              |                                                                                |
| ConfidentialIdentityRegistry | -             | deployment | -              | Confidential Identity Registry - Encrypted identity data                       |
|                              | -             | execution  | -              |                                                                                |
| DataOnChain                  | deployment    | -          | -              | Basic encryption and decryption - Good place to start explorining network      |
|                              | execution     | -          | -              | capabilties                                                                    |
| Precompile                   | deployment    | deployment | -              | Thorough examples of the precompile functionality                              |
|                              | execution     | execution  | -              |                                                                                |

(*) no deployment needed (system contract)
* Due to the nature of ongoing development, future version might break existing functionality

## Getting initial funds (Faucet)

We don't have the BOT faucet, yet. to receive funds send a telegram message to @gmesika with the following message: please send me devnet ETH to account <<your_eoa_address>>

## Python SDK ([coti-sdk-python](https://github.com/coti-io/coti-sdk-python)) - Usage

Examples that described above resides in [coti-sdk-python/examples], the solidity contracts are in confidentiality-contracts repo that is imported as a git submodule.
When executed, for example data_on_chain.py it will deploy the contract and create json file with details of the deployed
contract under [compiled_contracts] directory.

Check out the .env file for more details.

The python examples utilizes primitive deployment management that mostly checks if there is a json file under the [compiled_contracts] directory
and doesn't deploy incase it exists, otherwise deploys.

How to get started?

1. Generate EOA: Run the native_transfer.py script, it will transfer tiny amount to some random address - demonstrating standard native transfer.
   It will create a new EOA (you will see your public address in the script output), and account private key will be recorded in .env
   For the first time it will fail since account doesn't have any funds - refer to the Faucet section above
2. Generate Encryption Key: Run the onboard_account.py, it will ask for the network for the AES encryption key specific for this account and
   it will log it in the .env file (mandatory for every action that does COTI v2 onchain computation)
3. Execute: Now you can run any other example, e.g. precompiles_examples.py (see above for complete list)

In order to follow the transactions sent to the node, use the web_socket.py to be notified and see their onchain details.

Pending enhancements:
* Versioned pypi library
* Extending examples such as confidential ERC20 minting, confidential NFT (deployment and actions) and more...

#### To report issues, please use the [github issues](https://github.com/coti-io/coti-sdk-python/issues)

## Typescript SDK ([coti-sdk-typescript](https://github.com/coti-io/coti-sdk-typescript)) - Usage

Examples that described above resides in [coti-sdk-typescript/src/examples], the solidity contracts are in confidentiality-contracts repo that is imported as a git submodule.

1. Install dependencies `yarn`
2. Run ERC20 test `yarn erc20`

- \*Runnning test will create an account automatically, that will be saved into .env file and will need to be funded using a faucet

Pending enhancements:
* Versioned library
* Extending examples such as confidential ERC20 minting, confidential NFT (deployment and actions) and more...

#### To report issues, please use the [github issues](https://github.com/coti-io/coti-sdk-typescript/issues)

## Hardhat ([confidential-contracts](https://github.com/coti-io/confidentiality-contracts)) - Usage

1. Install dependencies `yarn`
2. Build and compile contracts `yarn build`
3. Run tests `yarn test`
4. Run specific tests `yarn test-nft` or `yarn test-erc20` or `yarn test-auction` or `yarn test-identity`

- \*Running any test will create an account automatically, that will be saved into .env file and will need to be funded using a faucet

### Add contracts to your project

This section provides instructions on how to add the confidentiality contracts to your project using popular development tools like Forge and Hardhat.

### Hardhat

```shell
$ yarn add git@github.com:coti-io/confidentiality-contracts.git
```

This command installs the confidentiality contracts from the specified Git repository using the Yarn package manager for Hardhat projects. After installation, you can import and use the contracts in your Solidity code.

#### To report issues, please use the [github issues](https://github.com/coti-io/confidentiality-contracts/issues)