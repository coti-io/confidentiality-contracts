## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

-   **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
-   **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
-   **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
-   **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

#### Create
```shell
$ source .env; forge create --rpc-url $SODALABS_NODE_RPC_URL --constructor-args "SODA" "SOD" 500000000 --private-key $SIGNING_KEY --revert-strings debug --nonce 287 --legacy src/token/PrivateERC20Contract.sol:PrivateERC20Contract

```

#### Script
```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>

$ source .env; forge script script/Counter.s.sol:CounterScript --rpc-url $SEPOLIA_RPC_URL #--broadcast
$ source .env; forge script script/PrivateERC20.s.sol:PrivateERC20Script --rpc-url $SODALABS_NODE_RPC_URL --legacy --skip-simulation --broadcast
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
