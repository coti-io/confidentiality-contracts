## Privacy contracts for Coti V2 with examples

## Install - Forge

```shell
# TODO: move the repo to the right org
$ forge install git@github.com:vladi-coti/privacy-contracts.git
```

## Install - Hardhat

```shell
# TODO: move the repo to the right org
$ yarn add git@github.com:vladi-coti/privacy-contracts.git
```

## Usage - Forge

### Compile

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Deploy - Forge

#### Script

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>

$ source .env; forge script script/Counter.s.sol:CounterScript --rpc-url $SEPOLIA_RPC_URL #--broadcast
$ source .env; forge script script/ConfidentialERC20.s.sol:ConfidentialERC20Script --rpc-url $SODALABS_NODE_RPC_URL --legacy --skip-simulation --broadcast

# run on forked forge with CotiV2 support
$ cargo run --manifest-path /Users/Vlad1/coti/foundry/crates/forge/Cargo.toml script script/ConfidentialERC20.s.sol:ConfidentialERC20Script --rpc-url "https://node.sodalabs.net" --legacy --broadcast --skip-simulation --slow
```

## Usage - Hardhat

### Compile

```shell
$ yarn hardhat compile
```

### Test

```shell
$ yarn test
```