## Privacy contracts for Coti V2

## Install - Forge

```shell
# TODO: move the repo to the right org
$ cargo add git@github.com:vladi-coti/privacy-contracts.git
```

## Install - Hardhat

```shell
# TODO: publish this repo as a package to npmjs
$ yarn add <npm package>
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
$ source .env; forge script script/PrivateERC20.s.sol:PrivateERC20Script --rpc-url $SODALABS_NODE_RPC_URL --legacy --skip-simulation --broadcast
```

## Usage - Hardhat

### Compile

```shell
$ yarn hardhat compile
```