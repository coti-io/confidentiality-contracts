// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {PrivateERC20} from "../contracts/token/ERC20/PrivateERC20.sol";

contract PrivateERC20Script is Script {
    uint64 initialAmount = 500000000;

    function setUp() public {}

    function run() public {
        uint256 key = vm.envUint("SIGNING_KEY");

        vm.startBroadcast(key);

        PrivateERC20 token = new PrivateERC20("SODA", "SOD", initialAmount);
        console.log("token deployed at", address(token));

        vm.stopBroadcast();
    }
}
