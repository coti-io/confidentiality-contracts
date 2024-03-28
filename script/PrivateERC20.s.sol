// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {PrivateERC20Contract} from "../src/token/PrivateERC20Contract.sol";

contract PrivateERC20Script is Script {
    uint64 initialAmount = 500000000;

    function setUp() public {}

    function run() public {
        uint256 key = vm.envUint("SIGNING_KEY");

        vm.startBroadcast(key);

        PrivateERC20Contract token = new PrivateERC20Contract(
            "SODA",
            "SOD",
            initialAmount
        );
        console.log("token deployed at", address(token));

        vm.stopBroadcast();
    }
}
