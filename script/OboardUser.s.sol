// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {GetUserKey} from "../src/user/GetUserKey.sol";

contract PrivateERC20Script is Script {
    uint64 initialAmount = 500000000;

    function setUp() public {}

    function run() public {
        uint256 key = vm.envUint("SIGNING_KEY");

        vm.startBroadcast(key);

        GetUserKey userKey = new GetUserKey();
        console.log("userKey deployed at", address(userKey));

        vm.stopBroadcast();
    }
}
