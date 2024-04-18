// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test, console, Vm} from "forge-std/Test.sol";

abstract contract TestWrapper is Test {
    Vm.Wallet public owner;
    Vm.Wallet public other;

    function setupFork() public {
        vm.createSelectFork("https://devnet.coti.io");
        vm.makePersistent(0x0000000000000000000000000000000000000064);
    }

    function setupAccounts() public {
        string memory keys = vm.envString("SIGNING_KEYS");
        string[] memory keyList = vm.split(keys, ",");

        owner = vm.createWallet(keyList[0]);
        other = vm.createWallet(keyList[1]);
    }
}
