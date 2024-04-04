// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test, console} from "forge-std/Test.sol";
import {PrivateERC20Contract} from "../src/token/PrivateERC20Contract.sol";

contract PrivateERC20Test is Test {
    PrivateERC20Contract public token;

    function setUp() public {
        token = new PrivateERC20Contract("SODA", "SOD", 500000000);
    }
}
