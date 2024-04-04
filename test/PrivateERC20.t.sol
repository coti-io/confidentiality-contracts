// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test, console} from "forge-std/Test.sol";
import {PrivateERC20} from "../contracts/token/PrivateERC20.sol";

contract PrivateERC20Test is Test {
    PrivateERC20 public token;

    function setUp() public {
        token = new PrivateERC20("Test Token", "TST", 100000000);
    }
}
