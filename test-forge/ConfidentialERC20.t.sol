// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test, console} from "forge-std/Test.sol";
import {ERC20Example} from "../contracts/ERC20Example.sol";

contract ConfidentialERC20Test is Test {
    ERC20Example public token;

    function setUp() public {
        token = new ERC20Example("Test Token", "TST", 100000000);
    }
}
