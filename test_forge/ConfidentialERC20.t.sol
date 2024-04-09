// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test, console} from "forge-std/Test.sol";
import {ConfidentialERC20} from "../contracts/token/ERC20/ConfidentialERC20.sol";

contract ConfidentialERC20Test is Test {
    ConfidentialERC20 public token;

    function setUp() public {
        token = new ConfidentialERC20("Test Token", "TST", 100000000);
    }
}
