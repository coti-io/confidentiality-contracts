// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test, console} from "forge-std/Test.sol";
import {TestWrapper} from "./TestWrapper.sol";
import {ERC20Example} from "../contracts/examples/ERC20Example.sol";

contract ConfidentialERC20Test is TestWrapper {
    ERC20Example public token;

    function setUp() public {
        setupFork();
        setupAccounts();

        token = new ERC20Example("Test Token", "TST", 100000000);
    }

    function test_deploy_name() view public {
        console.log("token.name()", token.name());
        assertEq(token.name(), "Test Token");
    }
}
