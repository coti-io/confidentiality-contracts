// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../lib/MpcCore.sol";
import {ConfidentialERC20} from "../token/ERC20/ConfidentialERC20.sol";

contract ERC20Example is ConfidentialERC20 {
    constructor(
        string memory name_,
        string memory symbol_,
        uint64 initialSupply
    ) ConfidentialERC20(name_, symbol_, 5) {
        _mint(msg.sender, initialSupply);
    }

    // sets the balance of the sender to the given amount (just for testing)
    function setBalance(uint64 amount) public {
        _mint(msg.sender, amount);
    }
}
