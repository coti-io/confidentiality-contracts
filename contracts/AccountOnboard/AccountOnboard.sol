// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract AccountOnboard {

    event AccountOnboarded(address indexed _from, bytes userKey);

    function OnboardAccount(bytes calldata signedEK, bytes calldata signature) public {
        bytes memory accountKey = MpcCore.getUserKey(signedEK, signature);
        emit AccountOnboarded(msg.sender, accountKey);
    }
}
