// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../lib/MpcCore.sol";

contract AccountOnboard {

    event AccountOnboarded(address indexed _from, bytes userKey1, bytes userKey2);

    /**
     * @notice onboards the account and emits the users AES encryption key in encrypted form
     * @dev the AES key must be decrypted in order to be used to pass encrypted data to the chain
     * @param publicKey RSA public key
     * @param signedEK signed hash of the RSA public key
     */
    function onboardAccount(bytes calldata publicKey, bytes calldata signedEK) public {
        (bytes memory accountKey1, bytes memory accountKey2)= MpcCore.getUserKey(publicKey, signedEK);
        emit AccountOnboarded(msg.sender, accountKey1, accountKey2);
    }
}
