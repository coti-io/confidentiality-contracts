// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../lib/MpcCore.sol";

contract TestMpcCore {
    ctString private userEncryptedString;
    
    ctString private networkEncryptedString;

    string public plaintext;

    bool public isEqual;

    function setUserEncryptedString(itString calldata it_) public {
        gtString memory gt_ = MpcCore.validateCiphertext(it_);

        userEncryptedString = MpcCore.offBoardToUser(gt_, msg.sender);
    }

    function getUserEncryptedString() public view returns (ctString memory) {
        return userEncryptedString;
    }

    function setNetworkEncryptedString(itString calldata it_) public {
        gtString memory gt_ = MpcCore.validateCiphertext(it_);

        networkEncryptedString = MpcCore.offBoard(gt_);
    }

    function decryptNetworkEncryptedString() public {
        gtString memory gt_ = MpcCore.onBoard(networkEncryptedString);

        plaintext = MpcCore.decrypt(gt_);
    }

    function setPublicString(string calldata str) public {
        gtString memory gt_ = MpcCore.setPublicString(str);

        userEncryptedString = MpcCore.offBoardToUser(gt_, msg.sender);
    }

    function setIsEqual(itString calldata a_, itString calldata b_, bool useEq) public {
        gtString memory a = MpcCore.validateCiphertext(a_);
        gtString memory b = MpcCore.validateCiphertext(b_);

        gtBool isEqual_;

        if (useEq) {
            isEqual_ = MpcCore.eq(a, b);
        } else {
            isEqual_ = MpcCore.not(MpcCore.ne(a, b));
        }

        isEqual = MpcCore.decrypt(isEqual_);
    }
}
