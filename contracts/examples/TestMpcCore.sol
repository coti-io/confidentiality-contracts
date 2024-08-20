// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../lib/MpcCore.sol";

contract TestMpcCore {

    // Encrypted string variables

    ctString private userEncryptedString;
    
    ctString private networkEncryptedString;

    string public plaintextString;

    bool public isEqual;

    // Encrypted address variables

    ctAddress public userEncryptedAddress;

    ctAddress public networkEncryptedAddress;

    address public plaintextAddress;


    // Encrypted string functions

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

        plaintextString = MpcCore.decrypt(gt_);
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

    function setRandomString() public {
        gtString memory gt_ = MpcCore.randString(20);

        userEncryptedString = MpcCore.offBoardToUser(gt_, msg.sender);
    }

    // Encrypted address function

    function setUserEncryptedAddress(itAddress calldata it_) public {
        gtAddress memory gt_ = MpcCore.validateCiphertext(it_);

        userEncryptedAddress = MpcCore.offBoardToUser(gt_, msg.sender);
    }

    function setNetworkEncryptedAddress(itAddress calldata it_) public {
        gtAddress memory gt_ = MpcCore.validateCiphertext(it_);

        networkEncryptedAddress = MpcCore.offBoard(gt_);
    }

    function decryptNetworkEncryptedAddress() public {
        gtAddress memory gt_ = MpcCore.onBoard(networkEncryptedAddress);

        plaintextAddress = MpcCore.decrypt(gt_);
    }

    function setPublicAddress(address addr) public {
        gtAddress memory gt_ = MpcCore.setPublicAddress(addr);

        userEncryptedAddress = MpcCore.offBoardToUser(gt_, msg.sender);
    }

    function setIsEqual(itAddress calldata a_, itAddress calldata b_, bool useEq) public {
        gtAddress memory a = MpcCore.validateCiphertext(a_);
        gtAddress memory b = MpcCore.validateCiphertext(b_);

        gtBool isEqual_;

        if (useEq) {
            isEqual_ = MpcCore.eq(a, b);
        } else {
            isEqual_ = MpcCore.not(MpcCore.ne(a, b));
        }

        isEqual = MpcCore.decrypt(isEqual_);
    }

    function setRandomAddress() public {
        gtAddress memory gt_ = MpcCore.randAddress();

        userEncryptedAddress = MpcCore.offBoardToUser(gt_, msg.sender);
    }
}
