pragma solidity ^0.8.19;

import "../lib/MpcCore.sol";

contract DataOnChain {

    uint64 private clearValue;
    ctUint64 private ctUserSomeEncryptedValue;
    ctUint64 private ctUserSomeEncryptedValueEncryptedInput;
    ctUint64 private ctNetworkSomeEncryptedValue;
    ctUint64 private ctNetworkSomeEncryptedValueEncryptedInput;

    constructor () {
        clearValue = 5;
    }

    event UserEncryptedValue(address indexed _from, ctUint64 ctUserSomeEncryptedValue);

    function getNetworkSomeEncryptedValue() external view returns (ctUint64 ctSomeEncryptedValue) {
        return ctNetworkSomeEncryptedValue;
    }

    function getNetworkSomeEncryptedValueEncryptedInput() external view returns (ctUint64 ctSomeEncryptedValue) {
        return ctNetworkSomeEncryptedValueEncryptedInput;
    }

    function getUserSomeEncryptedValue() external view returns (ctUint64 ctSomeEncryptedValue) {
        return ctUserSomeEncryptedValue;
    }

    function getUserSomeEncryptedValueEncryptedInput() external view returns (ctUint64 ctSomeEncryptedValue) {
        return ctUserSomeEncryptedValueEncryptedInput;
    }

    function setSomeEncryptedValue(uint64 _value) external {
        gtUint64 gtNetworkSomeEncryptedValue = MpcCore.setPublic64(_value);
        ctNetworkSomeEncryptedValue = MpcCore.offBoard(gtNetworkSomeEncryptedValue);
    }

    function setSomeEncryptedValueEncryptedInput(ctUint64 _itCT, bytes calldata _itSignature) external {
        itUint64 memory it;
        it.ciphertext = _itCT;
        it.signature = _itSignature;
        gtUint64 gtNetworkSomeEncryptedValue = MpcCore.validateCiphertext(it);
        ctNetworkSomeEncryptedValueEncryptedInput = MpcCore.offBoard(gtNetworkSomeEncryptedValue);
    }

    function setUserSomeEncryptedValue() external {
        gtUint64 gtNetworkSomeEncryptedValue = MpcCore.onBoard(ctNetworkSomeEncryptedValue);
        ctUserSomeEncryptedValue = MpcCore.offBoardToUser(gtNetworkSomeEncryptedValue, msg.sender);
        emit UserEncryptedValue(msg.sender, ctUserSomeEncryptedValue);
    }

    function setUserSomeEncryptedValueEncryptedInput() external {
        gtUint64 gtEncryptedUserSomeEncryptedValue = MpcCore.onBoard(ctNetworkSomeEncryptedValueEncryptedInput);
        ctUserSomeEncryptedValueEncryptedInput = MpcCore.offBoardToUser(gtEncryptedUserSomeEncryptedValue, msg.sender);
        emit UserEncryptedValue(msg.sender, ctUserSomeEncryptedValueEncryptedInput);
    }

    function getSomeValue() external returns (uint64 value) {
        return clearValue;
    }
}