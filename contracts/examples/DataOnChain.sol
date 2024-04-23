pragma solidity ^0.8.19;

import "MpcCore.sol";

contract DataOnChain {

    uint64 private clearValue;
    ctUint64 private ctUserSomeEncryptedValue;
    ctUint64 private ctNetworkSomeEncryptedValue;

    constructor () {
        clearValue = 5;
    }

    event UserEncryptedValue(address indexed _from, ctUint64 ctUserSomeEncryptedValue);

    function getNetworkSomeEncryptedValueOf() external view returns (ctUint64 ctSomeEncryptedValue) {
        return ctNetworkSomeEncryptedValue;
    }

    function getUserSomeEncryptedValueOf() external view returns (ctUint64 ctSomeEncryptedValue) {
        return ctUserSomeEncryptedValue;
    }

    function setSomeEncryptedValueOf(uint64 _value) external {
        gtUint64 gtNetworkSomeEncryptedValue = MpcCore.setPublic64(_value);
        ctNetworkSomeEncryptedValue = MpcCore.offBoard(gtNetworkSomeEncryptedValue);
    }

    function setUserSomeEncryptedValueOf() external {
        gtUint64 gtNetworkSomeEncryptedValue = MpcCore.onBoard(ctNetworkSomeEncryptedValue);
        ctUserSomeEncryptedValue = MpcCore.offBoardToUser(gtNetworkSomeEncryptedValue, msg.sender);
        emit UserEncryptedValue(msg.sender, ctUserSomeEncryptedValue);
    }

    function someValueOf() external returns (uint64 value) {
        return clearValue;
    }
}