// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract PrecompilesOffboardToUserKeyTestContract {

    bytes userKey;
    uint8 x;
    ctUint8 ctUserKey;

    uint256 ct8;
    uint256 ct16;
    uint256 ct32;
    uint256 ct64;

    function getCTs() public view returns (uint256, uint256, uint256, uint256) {
        return (ct8, ct16, ct32, ct64);
    }
    
    function getUserKeyTest(bytes calldata signedEK, bytes calldata signature, address addr) public returns (uint8) {

        gtUint8 a = MpcCore.setPublic8(uint8(5));
        gtUint8 c = MpcCore.add(a, uint8(5)); // 10
        userKey = MpcCore.getUserKey(signedEK, signature);
        ctUserKey = MpcCore.offBoardToUser(c, addr);
        ctUint8 ctSystemKey = MpcCore.offBoard(c);
        gtUint8 c1 = MpcCore.onBoard(ctSystemKey);
        x = MpcCore.decrypt(c1);
        return x;
    }

    function getX() public view returns (uint8) {
        return x;
    }

    function getUserKey() public view returns (bytes memory) {
        return userKey;
    }

    function getCt() public view returns (ctUint8) {
        return ctUserKey;
    }

    function userKeyTest(bytes calldata signedEK, bytes calldata signature) public view returns (bytes memory key) {

        return MpcCore.getUserKey(signedEK, signature);
    }

    function offboardToUserTest(uint8 a, address addr) public returns (uint256, uint256, uint256, uint256) {
        gtUint8 a8_s = MpcCore.setPublic8(a);
        gtUint16 a16_s = MpcCore.setPublic16(a);
        gtUint32 a32_s = MpcCore.setPublic32(a);
        gtUint64 a64_s = MpcCore.setPublic64(a);

        ctUint8 cipher8 = MpcCore.offBoardToUser(a8_s, addr);
        ctUint16 cipher16 = MpcCore.offBoardToUser(a16_s, addr);
        ctUint32 cipher32 = MpcCore.offBoardToUser(a32_s, addr);
        ctUint64 cipher64 = MpcCore.offBoardToUser(a64_s, addr);

        ct8 = ctUint8.unwrap(cipher8);
        ct16 = ctUint16.unwrap(cipher16);
        ct32 = ctUint32.unwrap(cipher32);
        ct64 = ctUint64.unwrap(cipher64);

        return (ct8, ct16, ct32, ct64);
    }
}
