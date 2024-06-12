// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;


type gtBool is uint256;
type gtUint8 is uint256;
type gtUint16 is uint256;
type gtUint32 is uint256;
type gtUint64 is uint256;

type ctBool is uint256;
type ctUint8 is uint256;
type ctUint16 is uint256;
type ctUint32 is uint256;
type ctUint64 is uint256;

struct itBool {
    ctBool ciphertext;
    bytes signature;
}
struct itUint8 {
    ctUint8 ciphertext;
    bytes signature;
}
struct itUint16 {
    ctUint16 ciphertext;
    bytes signature;
}
struct itUint32 {
    ctUint32 ciphertext;
    bytes signature;
}
struct itUint64 {
    ctUint64 ciphertext;
    bytes signature;
}

struct utBool {
    ctBool ciphertext;
    ctBool userCiphertext;
}
struct utUint8 {
    ctUint8 ciphertext;
    ctUint8 userCiphertext;
}
struct utUint16 {
    ctUint16 ciphertext;
    ctUint16 userCiphertext;
}
struct utUint32 {
    ctUint32 ciphertext;
    ctUint32 userCiphertext;
}
struct utUint64 {
    ctUint64 ciphertext;
    ctUint64 userCiphertext;
}


import "./MpcInterface.sol";


library MpcCore {

    enum MPC_TYPE {SBOOL_T , SUINT8_T , SUINT16_T, SUINT32_T ,SUINT64_T }
    enum ARGS {BOTH_SECRET , LHS_PUBLIC, RHS_PUBLIC  }

    function combineEnumsToBytes2(MPC_TYPE mpcType, ARGS argsType) internal pure returns (bytes2) {
        return bytes2(uint16(mpcType) << 8 | uint8(argsType));
    }

    function combineEnumsToBytes3(MPC_TYPE mpcType1, MPC_TYPE mpcType2, ARGS argsType) internal pure returns (bytes3) {
        return bytes3(uint24(mpcType1) << 16 | uint16(mpcType2) << 8 | uint8(argsType));
    }

    function combineEnumsToBytes4(MPC_TYPE mpcType1, MPC_TYPE mpcType2, MPC_TYPE mpcType3, ARGS argsType) internal pure returns (bytes4) {
        return bytes4(uint32(mpcType1) << 24 | uint24(mpcType2) << 16 | uint16(mpcType3) << 8 | uint8(argsType));
    }

    function getUserKey(bytes calldata signedEK, bytes calldata signature) internal view returns (bytes memory encryptedKey) {
        // Combine array from signedEK and signature
        bytes memory combined = new bytes(signature.length + signedEK.length);

        // Copy contents of signature into combined
        for (uint i = 0; i < signature.length; i++) {
            combined[i] = signature[i];
        }

        // Copy contents of _bytes2 into combined after _bytes1
        for (uint j = 0; j < signedEK.length; j++) {
            combined[signature.length + j] = signedEK[j];
        }
        return ExtendedOperations(MPC_PRECOMPILE).GetUserKey(combined);
    }

    

// =========== 1 bit operations ==============

    function validateCiphertext(itBool memory input) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            ValidateCiphertext(bytes1(uint8(MPC_TYPE.SBOOL_T)), ctBool.unwrap(input.ciphertext), input.signature));
    }

    function onBoard(ctBool ct) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            OnBoard(bytes1(uint8(MPC_TYPE.SBOOL_T)), ctBool.unwrap(ct)));
    }

    function offBoard(gtBool pt) internal returns (ctBool) {
          return ctBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            OffBoard(bytes1(uint8(MPC_TYPE.SBOOL_T)), gtBool.unwrap(pt)));
    }

    function offBoardToUser(gtBool pt, address addr) internal returns (ctBool) {
          return ctBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            OffBoardToUser(bytes1(uint8(MPC_TYPE.SBOOL_T)), gtBool.unwrap(pt), abi.encodePacked(addr)));
    }

    function offBoardCombined(gtBool pt, address addr) internal returns (utBool memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic(bool pt) internal returns (gtBool) {
        uint256 temp;
        temp = pt ? 1 : 0; 
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            SetPublic(bytes1(uint8(MPC_TYPE.SBOOL_T)), temp));
    }

    function rand() internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).Rand(bytes1(uint8(MPC_TYPE.SBOOL_T))));
    }

    function and(gtBool a, gtBool b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SBOOL_T, MPC_TYPE.SBOOL_T, ARGS.BOTH_SECRET), gtBool.unwrap(a), gtBool.unwrap(b)));
    }

    function or(gtBool a, gtBool b) internal returns (gtBool) {
          return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SBOOL_T, MPC_TYPE.SBOOL_T, ARGS.BOTH_SECRET), gtBool.unwrap(a), gtBool.unwrap(b)));
    }

    function xor(gtBool a, gtBool b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SBOOL_T, MPC_TYPE.SBOOL_T, ARGS.BOTH_SECRET), gtBool.unwrap(a), gtBool.unwrap(b)));
    }
    
    function eq(gtBool a, gtBool b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SBOOL_T, MPC_TYPE.SBOOL_T, ARGS.BOTH_SECRET), gtBool.unwrap(a), gtBool.unwrap(b)));
    }

    function ne(gtBool a, gtBool b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SBOOL_T, MPC_TYPE.SBOOL_T, ARGS.BOTH_SECRET), gtBool.unwrap(a), gtBool.unwrap(b)));
    }

    function decrypt(gtBool ct) internal returns (bool){
        uint256 temp = ExtendedOperations(MPC_PRECOMPILE).
            Decrypt(bytes1(uint8(MPC_TYPE.SBOOL_T)), gtBool.unwrap(ct));
        return temp != 0;
    }

    function mux(gtBool bit, gtBool a, gtBool b) internal returns (gtBool){
         return  gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SBOOL_T, MPC_TYPE.SBOOL_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtBool.unwrap(a), gtBool.unwrap(b)));
    }

    function not(gtBool a) internal returns (gtBool){
         return  gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Not(bytes1(uint8(MPC_TYPE.SBOOL_T)), gtBool.unwrap(a)));
    }


 // =========== Operations with BOTH_SECRET parameter ===========
 // =========== 8 bit operations ==============

    function validateCiphertext(itUint8 memory input) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            ValidateCiphertext(bytes1(uint8(MPC_TYPE.SUINT8_T)), ctUint8.unwrap(input.ciphertext), input.signature));
    }

    function onBoard(ctUint8 ct) internal returns (gtUint8) {
         return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            OnBoard(bytes1(uint8(MPC_TYPE.SUINT8_T)), ctUint8.unwrap(ct)));
    }

    function offBoard(gtUint8 pt) internal returns (ctUint8) {
          return ctUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            OffBoard(bytes1(uint8(MPC_TYPE.SUINT8_T)), gtUint8.unwrap(pt)));
    }

    function offBoardToUser(gtUint8 pt, address addr) internal returns (ctUint8) {
          return ctUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            OffBoardToUser(bytes1(uint8(MPC_TYPE.SUINT8_T)), gtUint8.unwrap(pt), abi.encodePacked(addr)));
    }

    function offBoardCombined(gtUint8 pt, address addr) internal returns (utUint8 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic8(uint8 pt) internal returns (gtUint8) {
          return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            SetPublic(bytes1(uint8(MPC_TYPE.SUINT8_T)), uint256(pt)));
    }

    function rand8() internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).Rand(bytes1(uint8(MPC_TYPE.SUINT8_T))));
    }

    function randBoundedBits8(uint8 numBits) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).RandBoundedBits(bytes1(uint8(MPC_TYPE.SUINT8_T)), numBits));
    }

    function add(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function sub(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
         return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function mul(gtUint8 a, gtUint8 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function div(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
          return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function rem(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
         return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function and(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
         return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function or(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
          return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function xor(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function shl(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
          return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function shr(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function eq(gtUint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function ne(gtUint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function ge(gtUint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function gt(gtUint8 a, gtUint8 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function le(gtUint8 a, gtUint8 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function lt(gtUint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function min(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function max(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function decrypt(gtUint8 ct) internal returns (uint8){
          return uint8(ExtendedOperations(MPC_PRECOMPILE).
            Decrypt(bytes1(uint8(MPC_TYPE.SUINT8_T)), gtUint8.unwrap(ct)));
    }

    function mux(gtBool bit, gtUint8 a, gtUint8 b) internal returns (gtUint8){
         return  gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function transfer(gtUint8 a, gtUint8 b, gtUint8 amount) internal returns (gtUint8, gtUint8, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint8.wrap(new_a), gtUint8.wrap(new_b), gtBool.wrap(res));
    }


 // =========== 16 bit operations ==============

    function validateCiphertext(itUint16 memory input) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            ValidateCiphertext(bytes1(uint8(MPC_TYPE.SUINT16_T)), ctUint16.unwrap(input.ciphertext), input.signature));
    }

    function onBoard(ctUint16 ct) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            OnBoard(bytes1(uint8(MPC_TYPE.SUINT16_T)), ctUint16.unwrap(ct)));
    }

    function offBoard(gtUint16 pt) internal returns (ctUint16) {
          return ctUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            OffBoard(bytes1(uint8(MPC_TYPE.SUINT16_T)), gtUint16.unwrap(pt)));
    }

    function offBoardToUser(gtUint16 pt, address addr) internal returns (ctUint16) {
          return ctUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            OffBoardToUser(bytes1(uint8(MPC_TYPE.SUINT16_T)), gtUint16.unwrap(pt), abi.encodePacked(addr)));
    }

    function offBoardCombined(gtUint16 pt, address addr) internal returns (utUint16 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic16(uint16 pt) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            SetPublic(bytes1(uint8(MPC_TYPE.SUINT16_T)), uint256(pt)));
    }

    function rand16() internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).Rand(bytes1(uint8(MPC_TYPE.SUINT16_T))));
    }

    function randBoundedBits16(uint8 numBits) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).RandBoundedBits(bytes1(uint8(MPC_TYPE.SUINT16_T)), numBits));
    }

    function add(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function sub(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function mul(gtUint16 a, gtUint16 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function div(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function rem(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function and(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function or(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function xor(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function shl(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function shr(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function eq(gtUint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function ne(gtUint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function ge(gtUint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function gt(gtUint16 a, gtUint16 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function le(gtUint16 a, gtUint16 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function lt(gtUint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }
    function min(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function max(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function decrypt(gtUint16 ct) internal returns (uint16){
          return uint16(ExtendedOperations(MPC_PRECOMPILE).
            Decrypt(bytes1(uint8(MPC_TYPE.SUINT16_T)), gtUint16.unwrap(ct)));
    }

    function mux(gtBool bit, gtUint16 a, gtUint16 b) internal returns (gtUint16){
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function transfer(gtUint16 a, gtUint16 b, gtUint16 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }



    // =========== 32 bit operations ==============

    function validateCiphertext(itUint32 memory input) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            ValidateCiphertext(bytes1(uint8(MPC_TYPE.SUINT32_T)), ctUint32.unwrap(input.ciphertext), input.signature));
    }

    function onBoard(ctUint32 ct) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            OnBoard(bytes1(uint8(MPC_TYPE.SUINT32_T)), ctUint32.unwrap(ct)));
    }

    function offBoard(gtUint32 pt) internal returns (ctUint32) {
          return ctUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            OffBoard(bytes1(uint8(MPC_TYPE.SUINT32_T)), gtUint32.unwrap(pt)));
    }

    function offBoardToUser(gtUint32 pt, address addr) internal returns (ctUint32) {
          return ctUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            OffBoardToUser(bytes1(uint8(MPC_TYPE.SUINT32_T)), gtUint32.unwrap(pt), abi.encodePacked(addr)));
    }
    
    function offBoardCombined(gtUint32 pt, address addr) internal returns (utUint32 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic32(uint32 pt) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            SetPublic(bytes1(uint8(MPC_TYPE.SUINT32_T)), uint256(pt)));
    }

    function rand32() internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).Rand(bytes1(uint8(MPC_TYPE.SUINT32_T))));
    }

    function randBoundedBits32(uint8 numBits) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).RandBoundedBits(bytes1(uint8(MPC_TYPE.SUINT32_T)), numBits));
    }

    function add(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function sub(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function mul(gtUint32 a, gtUint32 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function div(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function rem(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function and(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function or(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function xor(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function shl(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function shr(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }
    function eq(gtUint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function ne(gtUint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function ge(gtUint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function gt(gtUint32 a, gtUint32 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function le(gtUint32 a, gtUint32 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function lt(gtUint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function min(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function max(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function decrypt(gtUint32 ct) internal returns (uint32){
          return uint32(ExtendedOperations(MPC_PRECOMPILE).
            Decrypt(bytes1(uint8(MPC_TYPE.SUINT32_T)), gtUint32.unwrap(ct)));
    }

    function mux(gtBool bit, gtUint32 a, gtUint32 b) internal returns (gtUint32){
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function transfer(gtUint32 a, gtUint32 b, gtUint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }



// =========== 64 bit operations ==============

    function validateCiphertext(itUint64 memory input) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            ValidateCiphertext(bytes1(uint8(MPC_TYPE.SUINT64_T)), ctUint64.unwrap(input.ciphertext), input.signature));
    }

    function onBoard(ctUint64 ct) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            OnBoard(bytes1(uint8(MPC_TYPE.SUINT64_T)), ctUint64.unwrap(ct)));
    }

    function offBoard(gtUint64 pt) internal returns (ctUint64) {
          return ctUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            OffBoard(bytes1(uint8(MPC_TYPE.SUINT64_T)), gtUint64.unwrap(pt)));
    }

    function offBoardToUser(gtUint64 pt, address addr) internal returns (ctUint64) {
          return ctUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            OffBoardToUser(bytes1(uint8(MPC_TYPE.SUINT64_T)), gtUint64.unwrap(pt), abi.encodePacked(addr)));
    }

    function offBoardCombined(gtUint64 pt, address addr) internal returns (utUint64 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic64(uint64 pt) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            SetPublic(bytes1(uint8(MPC_TYPE.SUINT64_T)), uint256(pt)));
    }

    function rand64() internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).Rand(bytes1(uint8(MPC_TYPE.SUINT64_T))));
    }

    function randBoundedBits64(uint8 numBits) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).RandBoundedBits(bytes1(uint8(MPC_TYPE.SUINT64_T)), numBits));
    }

    function add(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function sub(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function mul(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function div(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function rem(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function and(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function or(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function xor(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }
    function shl(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function shr(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function eq(gtUint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function ne(gtUint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function ge(gtUint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function gt(gtUint64 a, gtUint64 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function le(gtUint64 a, gtUint64 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function lt(gtUint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function min(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function max(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function decrypt(gtUint64 ct) internal returns (uint64){
          return uint64(ExtendedOperations(MPC_PRECOMPILE).
            Decrypt(bytes1(uint8(MPC_TYPE.SUINT64_T)), gtUint64.unwrap(ct)));
    }

    function mux(gtBool bit, gtUint64 a, gtUint64 b) internal returns (gtUint64){
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function transfer(gtUint64 a, gtUint64 b, gtUint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(MPC_PRECOMPILE).
            TransferWithAllowance(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, uint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(MPC_PRECOMPILE).
            TransferWithAllowance(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }




// =========== Operations with LHS_PUBLIC parameter ===========
 // =========== 8 bit operations ==============

    function add(uint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function sub(uint8 a, gtUint8 b) internal returns (gtUint8) {
         return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function mul(uint8 a, gtUint8 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function div(uint8 a, gtUint8 b) internal returns (gtUint8) {
          return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }
    function rem(uint8 a, gtUint8 b) internal returns (gtUint8) {
         return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function and(uint8 a, gtUint8 b) internal returns (gtUint8) {
         return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function or(uint8 a, gtUint8 b) internal returns (gtUint8) {
          return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function xor(uint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function shl(uint8 a, gtUint8 b) internal returns (gtUint8) {
          return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function shr(uint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function eq(uint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function ne(uint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function ge(uint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function gt(uint8 a, gtUint8 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function le(uint8 a, gtUint8 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function lt(uint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function min(uint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function max(uint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }


 // =========== 16 bit operations ==============

    function add(uint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function sub(uint16 a, gtUint16 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function mul(uint16 a, gtUint16 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function div(uint16 a, gtUint16 b) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function rem(uint16 a, gtUint16 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function and(uint16 a, gtUint16 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function or(uint16 a, gtUint16 b) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function xor(uint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function shl(uint16 a, gtUint16 b) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function shr(uint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function eq(uint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function ne(uint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function ge(uint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function gt(uint16 a, gtUint16 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function le(uint16 a, gtUint16 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function lt(uint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function min(uint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function max(uint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }


    // =========== 32 bit operations ==============

    function add(uint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function sub(uint32 a, gtUint32 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function mul(uint32 a, gtUint32 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function div(uint32 a, gtUint32 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function rem(uint32 a, gtUint32 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function and(uint32 a, gtUint32 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function or(uint32 a, gtUint32 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function xor(uint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function shl(uint32 a, gtUint32 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function shr(uint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function eq(uint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function ne(uint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function ge(uint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function gt(uint32 a, gtUint32 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function le(uint32 a, gtUint32 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function lt(uint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function min(uint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function max(uint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }


// =========== 64 bit operations ==============

    function add(uint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function sub(uint64 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function mul(uint64 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function div(uint64 a, gtUint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function rem(uint64 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function and(uint64 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function or(uint64 a, gtUint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function xor(uint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function shl(uint64 a, gtUint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function shr(uint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function eq(uint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function ne(uint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function ge(uint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function gt(uint64 a, gtUint64 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function le(uint64 a, gtUint64 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function lt(uint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function min(uint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function max(uint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    
 // =========== Operations with RHS_PUBLIC parameter ===========
 // =========== 8 bit operations ==============

    function add(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function sub(gtUint8 a, uint8 b) internal returns (gtUint8) {
         return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function mul(gtUint8 a, uint8 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function div(gtUint8 a, uint8 b) internal returns (gtUint8) {
          return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function rem(gtUint8 a, uint8 b) internal returns (gtUint8) {
         return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function and(gtUint8 a, uint8 b) internal returns (gtUint8) {
         return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function or(gtUint8 a, uint8 b) internal returns (gtUint8) {
          return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function xor(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function shl(gtUint8 a, uint8 b) internal returns (gtUint8) {
          return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function shr(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function eq(gtUint8 a, uint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function ne(gtUint8 a, uint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }
    
    function ge(gtUint8 a, uint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function gt(gtUint8 a, uint8 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function le(gtUint8 a, uint8 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function lt(gtUint8 a, uint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function min(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function max(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

 // =========== 16 bit operations ==============

    function add(gtUint16 a, uint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function sub(gtUint16 a, uint16 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function mul(gtUint16 a, uint16 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function div(gtUint16 a, uint16 b) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function rem(gtUint16 a, uint16 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function and(gtUint16 a, uint16 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function or(gtUint16 a, uint16 b) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function xor(gtUint16 a, uint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function shl(gtUint16 a, uint16 b) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function shr(gtUint16 a, uint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function eq(gtUint16 a, uint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function ne(gtUint16 a, uint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function ge(gtUint16 a, uint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function gt(gtUint16 a, uint16 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function le(gtUint16 a, uint16 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function lt(gtUint16 a, uint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function min(gtUint16 a, uint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function max(gtUint16 a, uint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }


    // =========== 32 bit operations ==============

    function add(gtUint32 a, uint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function sub(gtUint32 a, uint32 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function mul(gtUint32 a, uint32 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function div(gtUint32 a, uint32 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function rem(gtUint32 a, uint32 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function and(gtUint32 a, uint32 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }
    function or(gtUint32 a, uint32 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function xor(gtUint32 a, uint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function shl(gtUint32 a, uint32 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function shr(gtUint32 a, uint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function eq(gtUint32 a, uint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function ne(gtUint32 a, uint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function ge(gtUint32 a, uint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function gt(gtUint32 a, uint32 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function le(gtUint32 a, uint32 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function lt(gtUint32 a, uint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function min(gtUint32 a, uint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function max(gtUint32 a, uint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }



// =========== 64 bit operations ==============

    function add(gtUint64 a, uint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function sub(gtUint64 a, uint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function mul(gtUint64 a, uint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function div(gtUint64 a, uint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function rem(gtUint64 a, uint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function and(gtUint64 a, uint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function or(gtUint64 a, uint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function xor(gtUint64 a, uint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function shl(gtUint64 a, uint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function shr(gtUint64 a, uint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function eq(gtUint64 a, uint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function ne(gtUint64 a, uint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function ge(gtUint64 a, uint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function gt(gtUint64 a, uint64 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function le(gtUint64 a, uint64 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function lt(gtUint64 a, uint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function min(gtUint64 a, uint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function max(gtUint64 a, uint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    // In the context of a transfer, scalar balances are irrelevant;
	// The only possibility for a scalar value is within the "amount" parameter.
	// Therefore, in this scenario, LHS_PUBLIC signifies a scalar amount, not balance1.

    function transfer(gtUint8 a, gtUint8 b, uint8 amount) internal returns (gtUint8, gtUint8, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint8.unwrap(b), uint256(amount));
        return (gtUint8.wrap(new_a), gtUint8.wrap(new_b), gtBool.wrap(res));
    }
    
    function transfer(gtUint16 a, gtUint16 b, uint16 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint16.unwrap(b), uint256(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint16 b, uint16 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint16.unwrap(b), uint256(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint8 b, uint16 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint8.unwrap(b), uint256(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint32 b, uint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint32.unwrap(b), uint256(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint32 b, uint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint32.unwrap(b), uint256(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint8 b, uint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint8.unwrap(b), uint256(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint32 b, uint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint32.unwrap(b), uint256(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint16 b, uint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint16.unwrap(b), uint256(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint64 b, uint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint64.unwrap(b), uint256(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint64 b, uint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint64.unwrap(b), uint256(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint8 b, uint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint8.unwrap(b), uint256(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint64 b, uint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint64.unwrap(b), uint256(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint16 b, uint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint16.unwrap(b), uint256(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint64 b, uint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint64.unwrap(b), uint256(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint32 b, uint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint32.unwrap(b), uint256(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    
    

 // ================= Cast operation =================
 // =========== 8 - 16 bit operations ==============

    function add(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function add(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function sub(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function sub(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function mul(gtUint8 a, gtUint16 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function mul(gtUint16 a, gtUint8 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function div(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function div(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function rem(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function rem(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function and(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function and(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function or(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function or(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function xor(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function xor(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function shl(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function shl(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function shr(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function shr(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function eq(gtUint8 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function eq(gtUint16 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function ne(gtUint8 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function ne(gtUint16 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function ge(gtUint8 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function ge(gtUint16 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function gt(gtUint8 a, gtUint16 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function gt(gtUint16 a, gtUint8 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function le(gtUint8 a, gtUint16 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

     function le(gtUint16 a, gtUint8 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function lt(gtUint8 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function lt(gtUint16 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function min(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function min(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function max(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function max(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function mux(gtBool bit, gtUint8 a, gtUint16 b) internal returns (gtUint16){
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function mux(gtBool bit, gtUint16 a, gtUint8 b) internal returns (gtUint16){
         return gtUint16.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function transfer(gtUint8 a, gtUint16 b, gtUint16 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint8 b, gtUint16 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint16 b, gtUint8 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint8 b, gtUint8 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint16 b, gtUint8 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }



    // =========== 8- 32 bit operations ==============

    function add(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function add(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function sub(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function sub(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function mul(gtUint8 a, gtUint32 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function mul(gtUint32 a, gtUint8 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function div(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function div(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function rem(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function rem(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function and(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function and(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function or(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function or(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function xor(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function xor(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function shl(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function shl(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function shr(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function shr(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function eq(gtUint8 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function eq(gtUint32 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function ne(gtUint8 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function ne(gtUint32 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function ge(gtUint8 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function ge(gtUint32 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function gt(gtUint8 a, gtUint32 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function gt(gtUint32 a, gtUint8 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function le(gtUint8 a, gtUint32 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function le(gtUint32 a, gtUint8 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function lt(gtUint8 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function lt(gtUint32 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function min(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function min(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function max(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

     function max(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function mux(gtBool bit, gtUint8 a, gtUint32 b) internal returns (gtUint32){
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function mux(gtBool bit, gtUint32 a, gtUint8 b) internal returns (gtUint32){
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function transfer(gtUint8 a, gtUint32 b, gtUint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T,  MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint8 b, gtUint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T,  MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint32 b, gtUint8 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T,  MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint8 b, gtUint8 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T,  MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint32 b, gtUint16 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T,  MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint8 b, gtUint16 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T,  MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint32 b, gtUint8 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T,  MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }


    // =========== 16 - 32 bit operations ==============

    function add(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function add(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function sub(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function sub(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function mul(gtUint16 a, gtUint32 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function mul(gtUint32 a, gtUint16 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function div(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function div(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function rem(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function rem(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function and(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function and(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function or(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function or(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function xor(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function xor(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function shl(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function shl(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
          return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function shr(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function shr(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function eq(gtUint16 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function eq(gtUint32 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function ne(gtUint16 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function ne(gtUint32 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function ge(gtUint16 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function ge(gtUint32 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function gt(gtUint16 a, gtUint32 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function gt(gtUint32 a, gtUint16 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function le(gtUint16 a, gtUint32 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function le(gtUint32 a, gtUint16 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function lt(gtUint16 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function lt(gtUint32 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function min(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function min(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function max(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

     function max(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function mux(gtBool bit, gtUint16 a, gtUint32 b) internal returns (gtUint32){
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function mux(gtBool bit, gtUint32 a, gtUint16 b) internal returns (gtUint32){
         return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function transfer(gtUint16 a, gtUint32 b, gtUint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint16 b, gtUint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint32 b, gtUint8 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint16 b, gtUint8 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint32 b, gtUint16 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint16 b, gtUint16 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint32 b, gtUint16 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T,  MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }



// =========== 8 - 64 bit operations ==============
    
    function add(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function add(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function sub(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function sub(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function mul(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function mul(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function div(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function div(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function rem(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function rem(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function and(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function and(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function or(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function or(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function xor(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function xor(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function shl(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function shl(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function shr(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function shr(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function eq(gtUint8 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function eq(gtUint64 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function ne(gtUint8 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function ne(gtUint64 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function ge(gtUint8 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function ge(gtUint64 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function gt(gtUint8 a, gtUint64 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }
    
    function gt(gtUint64 a, gtUint8 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function le(gtUint8 a, gtUint64 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }
    
    function le(gtUint64 a, gtUint8 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function lt(gtUint8 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function lt(gtUint64 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function min(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function min(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function max(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

     function max(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function mux(gtBool bit, gtUint8 a, gtUint64 b) internal returns (gtUint64){
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function mux(gtBool bit, gtUint64 a, gtUint8 b) internal returns (gtUint64){
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function transfer(gtUint8 a, gtUint64 b, gtUint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint8 b, gtUint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint64.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint64 b, gtUint8 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint8 b, gtUint8 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint64 b, gtUint16 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint8 b, gtUint16 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

     function transfer(gtUint8 a, gtUint64 b, gtUint32 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint8 b, gtUint32 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint64 b, gtUint8 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    // =========== 16 - 64 bit operations ==============
    
    function add(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function add(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function sub(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function sub(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function mul(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function mul(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function div(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function div(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function rem(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function rem(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function and(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function and(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function or(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function or(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function xor(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function xor(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function shl(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function shl(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function shr(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function shr(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function eq(gtUint16 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function eq(gtUint64 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function ne(gtUint16 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function ne(gtUint64 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function ge(gtUint16 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function ge(gtUint64 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function gt(gtUint16 a, gtUint64 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }
    
    function gt(gtUint64 a, gtUint16 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function le(gtUint16 a, gtUint64 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }
    
    function le(gtUint64 a, gtUint16 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function lt(gtUint16 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function lt(gtUint64 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function min(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function min(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function max(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

     function max(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function mux(gtBool bit, gtUint16 a, gtUint64 b) internal returns (gtUint64){
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function mux(gtBool bit, gtUint64 a, gtUint16 b) internal returns (gtUint64){
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function transfer(gtUint16 a, gtUint64 b, gtUint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint16 b, gtUint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint64.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint64 b, gtUint8 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint16 b, gtUint8 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint64 b, gtUint16 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint16 b, gtUint16 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint64 b, gtUint32 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint16 b, gtUint32 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint64 b, gtUint16 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

     // =========== 32 - 64 bit operations ==============
    
    function add(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function add(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function sub(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function sub(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function mul(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function mul(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function div(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function div(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function rem(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function rem(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function and(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function and(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function or(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function or(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function xor(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function xor(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function shl(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function shl(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
          return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function shr(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function shr(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function eq(gtUint32 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function eq(gtUint64 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function ne(gtUint32 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function ne(gtUint64 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function ge(gtUint32 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function ge(gtUint64 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function gt(gtUint32 a, gtUint64 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }
    
    function gt(gtUint64 a, gtUint32 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function le(gtUint32 a, gtUint64 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }
    
    function le(gtUint64 a, gtUint32 b) internal returns (gtBool) {
         return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function lt(gtUint32 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function lt(gtUint64 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function min(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function min(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function max(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

     function max(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function mux(gtBool bit, gtUint32 a, gtUint64 b) internal returns (gtUint64){
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function mux(gtBool bit, gtUint64 a, gtUint32 b) internal returns (gtUint64){
         return gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function transfer(gtUint32 a, gtUint64 b, gtUint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint32 b, gtUint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint64.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint64 b, gtUint8 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint32 b, gtUint8 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint64 b, gtUint16 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint32 b, gtUint16 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint64 b, gtUint32 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint32 b, gtUint32 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint64 b, gtUint32 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(MPC_PRECOMPILE).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }
}