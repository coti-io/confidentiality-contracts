// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface ExtendedOperations {

    function OnBoard(bytes1 metaData, uint256 ct) external returns (uint256 result);
    function OffBoard(bytes1 metaData, uint256 ct) external returns (uint256 result);
    function OffBoardToUser(bytes1 metaData, uint256 ct, bytes calldata addr) external returns (uint256 result);
    function SetPublic(bytes1 metaData, uint256 ct) external returns (uint256 result);
    function Rand(bytes1 metaData) external returns (uint256 result);
    function RandBoundedBits(bytes1 metaData, uint8 numBits) external returns (uint256 result);

    function Add(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Sub(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Mul(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Div(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Rem(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function And(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Or(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Xor(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Shl(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Shr(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Eq(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Ne(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Ge(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Gt(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Le(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Lt(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Min(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Max(bytes3 metaData, uint256 lhs, uint256 rhs) external returns (uint256 result);
    function Decrypt(bytes1 metaData, uint256 a) external returns (uint256 result);
    function Mux(bytes3 metaData, uint256 bit, uint256 a,uint256 b) external returns (uint256 result);
    function Not(bytes1 metaData, uint256 a) external returns (uint256 result);
    function Transfer(bytes4 metaData, uint256 a, uint256 b, uint256 amount) external returns (uint256 new_a, uint256 new_b, uint256 res);
    function TransferWithAllowance(bytes4 metaData, uint256 a, uint256 b, uint256 amount, uint256 allowance) external returns (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance);
    function ValidateCiphertext(bytes1 metaData, uint256 ciphertext, bytes calldata signature) external returns (uint256 result);
    function GetUserKey(bytes calldata signedEK) external view returns (bytes memory encryptedKey);
}

address constant MPC_PRECOMPILE = address(0x0000000000000000000000000000000000000064);

