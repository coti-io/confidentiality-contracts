// SPDX-License-Identifier: MIT

// For more info, see: https://docs.ethers.org

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

pragma solidity ^0.8.19;

// Returns the decimal string representation of value
function itoa(uint value) pure returns (string memory) {
    // Count the length of the decimal string representation
    uint length = 1;
    uint v = value;
    while ((v /= 10) != 0) {
        length++;
    }

    // Allocated enough bytes
    bytes memory result = new bytes(length);

    // Place each ASCII string character in the string,
    // right to left
    while (true) {
        length--;

        // The ASCII value of the modulo 10 value
        result[length] = bytes1(uint8(0x30 + (value % 10)));

        value /= 10;

        if (length == 0) {
            break;
        }
    }

    return string(result);
}

contract RecoverMessage {
    using ECDSA for bytes32;

    // This is the EIP-2098 compact representation, which reduces gas costs
    struct SignatureCompact {
        bytes32 r;
        bytes32 yParityAndS;
    }

    // This is an expaned Signature representation
    struct SignatureExpanded {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    // Helper function
    function _ecrecover(
        string memory message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address) {
        // Compute the EIP-191 prefixed message
        bytes memory prefixedMessage = abi.encodePacked(
            "\x19Ethereum Signed Message:\n",
            itoa(bytes(message).length),
            message
        );

        // Compute the message digest
        bytes32 digest = keccak256(prefixedMessage);

        // Use the native ecrecover provided by the EVM
        return ecrecover(digest, v, r, s);
    }

    // Recover the address from an EIP-2098 compact Signature, which packs the bit for
    // v into an unused bit within s, which saves gas overall, costing a little extra
    // in computation, but saves far more in calldata length.
    //
    // This Signature format is 64 bytes in length.
    function recoverStringFromCompact(
        string calldata message,
        SignatureCompact calldata sig
    ) public pure returns (address) {
        // Decompose the EIP-2098 signature (the struct is 64 bytes in length)
        uint8 v = 27 + uint8(uint256(sig.yParityAndS) >> 255);
        bytes32 s = bytes32((uint256(sig.yParityAndS) << 1) >> 1);

        return _ecrecover(message, v, sig.r, s);
    }

    // Recover the address from the expanded Signature struct.
    //
    // This Signature format is 96 bytes in length.
    function recoverStringFromExpanded(
        string calldata message,
        SignatureExpanded calldata sig
    ) public pure returns (address) {
        // The v, r and s are included directly within the struct, which is 96 bytes in length
        return _ecrecover(message, sig.v, sig.r, sig.s);
    }

    // Recover the address from a v, r and s passed directly into the method.
    //
    // This Signature format is 96 bytes in length.
    function recoverStringFromVRS(
        string calldata message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public pure returns (address) {
        // The v, r and s are included directly within the struct, which is 96 bytes in length
        return _ecrecover(message, v, r, s);
    }

    // Recover the address from a raw signature. The signature is 65 bytes, which when
    // ABI encoded is 160 bytes long (a pointer, a length and the padded 3 words of data).
    //
    // When using raw signatures, some tools return the v as 0 or 1. In this case you must
    // add 27 to that value as v must be either 27 or 28.
    //
    // This Signature format is 65 bytes of data, but when ABI encoded is 160 bytes in length;
    // a pointer (32 bytes), a length (32 bytes) and the padded 3 words of data (96 bytes).
    function recoverStringFromRaw(
        string calldata message,
        bytes calldata sig
    ) public pure returns (address) {
        // Sanity check before using assembly
        require(sig.length == 65, "invalid signature");

        // Decompose the raw signature into r, s and v (note the order)
        uint8 v;
        bytes32 r;
        bytes32 s;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 0x20))
            v := calldataload(add(sig.offset, 0x21))
        }

        return _ecrecover(message, v, r, s);
    }

    // This is provided as a quick example for those that only need to recover a signature
    // for a signed hash (highly discouraged; but common), which means we can hardcode the
    // length in the prefix. This means we can drop the itoa and _ecrecover functions above.
    function recoverHashFromCompact(
        bytes32 hash,
        SignatureCompact calldata sig
    ) public pure returns (address) {
        bytes memory prefixedMessage = abi.encodePacked(
            // Notice the length of the message is hard-coded to 32
            // here -----------------------v
            "\x19Ethereum Signed Message:\n32",
            hash
        );

        bytes32 digest = keccak256(prefixedMessage);

        // Decompose the EIP-2098 signature
        uint8 v = 27 + uint8(uint256(sig.yParityAndS) >> 255);
        bytes32 s = bytes32((uint256(sig.yParityAndS) << 1) >> 1);

        return ecrecover(digest, v, sig.r, s);
    }

    function recoverECDSA(
        bytes32 hash,
        bytes calldata signature
    ) public pure returns (address) {
        return
            ECDSA.recover(
                MessageHashUtils.toEthSignedMessageHash(hash),
                signature
            );
    }
}
