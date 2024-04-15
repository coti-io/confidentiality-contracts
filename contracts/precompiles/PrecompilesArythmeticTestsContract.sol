// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract PrecompilesArythmeticTestsContract {

    struct AllGTCastingValues {
        gtUint8 a8_s;
        gtUint8 b8_s;
        gtUint16 a16_s;
        gtUint16 b16_s;
        gtUint32 a32_s;
        gtUint32 b32_s;
        gtUint64 a64_s;
        gtUint64 b64_s;
    }

    struct Check16 {
        gtUint16 res16_16;
        gtUint16 res8_16;
        gtUint16 res16_8;
    }

    struct CheckMul16 {
        gtUint32 res16_16;
        gtUint32 res8_16;
        gtUint32 res16_8;
    }

    struct Check32 {
        gtUint32 res32_32;
        gtUint32 res8_32;
        gtUint32 res32_8;
        gtUint32 res16_32;
        gtUint32 res32_16;
    }

    struct CheckMul32 {
        gtUint64 res32_32;
        gtUint64 res8_32;
        gtUint64 res32_8;
        gtUint64 res16_32;
        gtUint64 res32_16;
    }

    struct Check64 {
        gtUint64 res64_64;
        gtUint64 res8_64;
        gtUint64 res64_8;
        gtUint64 res16_64;
        gtUint64 res64_16;
        gtUint64 res32_64;
        gtUint64 res64_32;
    }

    uint8 result;
    uint16 result16;

    function getResult() public view returns (uint8) {
        return result;
    }

    function getResult16() public view returns (uint16) {
        return result16;
    }

    function setPublicValues(AllGTCastingValues memory castingValues, uint8 a, uint8 b) public{
        castingValues.a8_s = MpcCore.setPublic8(a);
        castingValues.b8_s = MpcCore.setPublic8(b);
        castingValues.a16_s =  MpcCore.setPublic16(a);
        castingValues.b16_s =  MpcCore.setPublic16(b);
        castingValues.a32_s =  MpcCore.setPublic32(a);
        castingValues.b32_s =  MpcCore.setPublic32(b);
        castingValues.a64_s =  MpcCore.setPublic64(a);
        castingValues.b64_s =  MpcCore.setPublic64(b);
    }

    function decryptAndCompareResults16(Check16 memory check16) public returns (uint16){

        // Calculate the result
        uint16 result = MpcCore.decrypt(check16.res16_16);

        require(result == MpcCore.decrypt(check16.res8_16) && result == MpcCore.decrypt(check16.res16_8), 
                                "decryptAndCompareAllResults: Failed to decrypt and compare all results");
        return result;
    }

    function decryptAndCompareResults32(Check32 memory check32) public returns (uint32){

        // Calculate the result
        uint32 result = MpcCore.decrypt(check32.res32_32);

        require(result == MpcCore.decrypt(check32.res8_32) && result == MpcCore.decrypt(check32.res32_8) 
                && result == MpcCore.decrypt(check32.res32_16) && result == MpcCore.decrypt(check32.res16_32), 
                "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return result;
    }

    function decryptAndCompareResults64(Check64 memory check64) public returns (uint64){

        // Calculate the result
        uint64 result = MpcCore.decrypt(check64.res64_64);

        require(result == MpcCore.decrypt(check64.res8_64) && result == MpcCore.decrypt(check64.res64_8) 
                && result == MpcCore.decrypt(check64.res64_16) && result == MpcCore.decrypt(check64.res16_64)
                && result == MpcCore.decrypt(check64.res64_32) && result == MpcCore.decrypt(check64.res32_64), 
                "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return result;
    }

    function addTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        result =  MpcCore.decrypt(MpcCore.add(castingValues.a8_s, castingValues.b8_s));
    
        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.add(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.add(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.add(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "addTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.add(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.add(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.add(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.add(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.add(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "addTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.add(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.add(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.add(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.add(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.add(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.add(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.add(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "addTest: cast 64 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.add(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.add(castingValues.a8_s, b)),
                "addTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.add(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.add(castingValues.a16_s, b)),
                "addTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.add(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.add(castingValues.a32_s, b)),
                "addTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.add(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.add(castingValues.a64_s, b)),
                "addTest: test 64 bits with scalar failed");

        return result;
    }

    function subTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        result =  MpcCore.decrypt(MpcCore.sub(castingValues.a8_s, castingValues.b8_s));
        
        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.sub(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.sub(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.sub(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "subTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.sub(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.sub(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.sub(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.sub(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.sub(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "subTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.sub(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.sub(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.sub(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.sub(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.sub(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.sub(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.sub(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "subTest: cast 64 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.sub(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.sub(castingValues.a8_s, b)),
                "subTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.sub(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.sub(castingValues.a16_s, b)),
                "subTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.sub(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.sub(castingValues.a32_s, b)),
                "subTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.sub(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.sub(castingValues.a64_s, b)),
                "subTest: test 64 bits with scalar failed");

        return result;
    }

    function mulTest(uint8 a, uint8 b) public returns (uint16) {
        AllGTCastingValues memory castingValues;
        CheckMul16 memory checkMul16;
        CheckMul32 memory checkMul32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        result16 = MpcCore.decrypt(MpcCore.mul(castingValues.a8_s, castingValues.b8_s));
        
        // Calculate the result with casting to 16
        checkMul16.res16_16 = MpcCore.mul(castingValues.a16_s, castingValues.b16_s);
        checkMul16.res8_16 = MpcCore.mul(castingValues.a8_s, castingValues.b16_s);
        checkMul16.res16_8 = MpcCore.mul(castingValues.a16_s, castingValues.b8_s);
        require(result16 == MpcCore.decrypt(checkMul16.res16_16) && result16 == MpcCore.decrypt(checkMul16.res8_16)
                && result16 == MpcCore.decrypt(checkMul16.res16_8), "mulTest: cast 16 failed");
        
        // Calculate the result with casting to 32
        checkMul32.res32_32 = MpcCore.mul(castingValues.a32_s, castingValues.b32_s);
        checkMul32.res8_32 = MpcCore.mul(castingValues.a8_s, castingValues.b32_s);
        checkMul32.res32_8 = MpcCore.mul(castingValues.a32_s, castingValues.b8_s);
        checkMul32.res16_32 = MpcCore.mul(castingValues.a16_s, castingValues.b32_s);
        checkMul32.res32_16 = MpcCore.mul(castingValues.a32_s, castingValues.b16_s);
        require(result16 == MpcCore.decrypt(checkMul32.res32_32) && result16 == MpcCore.decrypt(checkMul32.res8_32) 
                && result16 == MpcCore.decrypt(checkMul32.res32_8) && result16 == MpcCore.decrypt(checkMul32.res32_16) 
                && result16 == MpcCore.decrypt(checkMul32.res16_32), "mulTest: cast 32 failed");
        
        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.mul(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.mul(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.mul(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.mul(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.mul(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.mul(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.mul(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result16 == res64, "mulTest: cast 64 failed");
        
        // Check the result with scalar
        require(result16 == MpcCore.decrypt(MpcCore.mul(a, castingValues.b8_s)) && result16 == MpcCore.decrypt(MpcCore.mul(castingValues.a8_s, b)),
                "mulTest: test 8 bits with scalar failed");
        require(result16 == MpcCore.decrypt(MpcCore.mul(a, castingValues.b16_s)) && result16 == MpcCore.decrypt(MpcCore.mul(castingValues.a16_s, b)),
                "mulTest: test 16 bits with scalar failed");
        require(result16 == MpcCore.decrypt(MpcCore.mul(a, castingValues.b32_s)) && result16 == MpcCore.decrypt(MpcCore.mul(castingValues.a32_s, b)),
                "mulTest: test 32 bits with scalar failed");
        require(result16 == MpcCore.decrypt(MpcCore.mul(a, castingValues.b64_s)) && result16 == MpcCore.decrypt(MpcCore.mul(castingValues.a64_s, b)),
                "mulTest: test 64 bits with scalar failed");

        return result16;
    }
}