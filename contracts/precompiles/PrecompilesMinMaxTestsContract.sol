// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract PrecompilesMinMaxTestsContract {

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

    struct Check32 {
        gtUint32 res32_32;
        gtUint32 res8_32;
        gtUint32 res32_8;
        gtUint32 res16_32;
        gtUint32 res32_16;
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

    uint8 result;

    function getResult() public view returns (uint8) {
        return result;
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

    function minTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        result =  MpcCore.decrypt(MpcCore.min(castingValues.a8_s, castingValues.b8_s));
    
        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.min(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.min(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.min(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "minTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.min(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.min(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.min(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.min(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.min(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "minTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.min(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.min(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.min(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.min(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.min(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.min(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.min(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "minTest: cast 64 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.min(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.min(castingValues.a8_s, b)),
                "minTest: test 8 bits with scalar failed");
        require(res16 == MpcCore.decrypt(MpcCore.min(a, castingValues.b16_s)) && res16 == MpcCore.decrypt(MpcCore.min(castingValues.a16_s, b)),
                "minTest: test 16 bits with scalar failed");
        require(res32 == MpcCore.decrypt(MpcCore.min(a, castingValues.b32_s)) && res32 == MpcCore.decrypt(MpcCore.min(castingValues.a32_s, b)),
                "minTest: test 32 bits with scalar failed");
        require(res64 == MpcCore.decrypt(MpcCore.min(a, castingValues.b64_s)) && res64 == MpcCore.decrypt(MpcCore.min(castingValues.a64_s, b)),
                "minTest: test 64 bits with scalar failed");

        return result;
    }

    function maxTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        result =  MpcCore.decrypt(MpcCore.max(castingValues.a8_s, castingValues.b8_s));
    
        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.max(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.max(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.max(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "maxTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.max(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.max(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.max(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.max(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.max(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "maxTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.max(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.max(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.max(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.max(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.max(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.max(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.max(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "maxTest: cast 64 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.max(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.max(castingValues.a8_s, b)),
                "minTest: test 8 bits with scalar failed");
        require(res16 == MpcCore.decrypt(MpcCore.max(a, castingValues.b16_s)) && res16 == MpcCore.decrypt(MpcCore.max(castingValues.a16_s, b)),
                "minTest: test 16 bits with scalar failed");
        require(res32 == MpcCore.decrypt(MpcCore.max(a, castingValues.b32_s)) && res32 == MpcCore.decrypt(MpcCore.max(castingValues.a32_s, b)),
                "minTest: test 32 bits with scalar failed");
        require(res64 == MpcCore.decrypt(MpcCore.max(a, castingValues.b64_s)) && res64 == MpcCore.decrypt(MpcCore.max(castingValues.a64_s, b)),
                "minTest: test 64 bits with scalar failed");

        return result;
    }

}