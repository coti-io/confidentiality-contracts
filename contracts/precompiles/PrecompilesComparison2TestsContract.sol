// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract PrecompilesComparison2TestsContract {

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
        gtBool res16_16;
        gtBool res8_16;
        gtBool res16_8;
    }

    struct Check32 {
        gtBool res32_32;
        gtBool res8_32;
        gtBool res32_8;
        gtBool res16_32;
        gtBool res32_16;
    }

    struct Check64 {
        gtBool res64_64;
        gtBool res8_64;
        gtBool res64_8;
        gtBool res16_64;
        gtBool res64_16;
        gtBool res32_64;
        gtBool res64_32;
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

    bool result;

    function getResult() public view returns (bool) {
        return result;
    }

    function decryptAndCompareResults16(Check16 memory check16) public returns (bool){

        // Calculate the result
        bool result = MpcCore.decrypt(check16.res16_16);

        require(result == MpcCore.decrypt(check16.res8_16) && result == MpcCore.decrypt(check16.res16_8), 
                                "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return result;
    }

    function decryptAndCompareResults32(Check32 memory check32) public returns (bool){

        // Calculate the result
        bool result = MpcCore.decrypt(check32.res32_32);

        require(result == MpcCore.decrypt(check32.res8_32) && result == MpcCore.decrypt(check32.res32_8) 
                && result == MpcCore.decrypt(check32.res32_16) && result == MpcCore.decrypt(check32.res16_32), 
                "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return result;
    }

    function decryptAndCompareResults64(Check64 memory check64) public returns (bool){

        // Calculate the result
        bool result = MpcCore.decrypt(check64.res64_64);

        require(result == MpcCore.decrypt(check64.res8_64) && result == MpcCore.decrypt(check64.res64_8) 
                && result == MpcCore.decrypt(check64.res64_16) && result == MpcCore.decrypt(check64.res16_64)
                && result == MpcCore.decrypt(check64.res64_32) && result == MpcCore.decrypt(check64.res32_64), 
                "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return result;
    }

    function eqTest(uint8 a, uint8 b) public returns (bool) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        result =  MpcCore.decrypt(MpcCore.eq(castingValues.a8_s, castingValues.b8_s));
    
        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.eq(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.eq(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.eq(castingValues.a16_s, castingValues.b8_s);
        bool res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "eqTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.eq(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.eq(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.eq(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.eq(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.eq(castingValues.a32_s, castingValues.b16_s);
        bool res32 = decryptAndCompareResults32(check32);
        require(result == res32, "eqTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.eq(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.eq(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.eq(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.eq(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.eq(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.eq(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.eq(castingValues.a64_s, castingValues.b32_s);
        bool res64 = decryptAndCompareResults64(check64);
        require(result == res64, "eqTest: cast 64 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.eq(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.eq(castingValues.a8_s, b)),
                "eqTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.eq(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.eq(castingValues.a16_s, b)),
                "eqTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.eq(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.eq(castingValues.a32_s, b)),
                "eqTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.eq(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.eq(castingValues.a64_s, b)),
                "eqTest: test 64 bits with scalar failed");

        return result;
    }

    function neTest(uint8 a, uint8 b) public returns (bool) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        result =  MpcCore.decrypt(MpcCore.ne(castingValues.a8_s, castingValues.b8_s));
    
        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.ne(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.ne(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.ne(castingValues.a16_s, castingValues.b8_s);
        bool res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "neTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.ne(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.ne(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.ne(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.ne(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.ne(castingValues.a32_s, castingValues.b16_s);
        bool res32 = decryptAndCompareResults32(check32);
        require(result == res32, "neTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.ne(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.ne(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.ne(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.ne(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.ne(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.ne(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.ne(castingValues.a64_s, castingValues.b32_s);
        bool res64 = decryptAndCompareResults64(check64);
        require(result == res64, "neTest: cast 64 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.ne(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.ne(castingValues.a8_s, b)),
                "neTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ne(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.ne(castingValues.a16_s, b)),
                "neTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ne(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.ne(castingValues.a32_s, b)),
                "neTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ne(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.ne(castingValues.a64_s, b)),
                "neTest: test 64 bits with scalar failed");

        return result;
    }

    function geTest(uint8 a, uint8 b) public returns (bool) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        result =  MpcCore.decrypt(MpcCore.ge(castingValues.a8_s, castingValues.b8_s));
    
        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.ge(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.ge(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.ge(castingValues.a16_s, castingValues.b8_s);
        bool res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "geTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.ge(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.ge(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.ge(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.ge(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.ge(castingValues.a32_s, castingValues.b16_s);
        bool res32 = decryptAndCompareResults32(check32);
        require(result == res32, "geTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.ge(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.ge(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.ge(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.ge(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.ge(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.ge(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.ge(castingValues.a64_s, castingValues.b32_s);
        bool res64 = decryptAndCompareResults64(check64);
        require(result == res64, "geTest: cast 64 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.ge(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.ge(castingValues.a8_s, b)),
                "geTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ge(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.ge(castingValues.a16_s, b)),
                "geTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ge(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.ge(castingValues.a32_s, b)),
                "geTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ge(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.ge(castingValues.a64_s, b)),
                "geTest: test 64 bits with scalar failed");

        return result;
    }

}