// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract PrecompilesTransferScalarTestsContract {

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

    uint8 new_a;
    uint8 new_b;
    bool res;

    function getResults() public view returns (uint8, uint8, bool) {
        return (new_a, new_b, res);
    }

    function computeAndChekTransfer16(AllGTCastingValues memory allGTCastingValues, uint8 new_a, uint8 new_b, bool res, uint8 amount) public {
        
        // Check all options for casting to 16 while amount is scalar
        (gtUint16 newA_s, gtUint16 newB_s, gtBool res_s) = MpcCore.transfer(allGTCastingValues.a16_s, allGTCastingValues.b16_s, amount);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a8_s, allGTCastingValues.b16_s, amount);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a16_s, allGTCastingValues.b8_s, amount);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: check scalar failed");
    }

    function computeAndChekTransfer32(AllGTCastingValues memory allGTCastingValues, uint8 new_a, uint8 new_b, bool res, uint8 amount) public {

        // Check all options for casting to 32 while amount is scalar
        (gtUint32 newA_s, gtUint32 newB_s, gtBool res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b32_s, amount);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a8_s, allGTCastingValues.b32_s, amount);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b8_s, amount);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a16_s, allGTCastingValues.b32_s, amount);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b16_s, amount);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: check scalar failed");
    }

    function computeAndChekTransfer64(AllGTCastingValues memory allGTCastingValues, uint8 new_a, uint8 new_b, bool res, uint8 amount) public {

        // Check all options for casting to 64 while amount is scalar
        (gtUint64 newA_s, gtUint64 newB_s, gtBool res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b64_s, amount);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a8_s, allGTCastingValues.b64_s, amount);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b8_s, amount);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a16_s, allGTCastingValues.b64_s, amount);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b16_s, amount);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b64_s, amount);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b32_s, amount);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: check scalar failed");
    }


    function transferScalarTest(uint8 a, uint8 b, uint8 amount) public returns (uint8, uint8, bool) {
        AllGTCastingValues memory allGTCastingValues;
        allGTCastingValues.a8_s = MpcCore.setPublic8(a);
        allGTCastingValues.b8_s = MpcCore.setPublic8(b);
        allGTCastingValues.a16_s =  MpcCore.setPublic16(a);
        allGTCastingValues.b16_s =  MpcCore.setPublic16(b);
        allGTCastingValues.a32_s =  MpcCore.setPublic32(a);
        allGTCastingValues.b32_s =  MpcCore.setPublic32(b);
        allGTCastingValues.a64_s =  MpcCore.setPublic64(a);
        allGTCastingValues.b64_s =  MpcCore.setPublic64(b);
        
        // Calculate the expected result 
        (gtUint8 newA_s, gtUint8 newB_s, gtBool res_s) = MpcCore.transfer(allGTCastingValues.a8_s, allGTCastingValues.b8_s, amount);
        new_a =  MpcCore.decrypt(newA_s);
        new_b =  MpcCore.decrypt(newB_s);
        res =  MpcCore.decrypt(res_s);

        // Calculate the result with casting to 16
        computeAndChekTransfer16(allGTCastingValues, new_a, new_b, res, amount);

        // Calculate the result with casting to 32
        computeAndChekTransfer32(allGTCastingValues, new_a, new_b, res, amount);

        // Calculate the result with casting to 64
        computeAndChekTransfer64(allGTCastingValues, new_a, new_b, res, amount);
    
        return (new_a, new_b, res); 
    }

}