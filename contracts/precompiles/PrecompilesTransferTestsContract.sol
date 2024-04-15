// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract PrecompilesTransferTestsContract {

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

    struct AllAmountValues {
        gtUint8 amount8_s;
        gtUint16 amount16_s;
        gtUint32 amount32_s;
        gtUint64 amount64_s;
        uint8 amount;
    }

    uint8 newA;
    uint8 newB;
    bool result;

    function getResults() public view returns (uint8, uint8, bool) {
        return (newA, newB, result);
    }
    

    function computeAndChekTransfer16(AllGTCastingValues memory allGTCastingValues, AllAmountValues memory allAmountValues, uint8 new_a, uint8 new_b, bool res) public {
        (gtUint16 newA_s, gtUint16 newB_s, gtBool res_s) = MpcCore.transfer(allGTCastingValues.a16_s, allGTCastingValues.b16_s, allAmountValues.amount8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 16 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a8_s, allGTCastingValues.b16_s, allAmountValues.amount8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 16 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a16_s, allGTCastingValues.b8_s, allAmountValues.amount8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 16 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a16_s, allGTCastingValues.b16_s, allAmountValues.amount16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 16 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a8_s, allGTCastingValues.b16_s, allAmountValues.amount16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 16 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a16_s, allGTCastingValues.b8_s, allAmountValues.amount16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 16 failed");
    }

    function computeAndChekTransfer32(AllGTCastingValues memory allGTCastingValues, AllAmountValues memory allAmountValues, uint8 new_a, uint8 new_b, bool res) public {

        // Check all options for casting to 32 while amount is 32
        (gtUint32 newA_s, gtUint32 newB_s, gtBool res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b32_s, allAmountValues.amount32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a8_s, allGTCastingValues.b32_s, allAmountValues.amount32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b8_s, allAmountValues.amount32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a16_s, allGTCastingValues.b32_s, allAmountValues.amount32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b16_s, allAmountValues.amount32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");


        // Check all options for casting to 32 while amount is 8
        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b32_s, allAmountValues.amount8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a8_s, allGTCastingValues.b32_s, allAmountValues.amount8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b8_s, allAmountValues.amount8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a16_s, allGTCastingValues.b32_s, allAmountValues.amount8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b16_s, allAmountValues.amount8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        // Check all options for casting to 32 while amount is 16
        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b32_s, allAmountValues.amount16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a8_s, allGTCastingValues.b32_s, allAmountValues.amount16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b8_s, allAmountValues.amount16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a16_s, allGTCastingValues.b32_s, allAmountValues.amount16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b16_s, allAmountValues.amount16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");
    }

    function computeAndChekTransfer64(AllGTCastingValues memory allGTCastingValues, AllAmountValues memory allAmountValues, uint8 new_a, uint8 new_b, bool res) public {

        // Check all options for casting to 64 while amount is 64
        (gtUint64 newA_s, gtUint64 newB_s, gtBool res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b64_s, allAmountValues.amount64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a8_s, allGTCastingValues.b64_s, allAmountValues.amount64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b8_s, allAmountValues.amount64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a16_s, allGTCastingValues.b64_s, allAmountValues.amount64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b16_s, allAmountValues.amount64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b64_s, allAmountValues.amount64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b32_s, allAmountValues.amount64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");


        // Check all options for casting to 64 while amount is 32
        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b64_s, allAmountValues.amount32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a8_s, allGTCastingValues.b64_s, allAmountValues.amount32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b8_s, allAmountValues.amount32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a16_s, allGTCastingValues.b64_s, allAmountValues.amount32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b16_s, allAmountValues.amount32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b64_s, allAmountValues.amount32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b32_s, allAmountValues.amount32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 32 failed");


        // Check all options for casting to 64 while amount is 8
        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b64_s, allAmountValues.amount8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 8 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a8_s, allGTCastingValues.b64_s, allAmountValues.amount8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 8 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b8_s, allAmountValues.amount8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 8 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a16_s, allGTCastingValues.b64_s, allAmountValues.amount8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 8 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b16_s, allAmountValues.amount8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 8 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b64_s, allAmountValues.amount8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 8 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b32_s, allAmountValues.amount8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 8 failed");
       
        // Check all options for casting to 64 while amount is 16
        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b64_s, allAmountValues.amount16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 16 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a8_s, allGTCastingValues.b64_s, allAmountValues.amount16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 16 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b8_s, allAmountValues.amount16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 16 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a16_s, allGTCastingValues.b64_s, allAmountValues.amount16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 16 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b16_s, allAmountValues.amount16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 16 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a32_s, allGTCastingValues.b64_s, allAmountValues.amount16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 16 failed");

        (newA_s, newB_s, res_s) = MpcCore.transfer(allGTCastingValues.a64_s, allGTCastingValues.b32_s, allAmountValues.amount16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 16 failed");
    }


    function transferTest(uint8 a, uint8 b, uint8 amount) public returns (uint8, uint8, bool) {
        AllGTCastingValues memory allGTCastingValues;
        AllAmountValues memory allAmountValues;
        allGTCastingValues.a8_s = MpcCore.setPublic8(a);
        allGTCastingValues.b8_s = MpcCore.setPublic8(b);
        allGTCastingValues.a16_s =  MpcCore.setPublic16(a);
        allGTCastingValues.b16_s =  MpcCore.setPublic16(b);
        allGTCastingValues.a32_s =  MpcCore.setPublic32(a);
        allGTCastingValues.b32_s =  MpcCore.setPublic32(b);
        allGTCastingValues.a64_s =  MpcCore.setPublic64(a);
        allGTCastingValues.b64_s =  MpcCore.setPublic64(b);
        allAmountValues.amount8_s = MpcCore.setPublic8(amount);
        allAmountValues.amount16_s = MpcCore.setPublic16(amount);
        allAmountValues.amount32_s = MpcCore.setPublic32(amount);
        allAmountValues.amount64_s = MpcCore.setPublic64(amount);
        allAmountValues.amount = amount;
        
        // Calculate the expected result 
        (gtUint8 newA_s, gtUint8 newB_s, gtBool res_s) = MpcCore.transfer(allGTCastingValues.a8_s, allGTCastingValues.b8_s, allAmountValues.amount8_s);
        newA = MpcCore.decrypt(newA_s);
        newB = MpcCore.decrypt(newB_s);
        result = MpcCore.decrypt(res_s);

        // Calculate the result with casting to 16
        computeAndChekTransfer16(allGTCastingValues, allAmountValues, newA, newB, result);

        // Calculate the result with casting to 32
        computeAndChekTransfer32(allGTCastingValues, allAmountValues, newA, newB, result);

        // Calculate the result with casting to 64
        computeAndChekTransfer64(allGTCastingValues, allAmountValues, newA, newB, result);
    
        return (newA, newB, result); 
    }

}