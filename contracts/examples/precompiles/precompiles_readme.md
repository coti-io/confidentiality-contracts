# PrecompilesArythmeticTestsContract.sol

Performs arithmetic operations (addition, subtraction, and multiplication) on different bit-length values and ensures consistency across various data types.

## Structures
The contract defines several structures to hold values and results for different bit-lengths:

- `AllGTCastingValues`: Holds 8-bit, 16-bit, 32-bit, and 64-bit unsigned integers.
- `Check16`, `Check32`, `Check64`: Hold the results of operations for different bit-length combinations.
- `CheckMul16`, `CheckMul32`: Hold the multiplication results for different bit-length combinations.

## State Variables
- `result`: Stores an 8-bit result.
- `result16`: Stores a 16-bit result.

## Functions
1. **`getResult`**: Returns the 8-bit result.
2. **`getResult16`**: Returns the 16-bit result.
3. **`setPublicValues`**: Sets the public values for different bit-lengths using `MpcCore.setPublic` methods.
4. **`decryptAndCompareResults16`**: Decrypts and compares 16-bit results to ensure consistency.
5. **`decryptAndCompareResults32`**: Decrypts and compares 32-bit results to ensure consistency.
6. **`decryptAndCompareResults64`**: Decrypts and compares 64-bit results to ensure consistency.

## Arithmetic Operations
1. **`addTest`**: Performs addition on the given 8-bit values and checks consistency across different bit-lengths:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the addition results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

2. **`subTest`**: Similar to `addTest`, but performs subtraction:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the subtraction results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

3. **`mulTest`**: Similar to `addTest`, but performs multiplication:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the multiplication results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

## Core Operations
The contract relies on the `MpcCore` library for:
- Setting public values (`setPublic8`, `setPublic16`, `setPublic32`, `setPublic64`).
- Performing arithmetic operations (`add`, `sub`, `mul`).
- Decrypting results (`decrypt`).

## Summary
The contract ensures that arithmetic operations on various bit-length values are consistent and correct by performing the operations, decrypting the results, and comparing them across different types and combinations. This can be particularly useful for testing and validating the correctness of arithmetic operations in a decentralized environment.

# PrecompilesBitwiseTestsContract.sol

Performs bitwise operations (AND, OR, XOR) on different bit-length values and ensures consistency across various data types.

## Structures
The contract defines several structures to hold values and results for different bit-lengths:

- `AllGTCastingValues`: Holds 8-bit, 16-bit, 32-bit, and 64-bit unsigned integers.
- `Check16`, `Check32`, `Check64`: Hold the results of operations for different bit-length combinations.

## State Variables
- `result`: Stores an 8-bit result.

## Functions
1. **`getResult`**: Returns the 8-bit result.
2. **`setPublicValues`**: Sets the public values for different bit-lengths using `MpcCore.setPublic` methods.
3. **`decryptAndCompareResults16`**: Decrypts and compares 16-bit results to ensure consistency.
4. **`decryptAndCompareResults32`**: Decrypts and compares 32-bit results to ensure consistency.
5. **`decryptAndCompareResults64`**: Decrypts and compares 64-bit results to ensure consistency.

## Bitwise Operations
1. **`andTest`**: Performs bitwise AND on the given 8-bit values and checks consistency across different bit-lengths:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the AND results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

2. **`orTest`**: Similar to `andTest`, but performs bitwise OR:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the OR results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

3. **`xorTest`**: Similar to `andTest`, but performs bitwise XOR:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the XOR results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

## Core Operations
The contract relies on the `MpcCore` library for:
- Setting public values (`setPublic8`, `setPublic16`, `setPublic32`, `setPublic64`).
- Performing bitwise operations (`and`, `or`, `xor`).
- Decrypting results (`decrypt`).

## Summary
The contract ensures that bitwise operations on various bit-length values are consistent and correct by performing the operations, decrypting the results, and comparing them across different types and combinations. This can be particularly useful for testing and validating the correctness of bitwise operations in a decentralized environment.

# PrecompilesComparison1TestsContract.sol

Performs comparison operations (greater than, less than or equal to, and less than) on different bit-length values and ensures consistency across various data types.

## Structures
The contract defines several structures to hold values and results for different bit-lengths:

- `AllGTCastingValues`: Holds 8-bit, 16-bit, 32-bit, and 64-bit unsigned integers.
- `Check16`, `Check32`, `Check64`: Hold the results of operations for different bit-length combinations.

## State Variables
- `result`: Stores a boolean result.

## Functions
1. **`getResult`**: Returns the boolean result.
2. **`setPublicValues`**: Sets the public values for different bit-lengths using `MpcCore.setPublic` methods.
3. **`decryptAndCompareResults16`**: Decrypts and compares 16-bit results to ensure consistency.
4. **`decryptAndCompareResults32`**: Decrypts and compares 32-bit results to ensure consistency.
5. **`decryptAndCompareResults64`**: Decrypts and compares 64-bit results to ensure consistency.

## Comparison Operations
1. **`gtTest`**: Performs a greater-than comparison on the given 8-bit values and checks consistency across different bit-lengths:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the greater-than results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

2. **`leTest`**: Similar to `gtTest`, but performs a less-than-or-equal-to comparison:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the less-than-or-equal-to results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

3. **`ltTest`**: Similar to `gtTest`, but performs a less-than comparison:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the less-than results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

## Core Operations
The contract relies on the `MpcCore` library for:
- Setting public values (`setPublic8`, `setPublic16`, `setPublic32`, `setPublic64`).
- Performing comparison operations (`gt`, `le`, `lt`).
- Decrypting results (`decrypt`).

## Summary
The contract ensures that comparison operations on various bit-length values are consistent and correct by performing the operations, decrypting the results, and comparing them across different types and combinations. This can be particularly useful for testing and validating the correctness of comparison operations in a decentralized environment.

# PrecompilesComparison2TestsContract.sol

Performs additional comparison operations (equal to, not equal to, greater than or equal to) on different bit-length values and ensures consistency across various data types.

## Structures
The contract defines several structures to hold values and results for different bit-lengths:

- `AllGTCastingValues`: Holds 8-bit, 16-bit, 32-bit, and 64-bit unsigned integers.
- `Check16`, `Check32`, `Check64`: Hold the results of operations for different bit-length combinations.

## State Variables
- `result`: Stores a boolean result.

## Functions
1. **`getResult`**: Returns the boolean result.
2. **`setPublicValues`**: Sets the public values for different bit-lengths using `MpcCore.setPublic` methods.
3. **`decryptAndCompareResults16`**: Decrypts and compares 16-bit results to ensure consistency.
4. **`decryptAndCompareResults32`**: Decrypts and compares 32-bit results to ensure consistency.
5. **`decryptAndCompareResults64`**: Decrypts and compares 64-bit results to ensure consistency.

## Comparison Operations
1. **`eqTest`**: Performs an equal-to comparison on the given 8-bit values and checks consistency across different bit-lengths:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the equal-to results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

2. **`neTest`**: Similar to `eqTest`, but performs a not-equal-to comparison:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the not-equal-to results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

3. **`geTest`**: Similar to `eqTest`, but performs a greater-than-or-equal-to comparison:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the greater-than-or-equal-to results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

## Core Operations
The contract relies on the `MpcCore` library for:
- Setting public values (`setPublic8`, `setPublic16`, `setPublic32`, `setPublic64`).
- Performing comparison operations (`eq`, `ne`, `ge`).
- Decrypting results (`decrypt`).

## Summary
The contract ensures that comparison operations on various bit-length values are consistent and correct by performing the operations, decrypting the results, and comparing them across different types and combinations. This can be particularly useful for testing and validating the correctness of comparison operations in a decentralized environment.

# PrecompilesMinMaxTestsContract.sol

Performs minimum and maximum operations on different bit-length values and ensures consistency across various data types.

## Structures
The contract defines several structures to hold values and results for different bit-lengths:

- `AllGTCastingValues`: Holds 8-bit, 16-bit, 32-bit, and 64-bit unsigned integers.
- `Check16`, `Check32`, `Check64`: Hold the results of operations for different bit-length combinations.

## State Variables
- `result`: Stores an 8-bit result.

## Functions
1. **`getResult`**: Returns the 8-bit result.
2. **`setPublicValues`**: Sets the public values for different bit-lengths using `MpcCore.setPublic` methods.
3. **`decryptAndCompareResults16`**: Decrypts and compares 16-bit results to ensure consistency.
4. **`decryptAndCompareResults32`**: Decrypts and compares 32-bit results to ensure consistency.
5. **`decryptAndCompareResults64`**: Decrypts and compares 64-bit results to ensure consistency.

## Min/Max Operations
1. **`minTest`**: Performs a minimum comparison on the given 8-bit values and checks consistency across different bit-lengths:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the minimum results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

2. **`maxTest`**: Similar to `minTest`, but performs a maximum comparison:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the maximum results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

## Core Operations
The contract relies on the `MpcCore` library for:
- Setting public values (`setPublic8`, `setPublic16`, `setPublic32`, `setPublic64`).
- Performing min/max operations (`min`, `max`).
- Decrypting results (`decrypt`).

## Summary
The contract ensures that min/max operations on various bit-length values are consistent and correct by performing the operations, decrypting the results, and comparing them across different types and combinations. This can be particularly useful for testing and validating the correctness of min/max operations in a decentralized environment.

# PrecompilesMiscellaneous1TestsContract.sol

Performs various miscellaneous operations including random number generation and boolean logic operations.

## State Variables
- `random`: Stores a 64-bit random number.
- `andRes`, `orRes`, `xorRes`, `notRes`, `eqRes`, `neqRes`, `muxRes`, `onboardRes`: Store the results of boolean operations.

## Functions
1. **`getRandom`**: Returns the 64-bit random number.
2. **`getBooleanResults`**: Returns the results of the boolean operations as a tuple.

### Constants
- `MAX_SIZE_8_BITS`: Maximum size for 8-bit operations.
- `MAX_SIZE_16_BITS`: Maximum size for 16-bit operations.
- `MAX_SIZE_32_BITS`: Maximum size for 32-bit operations.
- `MAX_SIZE_64_BITS`: Maximum size for 64-bit operations.
- `MAX_BOOL_SIZE`: Maximum size for boolean operations.

### Helper Functions
1. **`checkNotAllEqual`**: Ensures that not all generated random numbers are equal.
2. **`checkBound`**: Ensures that all generated random numbers are within the specified bounds.

## Random Number Generation
1. **`randomTest`**: Generates random numbers and ensures they are not all equal.
2. **`randomBoundedTest`**: Generates bounded random numbers and ensures they are within the specified bounds.
3. **`randTest_`**: Core function for generating random numbers, both bounded and unbounded.

## Boolean Operations
1. **`booleanTest`**: Performs various boolean operations (AND, OR, XOR, NOT, EQ, NEQ, MUX) and stores the results.

### Core Operations
The contract relies on the `MpcCore` library for:
- Generating random numbers (`rand8`, `rand16`, `rand32`, `rand64`).
- Generating bounded random numbers (`randBoundedBits8`, `randBoundedBits16`, `randBoundedBits32`, `randBoundedBits64`).
- Performing boolean operations (`and`, `or`, `xor`, `not`, `eq`, `ne`, `mux`).
- Decrypting results (`decrypt`).
- Onboarding and offboarding boolean values (`offBoard`, `onBoard`).

## Summary
The contract ensures the correctness of random number generation and boolean operations by performing the operations, decrypting the results, and comparing them as necessary. This can be particularly useful for testing and validating the correctness of these operations in a decentralized environment.

# PrecompilesMiscellaneousTestsContract.sol

Performs various miscellaneous operations including division, remainder, mux, offboard/onboard, and boolean NOT operations.

## Structures
The contract defines several structures to hold values and results for different bit-lengths:

- `AllGTCastingValues`: Holds 8-bit, 16-bit, 32-bit, and 64-bit unsigned integers.
- `Check16`, `Check32`, `Check64`: Hold the results of operations for different bit-length combinations.

## State Variables
- `result`: Stores an 8-bit result.
- `boolResult`: Stores a boolean result.

## Functions
1. **`getResult`**: Returns the 8-bit result.
2. **`getBoolResult`**: Returns the boolean result.
3. **`setPublicValues`**: Sets the public values for different bit-lengths using `MpcCore.setPublic` methods.
4. **`decryptAndCompareResults16`**: Decrypts and compares 16-bit results to ensure consistency.
5. **`decryptAndCompareResults32`**: Decrypts and compares 32-bit results to ensure consistency.
6. **`decryptAndCompareResults64`**: Decrypts and compares 64-bit results to ensure consistency.

## Miscellaneous Operations
1. **`divTest`**: Performs division on the given 8-bit values and checks consistency across different bit-lengths:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the division results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

2. **`remTest`**: Similar to `divTest`, but performs remainder operation:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the remainder results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

3. **`muxTest`**: Performs a mux operation on the given 8-bit values and checks consistency across different bit-lengths:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the mux results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

4. **`offboardOnboardTest`**: Tests offboarding and onboarding of values:
   - Sets the public values for different bit-lengths.
   - Offboards and onboards the values.
   - Ensures the results are consistent across different data types.

5. **`notTest`**: Performs a NOT operation on the given boolean value and returns the result.

### Core Operations
The contract relies on the `MpcCore` library for:
- Setting public values (`setPublic8`, `setPublic16`, `setPublic32`, `setPublic64`).
- Performing miscellaneous operations (`div`, `rem`, `mux`, `not`, `offBoard`, `onBoard`).
- Decrypting results (`decrypt`).

## Summary
The contract ensures the correctness of various miscellaneous operations by performing the operations, decrypting the results, and comparing them as necessary. This can be particularly useful for testing and validating the correctness of these operations in a decentralized environment.

# PrecompilesOffboardToUserKeyTestContract.sol

Performs operations involving offboarding data to a user key and handling various cryptographic operations.

## State Variables
- `userKey`: Stores the user's key as bytes.
- `x`: Stores an 8-bit unsigned integer.
- `ctUserKey`: Stores the ciphertext of the user's key.
- `ct8`, `ct16`, `ct32`, `ct64`: Store ciphertexts of various bit-lengths.

## Functions
1. **`getCTs`**: Returns the ciphertexts of various bit-lengths.
2. **`getUserKeyTest`**: 
   - Sets a public 8-bit value `a`.
   - Adds `a` to 5 and offboards the result to the user's key.
   - Offboards the result to the system key and decrypts it.
   - Returns the decrypted value.
3. **`getX`**: Returns the value of `x`.
4. **`getUserKey`**: Returns the user's key.
5. **`getCt`**: Returns the ciphertext of the user's key.
6. **`userKeyTest`**: Returns the user's key based on the signed encryption key and signature.
7. **`offboardToUserTest`**:
   - Sets public values for 8-bit, 16-bit, 32-bit, and 64-bit.
   - Offboards these values to the user's key.
   - Stores and returns the ciphertexts.

### Core Operations
The contract relies on the `MpcCore` library for:
- Setting public values (`setPublic8`, `setPublic16`, `setPublic32`, `setPublic64`).
- Performing arithmetic operations (`add`).
- Offboarding data to the user's key (`offBoardToUser`).
- Offboarding data to the system key (`offBoard`).
- Onboarding data (`onBoard`).
- Decrypting results (`decrypt`).
- Retrieving the user's key (`getUserKey`).

## Summary
The contract ensures the correctness of operations involving offboarding to user keys by performing the operations, decrypting the results, and comparing them as necessary. This can be particularly useful for testing and validating the correctness of these operations in a decentralized environment.

# PrecompilesShiftTestsContract.sol

Performs various shift operations (left and right) on different bit-length values and ensures consistency across various data types.

## Structures
The contract defines several structures to hold values and results for different bit-lengths:

- `AllGTCastingValues`: Holds 8-bit, 16-bit, 32-bit, and 64-bit unsigned integers.
- `Check16`, `Check32`, `Check64`: Hold the results of operations for different bit-length combinations.

## State Variables
- `result`: Stores an 8-bit result.
- `result16`: Stores a 16-bit result.
- `result32`: Stores a 32-bit result.
- `result64`: Stores a 64-bit result.

## Functions
1. **`getResult`**: Returns the 8-bit result.
2. **`getAllShiftResults`**: Returns the results of the shift operations as a tuple (8-bit, 16-bit, 32-bit, 64-bit).
3. **`setPublicValues`**: Sets the public values for different bit-lengths using `MpcCore.setPublic` methods.
4. **`decryptAndCompareResults16`**: Decrypts and compares 16-bit results to ensure consistency.
5. **`decryptAndCompareResults32`**: Decrypts and compares 32-bit results to ensure consistency.
6. **`decryptAndCompareResults64`**: Decrypts and compares 64-bit results to ensure consistency.

## Shift Operations
1. **`shlTest`**: Performs a left shift on the given 8-bit values and checks consistency across different bit-lengths:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the left shift results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

2. **`shrTest`**: Similar to `shlTest`, but performs a right shift:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the right shift results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

### Core Operations
The contract relies on the `MpcCore` library for:
- Setting public values (`setPublic8`, `setPublic16`, `setPublic32`, `setPublic64`).
- Performing shift operations (`shl`, `shr`).
- Decrypting results (`decrypt`).

## Summary
The contract ensures the correctness of shift operations on various bit-length values by performing the operations, decrypting the results, and comparing them as necessary. This can be particularly useful for testing and validating the correctness of these operations in a decentralized environment.

# PrecompilesTransferScalarTestsContract.sol

Performs transfer operations with scalar values, checking the correctness of these operations across different bit-length values.

## Structures
The contract defines several structures to hold values and results for different bit-lengths:

- `AllGTCastingValues`: Holds 8-bit, 16-bit, 32-bit, and 64-bit unsigned integers.

## State Variables
- `new_a`: Stores the new value of `a` after the transfer.
- `new_b`: Stores the new value of `b` after the transfer.
- `res`: Stores the result of the transfer operation as a boolean.

## Functions
1. **`getResults`**: Returns the values of `new_a`, `new_b`, and `res`.
2. **`computeAndChekTransfer16`**: Checks the transfer operation for 16-bit values with a scalar amount:
   - Ensures consistency of the operation for different bit-length combinations involving 16-bit values.
3. **`computeAndChekTransfer32`**: Checks the transfer operation for 32-bit values with a scalar amount:
   - Ensures consistency of the operation for different bit-length combinations involving 32-bit values.
4. **`computeAndChekTransfer64`**: Checks the transfer operation for 64-bit values with a scalar amount:
   - Ensures consistency of the operation for different bit-length combinations involving 64-bit values.
5. **`transferScalarTest`**: Performs the transfer operation with a scalar amount and checks the results across different bit-length values:
   - Sets the public values for different bit-lengths.
   - Calculates the expected result.
   - Checks the transfer results for 16-bit, 32-bit, and 64-bit values.
   - Ensures the results are consistent across different data types and with scalars.

### Core Operations
The contract relies on the `MpcCore` library for:
- Setting public values (`setPublic8`, `setPublic16`, `setPublic32`, `setPublic64`).
- Performing transfer operations (`transfer`).
- Decrypting results (`decrypt`).

## Summary
The contract ensures the correctness of transfer operations with scalar values by performing the operations, decrypting the results, and comparing them as necessary. This can be particularly useful for testing and validating the correctness of these operations in a decentralized environment.

# PrecompilesTransferTestsContract.sol

Designed to test the transfer functionality of the `MpcCore` library with different data types and casting scenarios. The contract includes several key components and functions.

## Structures

1. `AllGTCastingValues`: This struct holds various data types (8, 16, 32, and 64-bit unsigned integers) to be used in the transfer tests.
2. `AllAmountValues`: This struct holds different data types for the amount to be transferred, as well as an 8-bit unsigned integer amount.

## State Variables

1. `newA`, `newB`: These variables store the new values of `a` and `b` after the transfer.
2. `result`: This boolean variable stores the result of the transfer.

## Functions

1. `getResults()`: A public view function that returns the current values of `newA`, `newB`, and `result`.
2. `computeAndChekTransfer16()`, `computeAndChekTransfer32()`, `computeAndChekTransfer64()`: These functions test the transfer functionality with different data types and casting scenarios (16, 32, and 64-bit). They use the `MpcCore.transfer` function and compare the results with the expected values using `MpcCore.decrypt`.
3. `transferTest()`: This function initiates the transfer tests. It sets up the casting values and amount values, performs the transfer using 8-bit values, and then calls the `computeAndChekTransfer16`, `computeAndChekTransfer32`, and `computeAndChekTransfer64` functions to test the transfer functionality with different casting scenarios.

### Core Operations
The contract relies on the `MpcCore` library for its core operations, which include:
1. `MpcCore.transfer`: This function performs the transfer of values based on the provided casting and amount values.
2. `MpcCore.decrypt`: This function decrypts the results of the transfer to verify the correctness of the operation.
3. `MpcCore.setPublic*`: These functions set the public values for different data types (8, 16, 32, and 64-bit unsigned integers).

## Summary
The `PrecompilesTransferTestsContract` ensures that the transfer functionality of the `MpcCore` library works correctly with various data types and casting scenarios by comparing the results of the `MpcCore.transfer` function with the expected values using `MpcCore.decrypt`.
