# MpcCore.sol

This Solidity library, `MpcCore`, provides core functionalities for secure multi-party computation (MPC) using the COTI protocol. Below is an overview of its components and functions:

## Types
The library defines several custom types using `uint256` as the base type:
- `gtBool`, `gtUint8`, `gtUint16`, `gtUint32`, `gtUint64`
- `ctBool`, `ctUint8`, `ctUint16`, `ctUint32`, `ctUint64`

## Structures
The library defines multiple structures for handling encrypted and signed data:
- `itBool`, `itUint8`, `itUint16`, `itUint32`, `itUint64`: Each structure contains a ciphertext (`ctBool`, `ctUint8`, etc.) and a signature (`bytes`).
- `utBool`, `utUint8`, `utUint16`, `utUint32`, `utUint64`: Each structure contains two ciphertexts (`ctBool`, `ctUint8`, etc.) for user and regular data.

## Enums
- `MPC_TYPE`: Enum to represent different MPC data types (`SBOOL_T`, `SUINT8_T`, `SUINT16_T`, `SUINT32_T`, `SUINT64_T`).
- `ARGS`: Enum to represent different argument types (`BOTH_SECRET`, `LHS_PUBLIC`, `RHS_PUBLIC`).

## Functions
### Enum Combination Functions
These functions combine enum values into bytes for efficient storage and transfer:
- `combineEnumsToBytes2(MPC_TYPE mpcType, ARGS argsType)`: Combines an `MPC_TYPE` and `ARGS` into a `bytes2` value.
- `combineEnumsToBytes3(MPC_TYPE mpcType1, MPC_TYPE mpcType2, ARGS argsType)`: Combines two `MPC_TYPE` values and an `ARGS` value into a `bytes3` value.
- `combineEnumsToBytes4(MPC_TYPE mpcType1, MPC_TYPE mpcType2, MPC_TYPE mpcType3, ARGS argsType)`: Combines three `MPC_TYPE` values and an `ARGS` value into a `bytes4` value.

### Key Management Functions
- `getUserKey(bytes calldata signedEK, bytes calldata signature)`: Retrieves the user's encrypted key using the provided signed encryption key and signature.

This library is designed to be used as part of a secure multi-party computation framework, facilitating the handling and combination of encrypted and signed data types.

# MpcInterface.sol

This Solidity interface, `ExtendedOperations`, defines a set of functions for performing various operations that are essential for secure multi-party computation (MPC) on the COTI network. Below is an overview of its components and functions:

## Functions

### Onboarding and Offboarding Functions
- `OnBoard(bytes1 metaData, uint256 ct)`: Onboards a new participant or data with the given metadata and ciphertext.
- `OffBoard(bytes1 metaData, uint256 ct)`: Offboards a participant or data with the given metadata and ciphertext.
- `OffBoardToUser(bytes1 metaData, uint256 ct, bytes calldata addr)`: Offboards data to a user-specified address.
- `SetPublic(bytes1 metaData, uint256 ct)`: Sets the data as public with the given metadata and ciphertext.

### Randomness Functions
- `Rand(bytes1 metaData)`: Generates a random value with the given metadata.
- `RandBoundedBits(bytes1 metaData, uint8 numBits)`: Generates a random value with a specified number of bits.

### Arithmetic Functions
- `Add(bytes3 metaData, uint256 lhs, uint256 rhs)`: Adds two values.
- `Sub(bytes3 metaData, uint256 lhs, uint256 rhs)`: Subtracts the second value from the first.
- `Mul(bytes3 metaData, uint256 lhs, uint256 rhs)`: Multiplies two values.
- `Div(bytes3 metaData, uint256 lhs, uint256 rhs)`: Divides the first value by the second.
- `Rem(bytes3 metaData, uint256 lhs, uint256 rhs)`: Computes the remainder of the division of two values.

### Bitwise Functions
- `And(bytes3 metaData, uint256 lhs, uint256 rhs)`: Performs a bitwise AND operation.
- `Or(bytes3 metaData, uint256 lhs, uint256 rhs)`: Performs a bitwise OR operation.
- `Xor(bytes3 metaData, uint256 lhs, uint256 rhs)`: Performs a bitwise XOR operation.
- `Shl(bytes3 metaData, uint256 lhs, uint256 rhs)`: Performs a bitwise shift left operation.
- `Shr(bytes3 metaData, uint256 lhs, uint256 rhs)`: Performs a bitwise shift right operation.

### Comparison Functions
- `Eq(bytes3 metaData, uint256 lhs, uint256 rhs)`: Checks if two values are equal.
- `Ne(bytes3 metaData, uint256 lhs, uint256 rhs)`: Checks if two values are not equal.
- `Ge(bytes3 metaData, uint256 lhs, uint256 rhs)`: Checks if the first value is greater than or equal to the second.
- `Gt(bytes3 metaData, uint256 lhs, uint256 rhs)`: Checks if the first value is greater than the second.
- `Le(bytes3 metaData, uint256 lhs, uint256 rhs)`: Checks if the first value is less than or equal to the second.
- `Lt(bytes3 metaData, uint256 lhs, uint256 rhs)`: Checks if the first value is less than the second.

This interface is designed to be implemented by a contract that performs secure multi-party computation, providing essential operations such as arithmetic, bitwise, and comparison functions, as well as onboarding and offboarding participants or data.
