# MpcCore.sol

This Solidity library, `MpcCore`, provides core functionalities for secure multi-party computation (MPC) using the COTI protocol.  

Below is an overview of its components and functions:


## Legend

- it = input text. This structure contains text that was encrypted by user and provided a signature to authenticate it.
- gc = garbled text
- ct = cipher text
- ut = user text. This structure  contains 2 types of cipher texts: one by the network and one by the user key. Convenient for operations that require some times to decipher one or another.

## Types
The library defines several custom types using `uint256` as the base type:
- `gtBool`, `gtUint8`, `gtUint16`, `gtUint32`, `gtUint64`
- `ctBool`, `ctUint8`, `ctUint16`, `ctUint32`, `ctUint64`
- `lenghts`, use to differentiate the length

## Structures
The library defines multiple structures for handling encrypted and signed data:
- `itBool`, `itUint8`, `itUint16`, `itUint32`, `itUint64`: Each structure contains a inputtext (`ctBool`, `ctUint8`, etc.) and a signature (`bytes`).
- `utBool`, `utUint8`, `utUint16`, `utUint32`, `utUint64`: Each structure contains two usertext (`ctBool`, `ctUint8`, etc.) for user and regular data.

## Enums
- `MPC_TYPE`: Enum to represent different MPC data types (`SBOOL_T`, `SUINT8_T`, `SUINT16_T`, `SUINT32_T`, `SUINT64_T`).
- `ARGS`: Enum to represent different argument types (`BOTH_SECRET`, `LHS_PUBLIC`, `RHS_PUBLIC`).

## Functions
### Enum Combination Functions
These functions combine enum values into bytes for efficient storage and transfer:
- `combineEnumsToBytes2(MPC_TYPE mpcType, ARGS argsType)`: Combines an `MPC_TYPE` and `ARGS` into a `bytes2` value.
- `combineEnumsToBytes3(MPC_TYPE mpcType1, MPC_TYPE mpcType2, ARGS argsType)`: Combines two `MPC_TYPE` values and an `ARGS` value into a `bytes3` value.
- `combineEnumsToBytes4(MPC_TYPE mpcType1, MPC_TYPE mpcType2, MPC_TYPE mpcType3, ARGS argsType)`: Combines three `MPC_TYPE` values and an `ARGS` value into a `bytes4` value.

### Overflow and Result Validation
- `checkOverflow`: Validates whether an overflow has occurred in a cryptographic operation.
- `checkRes8`, `checkRes16`, `checkRes32`, `checkRes64`: Check the result for different bit sizes (8, 16, 32, and 64 bits).

### Key Management Functions
- `getUserKey(bytes calldata signedEK, bytes calldata signature)`: Retrieves the user's AES encryption key in encrypted format, by using the provided public key to encrypt it - signature is used to validate the account ownership.
- `deleteUserKey`: Deletes a user’s cryptographic key.

This library is designed to be used as part of a secure multi-party computation framework, facilitating the handling and combination of encrypted and signed data types.

### Ciphertext Validation and Decryption
- `validateCiphertext`: Validates the integrity of a ciphertext.
- `decrypt`: Decrypts a given ciphertext.

### Onboarding and Offboarding Users
- `onBoard`: Adds a user to the MPC protocol, loading data from `ct` type to `gt` type.
- `offBoard`: Removes a user from the MPC protocol, transforming data from `gt` type to `ct` type.
- `offBoardToUser`: Transfers data ownership to a user during offboarding; transforms from `gt` type to `ct` type previously prepared by the user's AES key rather than the MPC one.
- `offBoardCombined`: Combines offboarding actions for multiple users, offboarding to both the user's AES key and the network's AES key.

### Setting Public Keys
- `setPublic`: Sets a public key for cryptographic operations, taking data that was sent to the contract in as `ct` and transforming it to `gt`.
- `setPublic8`, `setPublic16`, `setPublic32`, `setPublic64`: Sets public keys for specific bit sizes (8, 16, 32, and 64 bits).

### Random Number Generation
- `rand`, `rand8`, `rand16`, `rand32`, `rand64`: Generate random numbers of various bit sizes.
- `randBoundedBits8`, `randBoundedBits16`, `randBoundedBits32`, `randBoundedBits64`: Generates bounded random numbers within a specified range for different bit sizes.

### Logical and Comparison Operations
- `and`, `or`, `xor`: Perform bitwise operations.
- `eq`, `ne`, `ge`, `gt`, `le`, `lt`: Perform comparison operations (equality, inequality, greater than, less than, etc.).

### Mathematical Operations
- `add`, `checkedAdd`, `sub`, `checkedSub`, `mul`, `checkedMul`, `div`, `rem`: Perform mathematical operations, with both standard and overflow-checked versions available.
- `min`, `max`: Return the minimum or maximum of two values.

### Data Transfer Operations
- `transfer`, `transferWithAllowance`: Facilitate data or token transfer operations between accounts.

### Multiplexer and Logical Negation
- `mux`: Implements a multiplexer operation (conditional value selection).
- `not`: Implements a bitwise NOT operation.

# MpcInterface.sol

This Solidity interface, `ExtendedOperations`, defines a set of functions for performing various operations that are essential for secure multi-party computation (MPC) on the COTI network. Below is an overview of its components and functions:

## Functions

### Onboarding and Offboarding Functions
- `OnBoard(bytes1 metaData, uint256 ct)`: Onboards a new EOA. Metadata is used to define what is the data type being used (8 , 16, 32 , 64). This function is not directly called by others in MpcCore.
- `OffBoard(bytes1 metaData, uint256 ct)`: Offboards an EOA. Metadata is used to define what is the data type being used (8 , 16, 32 , 64). This function is not directly called by others in MpcCore.
- `OffBoardToUser(bytes1 metaData, uint256 ct, bytes calldata addr)`: Offboards an EOA to a user-specified address. Metadata is used to define what is the data type being used (8 , 16, 32 , 64). This function is not directly called by others in MpcCore.
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

### Validation and Transfer Functions
- `ValidateCiphertext(bytes calldata ciphertext, bytes calldata signature)`: Validates the given ciphertext and signature.
    - If the input is not valid, the call will revert with no return data and no additional gas will be consumed.
- `TransferWithAllowance(address from, address to, uint256 amount, bytes calldata signature)`: Transfers the specified amount from one address to another with the provided signature.

This interface is designed to be implemented by a contract that performs secure multi-party computation, providing essential operations such as arithmetic, bitwise, and comparison functions, as well as onboarding and offboarding participants or data.
