import fs from 'fs';
import { block_size, decrypt, prepareIT, hexBase } from '../../../soda-sdk/js/crypto.js';
import {SodaWeb3Helper, REMOTE_HTTP_PROVIDER_URL} from '../../../lib/js/sodaWeb3Helper.mjs';

const FILE_NAME = 'PrivateERC20Contract.sol';
const FILE_PATH = 'examples/contracts/';
const INITIAL_BALANCE = 500000000

function checkExpectedResult(name, expectedResult, result) {
    if (result === expectedResult) {
        console.log(`Test ${name} succeeded: ${result}`);
    } else {
        throw new Error(`Test ${name} failed. Expected: ${expectedResult}, Actual: ${result}`);
    }
}

function getFunctionSignature(func) {
    const encodedABI = func.encodeABI();
    return Buffer.from(encodedABI.substr(2, 8), 'hex');
}

function decryptValue(myCTBalance, userKey) {

    // Convert CT to bytes
    let ctString = myCTBalance.toString(hexBase);
    let ctArray = Buffer.from(ctString, 'hex');
    while (ctArray.length < 32) { // When the first bits are 0, bigint bit size is less than 32 and need to re-add the bits
        ctString = "0" + ctString;
        ctArray = Buffer.from(ctString, 'hex');
    }
    // Split CT into two 128-bit arrays r and cipher
    const cipher = ctArray.subarray(0, block_size);
    const r = ctArray.subarray(block_size);

    // Decrypt the cipher
    const decryptedMessage = decrypt(userKey, r, cipher);

    // console.log the decrypted cipher
    const decryptedBalance = parseInt(decryptedMessage.toString('hex'), block_size);

    return decryptedBalance;
}

async function executeAndCheckBalance(sodaHelper, func, contract, user_key, expectedBalance){
    await sodaHelper.callContractFunctionTransaction(func);
    // Get my encrypted balance, decrypt it and check if it is equal to the expected balance
    const my_CTBalance = await sodaHelper.callContractView("private_erc20", "balanceOf")
    const my_balance = decryptValue(my_CTBalance, user_key);
    checkExpectedResult('transfer', expectedBalance, my_balance);
}

async function checkAllowance(account, contract, user_key, expectedAllowance){
    // Get my encrypted allowance, decrypt it and check if it is equal to the expected allowance
    let allowanceCT = await contract.methods.allowance(account.address, account.address).call({'from': account.address})
    let allowance = decryptValue(allowanceCT, user_key)
    checkExpectedResult('allowance', expectedAllowance, allowance)
}

async function main() {
    // Get the private key from the environment variable
    const SIGNING_KEY = process.env.SIGNING_KEY;
    // Create helper function using the private key
    const sodaHelper = new SodaWeb3Helper(SIGNING_KEY, REMOTE_HTTP_PROVIDER_URL);

    // compile the onboard solidity contract
    const success = sodaHelper.setupContract(FILE_PATH, FILE_NAME, "private_erc20");
    if (!success){
        console.log("Failed to set up the contract")
        return
    }

    // Deploy the contract
    let receipt = await sodaHelper.deployContract("private_erc20", ["Soda", "SOD", INITIAL_BALANCE]);
    if (!receipt){
        console.log("Failed to deploy the contract")
        return
    }

    console.log("************* View functions *************");
    const contractName = await sodaHelper.callContractView("private_erc20", "name")
    console.log("Function call result name:", contractName);

    const symbol = await sodaHelper.callContractView("private_erc20", "symbol")
    console.log("Function call result symbol:", symbol);

    const decimals = await sodaHelper.callContractView("private_erc20", "decimals")
    console.log("Function call result decimals:", decimals);

    const totalSupply = await sodaHelper.callContractView("private_erc20", "totalSupply")
    console.log("Function call result totalSupply:", totalSupply);

    const user_key_hex = process.env.USER_KEY;
    const user_key = Buffer.from(user_key_hex, 'hex');

    console.log("************* Initial balance = ", INITIAL_BALANCE, " *************");
    let my_CTBalance = await sodaHelper.callContractView("private_erc20", "balanceOf")
    let my_balance = decryptValue(my_CTBalance, user_key);
    checkExpectedResult('balanceOf', INITIAL_BALANCE, my_balance);

    // Generate a new account for Alice
    const alice_address = sodaHelper.generateRandomAccount();

    const contract = sodaHelper.getContract("private_erc20")
    const account = sodaHelper.getAccount();

    const plaintext_integer = 5;


    console.log("************* Transfer clear ", plaintext_integer, " to Alice *************");
    // Transfer 5 SOD to Alice
    let func = contract.methods.transfer(alice_address.address, plaintext_integer, true);
    await executeAndCheckBalance(sodaHelper, func, contract, user_key, INITIAL_BALANCE - plaintext_integer)

    console.log("************* Transfer clear ", plaintext_integer, " to Alice *************");
    // Transfer 5 SOD to Alice
    func = contract.methods.contractTransferClear(alice_address.address, plaintext_integer);
    await executeAndCheckBalance(sodaHelper, func, contract, user_key, INITIAL_BALANCE - 2*plaintext_integer)

    console.log("************* Transfer IT ", plaintext_integer, " to Alice *************")
    // In order to generate the input text, we need to use some data of the function. 
    // For example, the address of the user, the address of the contract and also the function signature.
    // To simplify the process of obtaining the function signature, we use a dummy function with placeholder inputs.
    // After the signature is generated, we call prepare input text function and get the input text to use in the real function.
    const dummyCT = 0;
    const dummySignature = Buffer.alloc(65);
    func = contract.methods.transfer(alice_address.address, dummyCT, dummySignature, false); // Create dummy function to get the signature for prepare input text
    let hashFuncSig = getFunctionSignature(func);
    // After the function signature is obtained, prepare the input test for the function
    let {ctInt, signature} = prepareIT(plaintext_integer, user_key, account.address, contract.options.address, hashFuncSig, Buffer.from(SIGNING_KEY.slice(2), 'hex'));
    // Create the real function using the prepared IT
    func = contract.methods.transfer(alice_address.address, ctInt, signature, false);
    // Transfer 5 SOD to Alice
    await executeAndCheckBalance(sodaHelper, func, contract, user_key, INITIAL_BALANCE - 3*plaintext_integer)

    console.log("************* Transfer clear ", plaintext_integer, " from my account to Alice without allowance *************")
    // Trying to transfer 5 SOD to Alice. There is no allowance, transfer should fail
    func = contract.methods.transferFrom(account.address, alice_address.address, plaintext_integer, true)
    // There is no allowance, balance should remain the same
    await executeAndCheckBalance(sodaHelper, func, contract, user_key, INITIAL_BALANCE - 3*plaintext_integer)

    console.log("************* Approve ", plaintext_integer*10, " to my address *************")
    // Set allowance for this account
    func = contract.methods.approveClear(account.address, plaintext_integer*10)
    await sodaHelper.callContractFunctionTransaction(func);
    // Get my allowance to check that the allowance is correct
    checkAllowance(account, contract, user_key, plaintext_integer*10)

    console.log("************* Transfer clear ", plaintext_integer, " from my account to Alice *************")
    // Transfer 5 SOD to Alice
    func = contract.methods.transferFrom(account.address, alice_address.address, plaintext_integer, true)
    await executeAndCheckBalance(sodaHelper, func, contract, user_key, INITIAL_BALANCE - 4*plaintext_integer)

    console.log("************* Transfer clear ", plaintext_integer, " from my account to Alice *************")
    // Transfer 5 SOD to Alice
    func = contract.methods.contractTransferFromClear(account.address, alice_address.address, plaintext_integer)
    await executeAndCheckBalance(sodaHelper, func, contract, user_key, INITIAL_BALANCE - 5*plaintext_integer)

    console.log("************* Transfer IT ", plaintext_integer, " from my account to Alice *************");
    // Transfer 5 SOD to Alice
    func = contract.methods.transferFrom(account.address, alice_address.address, dummyCT, dummySignature, false);
    hashFuncSig = getFunctionSignature(func);
    ({ctInt, signature} = prepareIT(plaintext_integer, user_key, account.address, contract.options.address, hashFuncSig, Buffer.from(SIGNING_KEY.slice(2), 'hex')));
    // Create the real function using the prepared IT output
    func = contract.methods.transferFrom(account.address, alice_address.address, ctInt, signature, false);
    await executeAndCheckBalance(sodaHelper, func, contract, user_key, INITIAL_BALANCE - 6*plaintext_integer);
    
    console.log("************* Check my allowance *************")
    // Check the remainning allowance
    checkAllowance(account, contract, user_key, plaintext_integer*7)

    console.log("************* Approve IT 50 to my address *************")
    // Approve 50 SOD to this account
    func = contract.methods.approve(account.address, dummyCT, dummySignature); // Dummy function to get the signature
    hashFuncSig = getFunctionSignature(func);
    ({ctInt, signature} = prepareIT(50, user_key, account.address, contract.options.address, hashFuncSig, Buffer.from(SIGNING_KEY.slice(2), 'hex')));
    func = contract.methods.approve(account.address, ctInt, signature);
    await sodaHelper.callContractFunctionTransaction(func);

    console.log("************* Check my allowance *************")
    // Check that the allowance has changed to 50 SOD
    checkAllowance(account, contract, user_key, 50);
}

main();
