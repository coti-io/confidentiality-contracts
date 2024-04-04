import { block_size, decrypt, prepareIT, hexBase } from "../../../soda-sdk/js/crypto.js"
import { SodaWeb3Helper, REMOTE_HTTP_PROVIDER_URL } from "../../../lib/js/sodaWeb3Helper.mjs"

const FILE_PATH = "examples/contracts/"
const IDENTITY_FILE_NAME = "PrivateIdentityRegistry.sol"

function checkExpectedResult(name, expectedResult, result) {
  if (result === expectedResult) {
    console.log(`Test ${name} succeeded: ${result}`)
  } else {
    throw new Error(`Test ${name} failed. Expected: ${expectedResult}, Actual: ${result}`)
  }
}

function getFunctionSignature(func) {
  const encodedABI = func.encodeABI()
  return Buffer.from(encodedABI.substr(2, 8), "hex")
}

function decryptValue(myCTBalance, userKey) {
  // Convert CT to bytes
  let ctString = myCTBalance.toString(hexBase)
  let ctArray = Buffer.from(ctString, "hex")
  while (ctArray.length < 32) {
    // When the first bits are 0, bigint bit size is less than 32 and need to re-add the bits
    ctString = "0" + ctString
    ctArray = Buffer.from(ctString, "hex")
  }
  // Split CT into two 128-bit arrays r and cipher
  const cipher = ctArray.subarray(0, block_size)
  const r = ctArray.subarray(block_size)

  // Decrypt the cipher
  const decryptedMessage = decrypt(userKey, r, cipher)

  // console.log the decrypted cipher
  const decryptedBalance = parseInt(decryptedMessage.toString("hex"), block_size)

  return decryptedBalance
}

async function main() {
  // Get the private key from the environment variable
  const SIGNING_KEY = process.env.SIGNING_KEY
  // Create helper function using the private key
  const sodaHelper = new SodaWeb3Helper(SIGNING_KEY, REMOTE_HTTP_PROVIDER_URL)

  const contractId = "private_identity_registry"
  // compile the onboard solidity contracts
  if (!sodaHelper.setupContract(FILE_PATH, IDENTITY_FILE_NAME, contractId)) {
    console.log("Failed to set up the token contract")
    return
  }

  // Deploy the contract
  let receipt = await sodaHelper.deployContract(contractId, [])
  if (!receipt) {
    console.log("Failed to deploy the auction contract")
    return
  }

  const contract = sodaHelper.getContract(contractId)

  const user_key_hex = process.env.USER_KEY
  const user_key = Buffer.from(user_key_hex, "hex")

  const account = sodaHelper.getAccount()
  const dummyCT = 0
  const dummySignature = Buffer.alloc(65)

  await sodaHelper.callContractTransaction(contractId, "addRegistrar", [account.address, 1])
  await sodaHelper.callContractTransaction(contractId, "addDid", [account.address])

  const plaintext_identifier = 18
  console.log("************* Set Age Identifier ", plaintext_identifier, " *************")
  let func = contract.methods.setIdentifier(account.address, "age", dummyCT, dummySignature) // Dummy function to get the signature
  let hashFuncSig = getFunctionSignature(func)
  let { ctInt, signature } = prepareIT(
    plaintext_identifier,
    user_key,
    account.address,
    contract.options.address,
    hashFuncSig,
    Buffer.from(SIGNING_KEY.slice(2), "hex")
  )
  func = contract.methods.setIdentifier(account.address, "age", ctInt, signature)
  await sodaHelper.callContractFunctionTransaction(func)
  console.log("************* Identifier Set *************")

  await sodaHelper.callContractTransaction(contractId, "grantAccess", [account.address, ['age']])

  let age = await sodaHelper.callContractView(contractId, "getIdentifier", [account.address, "age"])
  checkExpectedResult("age", plaintext_identifier, decryptValue(age, user_key))
}

main()
