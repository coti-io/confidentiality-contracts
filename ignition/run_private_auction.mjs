import { block_size, decrypt, prepareIT, hexBase } from "../../../soda-sdk/js/crypto.js"
import { SodaWeb3Helper, REMOTE_HTTP_PROVIDER_URL } from "../../../lib/js/sodaWeb3Helper.mjs"

const ERC20_FILE_NAME = "ConfidentialERC20Contract.sol"
const AUCTION_FILE_NAME = "ConfidentialAuction.sol"
const FILE_PATH = "examples/contracts/"

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

async function checkAllowance(from, to, contract, user_key, expectedAllowance) {
  // Get my encrypted allowance, decrypt it and check if it is equal to the expected allowance
  let allowanceCT = await contract.methods.allowance(from, to).call({ from })
  let allowance = decryptValue(allowanceCT, user_key)
  checkExpectedResult("allowance", expectedAllowance, allowance)
}

async function main() {
  // Get the private key from the environment variable
  const SIGNING_KEY = process.env.SIGNING_KEY
  // Create helper function using the private key
  const sodaHelper = new SodaWeb3Helper(SIGNING_KEY, REMOTE_HTTP_PROVIDER_URL)

  // compile the onboard solidity contracts
  if (!sodaHelper.setupContract(FILE_PATH, ERC20_FILE_NAME, "private_erc20")) {
    console.log("Failed to set up the token contract")
    return
  }

  if (!sodaHelper.setupContract(FILE_PATH, AUCTION_FILE_NAME, "private_auction")) {
    console.log("Failed to set up the auction contract")
    return
  }

  const tokenContractAddress = "0x9330c00ca7f8d33b943c1ef1d6eea0f4b8d517c6"
  await sodaHelper.attachContract("private_erc20", tokenContractAddress)

  const BENEFICIARY_ADDRESS = process.env.BENEFICIARY_ADDRESS
  // Deploy the contract
  let receipt = await sodaHelper.deployContract("private_auction", [BENEFICIARY_ADDRESS, tokenContractAddress, 60 * 60 * 24, true])
  if (!receipt) {
    console.log("Failed to deploy the auction contract")
    return
  }

  console.log("************* View functions *************")
  const bidCounter = await sodaHelper.callContractView("private_auction", "bidCounter")
  console.log("Function call result bidCounter:", bidCounter)

  const endTime = await sodaHelper.callContractView("private_auction", "endTime")
  console.log("Function call result endTime:", endTime)

  const contractOwner = await sodaHelper.callContractView("private_auction", "contractOwner")
  console.log("Function call result contractOwner:", contractOwner)

  const beneficiary = await sodaHelper.callContractView("private_auction", "beneficiary")
  console.log("Function call result beneficiary:", beneficiary)

  const user_key_hex = process.env.USER_KEY
  const user_key = Buffer.from(user_key_hex, "hex")

  const tokenContract = sodaHelper.getContract("private_erc20")
  const auctionContract = sodaHelper.getContract("private_auction")
  const account = sodaHelper.getAccount()
  const plaintext_bid = 5
  const dummyCT = 0
  const dummySignature = Buffer.alloc(65)

  console.log("************* Approve IT 50 to my address *************")
  // Approve 50 SOD to this account
  let func = tokenContract.methods.approve(auctionContract.options.address, dummyCT, dummySignature) // Dummy function to get the signature
  let hashFuncSig = getFunctionSignature(func)
  let { ctInt, signature } = prepareIT(
    50,
    user_key,
    account.address,
    tokenContract.options.address,
    hashFuncSig,
    Buffer.from(SIGNING_KEY.slice(2), "hex")
  )
  func = tokenContract.methods.approve(auctionContract.options.address, ctInt, signature)
  await sodaHelper.callContractFunctionTransaction(func)

  console.log("************* Check my allowance *************")
  // Check that the allowance has changed to 50 SOD
  await checkAllowance(account.address, auctionContract.options.address, tokenContract, user_key, 50)

  console.log("************* Bid IT ", plaintext_bid, " *************")
  func = auctionContract.methods.bid(dummyCT, dummySignature)
  hashFuncSig = getFunctionSignature(func)
  ;({ ctInt, signature } = prepareIT(
    plaintext_bid,
    user_key,
    account.address,
    auctionContract.options.address,
    hashFuncSig,
    Buffer.from(SIGNING_KEY.slice(2), "hex")
  ))
  func = auctionContract.methods.bid(ctInt, signature)
  await sodaHelper.callContractFunctionTransaction(func)

  let bid = await sodaHelper.callContractView("private_auction", "getBid")
  checkExpectedResult("bid", plaintext_bid, decryptValue(bid, user_key))

  const plaintext_bid2 = 10
  console.log("************* Increase bid IT ", plaintext_bid2, " *************")
  func = auctionContract.methods.bid(dummyCT, dummySignature)
  hashFuncSig = getFunctionSignature(func)
  ;({ ctInt, signature } = prepareIT(
    plaintext_bid2,
    user_key,
    account.address,
    auctionContract.options.address,
    hashFuncSig,
    Buffer.from(SIGNING_KEY.slice(2), "hex")
  ))
  func = auctionContract.methods.bid(ctInt, signature)
  await sodaHelper.callContractFunctionTransaction(func)

  bid = await sodaHelper.callContractView("private_auction", "getBid")
  checkExpectedResult("increase bid", plaintext_bid2, decryptValue(bid, user_key))

  await sodaHelper.callContractTransaction("private_auction", "stop")

  const isHighestBid = await sodaHelper.callContractView("private_auction", "doIHaveHighestBid")
  checkExpectedResult("is highest", 1, decryptValue(isHighestBid, user_key))

  // const highestBid = await sodaHelper.callContractView("private_auction", "getHighestBid")
  // checkExpectedResult('highest', 10, decryptValue(highestBid, user_key))
}

main()
