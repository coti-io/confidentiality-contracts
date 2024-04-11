import hre from "hardhat"
import crypto from "crypto"
import { Signer, solidityPackedKeccak256, Signature, getBytes, verifyMessage } from "ethers"

const block_size = 16 // AES block size in bytes
const addressSize = 20 // 160-bit is the output of the Keccak-256 algorithm on the sender/contract address
const funcSigSize = 4
const ctSize = 32
const keySize = 32
const hexBase = 16

if (!process.env.USER_KEY) {
  throw new Error("please set USER_KEY env var")
}
export const user_key = Buffer.from(process.env.USER_KEY, "hex")

function encrypt(key: Buffer, plaintext: Buffer) {
  // Ensure plaintext is smaller than 128 bits (16 bytes)
  if (plaintext.length > block_size) {
    throw new RangeError("Plaintext size must be 128 bits or smaller.")
  }

  // Ensure key size is 128 bits (16 bytes)
  if (key.length != block_size) {
    throw new RangeError("Key size must be 128 bits.")
  }

  // Create a new AES cipher using the provided key
  const cipher = crypto.createCipheriv("aes-128-ecb", key, null)

  // Generate a random value 'r' of the same length as the block size
  const r = crypto.randomBytes(block_size)

  // Encrypt the random value 'r' using AES in ECB mode
  const encryptedR = cipher.update(r)

  // Pad the plaintext with zeros if it's smaller than the block size
  const plaintext_padded = Buffer.concat([Buffer.alloc(block_size - plaintext.length), plaintext])

  // XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
  const ciphertext = Buffer.alloc(encryptedR.length)
  for (let i = 0; i < encryptedR.length; i++) {
    ciphertext[i] = encryptedR[i] ^ plaintext_padded[i]
  }

  return { ciphertext, r }
}

function decrypt(key: Buffer, r: Buffer, ciphertext: Buffer) {
  if (ciphertext.length !== block_size) {
    throw new RangeError("Ciphertext size must be 128 bits.")
  }

  // Ensure key size is 128 bits (16 bytes)
  if (key.length != block_size) {
    throw new RangeError("Key size must be 128 bits.")
  }

  // Ensure random size is 128 bits (16 bytes)
  if (r.length != block_size) {
    throw new RangeError("Random size must be 128 bits.")
  }

  // Create a new AES decipher using the provided key
  const cipher = crypto.createCipheriv("aes-128-ecb", key, null)

  // Encrypt the random value 'r' using AES in ECB mode
  const encryptedR = cipher.update(r)

  // XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
  const plaintext = Buffer.alloc(encryptedR.length)
  for (let i = 0; i < encryptedR.length; i++) {
    plaintext[i] = encryptedR[i] ^ ciphertext[i]
  }

  return plaintext
}

export function decryptValue(myCTBalance: bigint) {
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
  const decryptedMessage = decrypt(user_key, r, cipher)

  return parseInt(decryptedMessage.toString("hex"), block_size)
}

export async function prepareIT(
  plaintext: bigint,
  sender: Signer & { address: string },
  contractAddress: string,
  functionSelector: string
) {
  // Convert the plaintext to bytes
  const plaintextBytes = Buffer.alloc(8) // Allocate a buffer of size 8 bytes
  plaintextBytes.writeBigUInt64BE(plaintext) // Write the uint64 value to the buffer as little-endian

  // Encrypt the plaintext using AES key
  const { ciphertext, r } = encrypt(user_key, plaintextBytes)
  console.log(`ciphertext: ${ciphertext.toString("hex")}`)
  const ct = Buffer.from("239b1296bcf08ebac779beeba66d28f99efe264d45d087f2c3800c243b8792d0", "hex") //Buffer.concat([ciphertext, r])
  console.log(`ct: ${ct.toString("hex")}`)

  const message = solidityPackedKeccak256(
    ["address", "address", "bytes4", "uint256"],
    [sender.address, contractAddress, functionSelector, BigInt("0x" + ct.toString("hex"))]
  )
  console.log(`message: ${message}`)

  const hash = getBytes(message)
  console.log(`hash: ${Buffer.from(hash).toString("hex")}`)

  const signature = await sender.signMessage(hash)
  const verified = verifyMessage(hash, signature)
  console.log(`verified: ${verified}`)
  console.log(`signature: ${signature}`)

  // const sig = Signature.from(signature)

  // let rBytes = Buffer.from(sig.r)
  // let sBytes = Buffer.from(sig.s)
  // let vByte = Buffer.from([sig.v - 27])

  // console.log(`sig.r ${sig.r}`)
  // console.log(`sig.s ${sig.s}`)
  // console.log(`sig.v ${sig.v - 27}`)
  // const sig2 = Buffer.concat([rBytes, sBytes, vByte])
  // console.log(`sig2: ${sig2.toString("hex")}`)

  await testRecover(signature, hash)

  // Convert the ciphertext to BigInt
  const ctInt = BigInt("0x" + ct.toString("hex"))
  console.log(`ctInt: ${ctInt.toString()}`)

  return { ctInt, signature }
}

async function testRecover(signature: string, hash: Uint8Array) {
  // const contract = await (await (await hre.ethers.getContractFactory("RecoverMessage")).deploy()).waitForDeployment()
  const contract = await hre.ethers.getContractAt("RecoverMessage", "0xA1913406A9f0D10fd44f02dA54e6fcdfffCF7E46")
  // console.log(`contract address ${await contract.getAddress()}`)
  const sig = Signature.from(signature)

  // // If the signature matches the EIP-2098 format, a Signature
  // // can be passed as the struct value directly, since the
  // // parser will pull out the matching struct keys from sig.
  // console.log(await contract.recoverStringFromCompact(hash, sig))

  // // Likewise, if the struct keys match an expanded signature
  // // struct, it can also be passed as the struct value directly.
  // console.log(await contract.recoverStringFromExpanded(hash, sig))

  // // If using an older API which requires the v, r and s be passed
  // // separately, those members are present on the Signature.
  // console.log(await contract.recoverStringFromVRS(hash, sig.v, sig.r, sig.s))

  // // Or if using an API that expects a raw signature.
  // console.log(await contract.recoverStringFromRaw(hash, signature))

  console.log(await contract.recoverECDSA(hash, signature))
}

// export async function sendEncrypted<C extends BaseContract>(
//   contract: C,
//   func: any,
//   encryptParam: bigint,
//   getParams: (it: bigint, signature: string) => unknown[],
//   signer: Signer & { address: string }
// ) {
//   const contractAddress = await contract.getAddress()
//   const { ctInt, signature } = await prepareIT(encryptParam, signer, contractAddress, func.fragment.selector)
//   return (await func(...getParams(ctInt, signature))).wait()
// }
