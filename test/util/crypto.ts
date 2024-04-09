import crypto from "crypto"
import { Signer, solidityPackedKeccak256, getBytes, verifyMessage, keccak256 } from "ethers"
// import {e} from "ethers"

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

  // console.log the decrypted cipher
  const decryptedBalance = parseInt(decryptedMessage.toString("hex"), block_size)

  return decryptedBalance
}

export async function prepareIT(plaintext: string, sender: Signer & { address: string }, contractAddress: string, functionSelector: string) {
  // Get the bytes of the sender, contract, and function signature
  // const senderBytes = toBuffer(sender)
  // const contractBytes = toBuffer(contractAddress)

  // Convert the plaintext to bytes
  const plaintextBytes = Buffer.alloc(8) // Allocate a buffer of size 8 bytes
  console.log(`plaintext: ${plaintext}`)
  plaintextBytes.writeBigUInt64BE(BigInt(plaintext)) // Write the uint64 value to the buffer as little-endian
  console.log(`plaintextBytes: ${plaintextBytes.toString("hex")}`)

  // Encrypt the plaintext using AES key
  const { ciphertext, r } = encrypt(user_key, plaintextBytes)
  console.log(`ciphertext: ${ciphertext.toString("hex")}`)
  let ct = Buffer.concat([ciphertext, r])
  console.log(`ct: ${ct.toString("hex")}`)

  const hash = solidityPackedKeccak256(
    ["address", "address", "bytes4", "uint256"],
    [sender.address, contractAddress, functionSelector, BigInt("0x" + ct.toString("hex"))]
  )
  console.log(`hash: ${hash}`)

  let message = Buffer.concat([Buffer.from(sender.address, "hex"), Buffer.from(contractAddress, "hex"), Buffer.from(functionSelector, "hex"), ct])
  const hash2 = keccak256(message)
  console.log(`hash2: ${hash2}`)

  const signature = await sender.signMessage(getBytes(hash2))

  console.log(`signature: ${signature}`)

  const addr = verifyMessage(getBytes(hash), signature)
  console.log(`addr: ${addr}`)

  // // Sign the message
  // const signature = signIT(senderBytes, contractBytes, functionSelector, ct, signingKey)

  // Convert the ciphertext to BigInt
  const ctInt = BigInt("0x" + ct.toString("hex"))
  console.log(`ctInt: ${ctInt.toString()}`)

  return { ctInt, signature }
}
