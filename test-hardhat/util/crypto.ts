import crypto from "crypto"
import { solidityPackedKeccak256, SigningKey, getBytes } from "ethers"
import type { User } from "./onboard"

const block_size = 16 // AES block size in bytes
const hexBase = 16

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

export function generateRSAKeyPair() {
  // Generate a new RSA key pair
  return crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "der", // Specify 'der' format for binary data
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "der", // Specify 'der' format for binary data
    },
  })
}

export function decryptRSA(privateKey: Buffer, ciphertext: Buffer) {
  // Load the private key in PEM format
  let privateKeyPEM = privateKey.toString("base64")
  privateKeyPEM = `-----BEGIN PRIVATE KEY-----\n${privateKeyPEM}\n-----END PRIVATE KEY-----`

  // Decrypt the ciphertext using RSA-OAEP
  return crypto.privateDecrypt(
    {
      key: privateKeyPEM,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    ciphertext
  )
}

export function decryptValue(myCTBalance: bigint, userKey: string) {
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
  const decryptedMessage = decrypt(Buffer.from(userKey, "hex"), r, cipher)

  return parseInt(decryptedMessage.toString("hex"), block_size)
}

export function sign(message: string, privateKey: string) {
  const key = new SigningKey(privateKey)
  const sig = key.sign(message)
  return Buffer.concat([getBytes(sig.r), getBytes(sig.s), getBytes(`0x0${sig.v - 27}`)])
}

export async function prepareIT(plaintext: bigint, sender: User, contractAddress: string, functionSelector: string) {
  // Convert the plaintext to bytes
  const plaintextBytes = Buffer.alloc(8) // Allocate a buffer of size 8 bytes
  plaintextBytes.writeBigUInt64BE(plaintext) // Write the uint64 value to the buffer as little-endian

  // Encrypt the plaintext using AES key
  const { ciphertext, r } = encrypt(Buffer.from(sender.userKey, "hex"), plaintextBytes)
  const ct = Buffer.concat([ciphertext, r])

  const message = solidityPackedKeccak256(
    ["address", "address", "bytes4", "uint256"],
    [sender.wallet.address, contractAddress, functionSelector, BigInt("0x" + ct.toString("hex"))]
  )

  const signature = sign(message, sender.wallet.privateKey)

  // Convert the ciphertext to BigInt
  const ctInt = BigInt("0x" + ct.toString("hex"))

  return { ctInt, signature }
}

// async function testRecover(signature: string, hash: Uint8Array) {
//   // const contract = await (await (await hre.ethers.getContractFactory("RecoverMessage")).deploy()).waitForDeployment()
//   const contract = await hre.ethers.getContractAt("RecoverMessage", "0xA1913406A9f0D10fd44f02dA54e6fcdfffCF7E46")
//   // console.log(`contract address ${await contract.getAddress()}`)

//   console.log(await contract.recoverECDSA(hash, signature))
// }
