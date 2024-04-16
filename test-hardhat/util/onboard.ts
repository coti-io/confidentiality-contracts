import os from "os"
import fs from "fs"
import hre from "hardhat"
import { Wallet, SigningKey, parseEther, getBytes, keccak256 } from "ethers"
import { generateRSAKeyPair, decryptRSA, sign } from "./crypto"

export type User = Awaited<ReturnType<typeof setupAccounts>>[number]

export async function setupAccounts() {
  const pks = process.env.SIGNING_KEYS ? process.env.SIGNING_KEYS.split(",") : []
  if (pks.length == 0) {
    const key1 = hre.ethers.Wallet.createRandom(hre.ethers.provider)
    const key2 = hre.ethers.Wallet.createRandom(hre.ethers.provider)

    setEnvValue("SIGNING_KEYS", `${key1.privateKey},${key2.privateKey}`)

    throw new Error(`Created new random account ${key1.publicKey}. Please use faucet to fund it.`)
  }

  const accounts = pks.map((pk) => new hre.ethers.Wallet(pk, hre.ethers.provider))
  let userKeys = process.env.USER_KEYS ? process.env.USER_KEYS.split(",") : []

  if (userKeys.length !== accounts.length) {
    userKeys = await Promise.all(accounts.map(async (account) => await onboard(account)))
    setEnvValue("USER_KEYS", userKeys.join(","))

    await accounts[0].sendTransaction({ to: accounts[1].address, value: parseEther("0.1") })
  }

  return accounts.map((a, i) => ({ wallet: a, userKey: userKeys[i] }))
}

async function deploy(owner: Wallet) {
  const factory = await hre.ethers.getContractFactory("GetUserKey", owner)
  const contract = await factory.connect(owner).deploy({ gasLimit: 12000000 })
  return contract.waitForDeployment()
}

async function onboard(user: Wallet) {
  const contract = await deploy(user)
  const { publicKey, privateKey } = generateRSAKeyPair()

  const signedEK = sign(keccak256(publicKey), user.privateKey)
  await (await contract.connect(user).getUserKey(publicKey, signedEK, { gasLimit: 12000000 })).wait()
  const encryptedKey = await contract.connect(user).getSavedUserKey()
  const buf = Buffer.from(encryptedKey.substring(2), "hex")
  return decryptRSA(privateKey, buf).toString("hex")
}

function setEnvValue(key: string, value: string) {
  fs.appendFileSync("./.env", `\n${key}=${value}`, "utf8")
}
