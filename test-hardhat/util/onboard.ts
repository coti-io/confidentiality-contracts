import fs from "fs"
import hre from "hardhat"
import {Wallet, parseEther, getDefaultProvider} from "ethers"
import {ConfidentialAccount, initEtherProvider, transferNative} from "@coti-io/coti-sdk-typescript"
import dotenv from "dotenv";

let pks = process.env.SIGNING_KEYS ? process.env.SIGNING_KEYS.split(",") : []

export async function setupAccounts() {
  dotenv.config();
  const provider = initEtherProvider('https://testnet.coti.io/rpc');

  if (pks.length == 0) {
    const wallet1 = hre.ethers.Wallet.createRandom(provider)
    const wallet2 = hre.ethers.Wallet.createRandom(provider)
    pks = [wallet1.privateKey, wallet2.privateKey]

    setEnvValue("PUBLIC_KEYS", `${wallet1.address},${wallet2.address}`)
    setEnvValue("SIGNING_KEYS", `${wallet1.privateKey},${wallet2.privateKey}`)

    throw new Error(`Created new random accounts ${wallet1.address} and ${wallet2.address}. Please use faucet to fund it.`)
  }

  const wallets = pks.map((pk) => new hre.ethers.Wallet(pk, provider))
  if ((await provider.getBalance(wallets[0].address)) === BigInt("0")) {
    throw new Error(`Please use faucet to fund account ${wallets[0].address}`)
  }

  let userKeys = process.env.USER_KEYS ? process.env.USER_KEYS.split(",") : []

  const toAccount = async (wallet: Wallet, userKey?: string) => {
    if (userKey) {
      return new ConfidentialAccount(wallet, userKey)
    }

    console.log("************* Onboarding user ", wallet.address, " *************")
    const account = await ConfidentialAccount.onboard(wallet)
    console.log("************* Onboarded! created user key and saved into .env file *************")

    return account
  }

  let accounts: ConfidentialAccount[] = []
  if (userKeys.length !== wallets.length) {
    await (await wallets[0].sendTransaction({ to: wallets[1].address, value: parseEther("0.1") })).wait()

    accounts = await Promise.all(wallets.map(async (account, i) => await toAccount(account)))
    setEnvValue("USER_KEYS", accounts.map((a) => a.userKey).join(","))
  } else {
    accounts = await Promise.all(wallets.map(async (account, i) => await toAccount(account, userKeys[i])))
  }

  return accounts
}

function setEnvValue(key: string, value: string) {
  fs.appendFileSync("./.env", `\n${key}=${value}`, "utf8")
}
