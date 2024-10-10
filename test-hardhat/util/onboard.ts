import fs from "fs"
import {parseEther} from "ethers"
import { CotiNetwork, getDefaultProvider, Wallet } from "@coti-io/coti-ethers";

let pks = process.env.SIGNING_KEYS ? process.env.SIGNING_KEYS.split(",") : []

export async function setupAccounts() {
  const provider = getDefaultProvider(CotiNetwork.Testnet);

  if (pks.length == 0) {
    const wallet1 = Wallet.createRandom(provider)
    const wallet2 = Wallet.createRandom(provider)
    pks = [wallet1.privateKey, wallet2.privateKey]

    setEnvValue("PUBLIC_KEYS", `${wallet1.address},${wallet2.address}`)
    setEnvValue("SIGNING_KEYS", `${wallet1.privateKey},${wallet2.privateKey}`)

    throw new Error(`Created new random accounts ${wallet1.address} and ${wallet2.address}. Please use faucet to fund it.`)
  }

  const wallets = pks.map((pk) => new Wallet(pk, provider))
  if ((await provider.getBalance(wallets[0].address)) === BigInt("0")) {
    throw new Error(`Please use faucet to fund account ${wallets[0].address}`)
  }

  let userKeys = process.env.USER_KEYS ? process.env.USER_KEYS.split(",") : []

  const toAccount = async (wallet: Wallet, userKey?: string) => {
    if (userKey) {
      wallet.setAesKey(userKey)
      return wallet
    }

    console.log("************* Onboarding user ", wallet.address, " *************")
    await wallet.generateOrRecoverAes()
    console.log("************* Onboarded! created user key and saved into .env file *************")

    return wallet
  }

  let accounts: Wallet[] = []
  if (userKeys.length !== wallets.length) {
    await (await wallets[0].sendTransaction({ to: wallets[1].address, value: parseEther("0.1") })).wait()

    accounts = await Promise.all(wallets.map(async (account, i) => await toAccount(account)))
    setEnvValue("USER_KEYS", accounts.map((a) => a.getUserOnboardInfo()?.aesKey).join(","))
  } else {
    accounts = await Promise.all(wallets.map(async (account, i) => await toAccount(account, userKeys[i])))
  }

  return accounts
}

function setEnvValue(key: string, value: string) {
  fs.appendFileSync("./.env", `\n${key}=${value}`, "utf8")
}
