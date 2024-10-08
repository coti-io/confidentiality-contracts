import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "./util/onboard"
import { itUint, Wallet } from "@coti-io/coti-ethers"

export const deploymentInfo = { name: "My Confidential Token", symbol: "CTOK", decimals: 5, initialSupply: 500000000 } as const
const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const tokenContract = await hre.ethers.getContractFactory("ERC20Example")
  const { name, symbol, initialSupply } = deploymentInfo
  const token = await tokenContract
    .connect(owner as any)
    .deploy(name, symbol, initialSupply, { gasLimit, from: owner.address })
  const contract = await token.waitForDeployment()

  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

async function expectBalance(
  token: Awaited<ReturnType<typeof deploy>>["contract"],
  amount: number,
  wallet: Wallet
) {
  const ctBalance = await token.connect(wallet as any).balanceOf()
  let balance = await wallet.decryptValue(ctBalance)
  expect(balance).to.equal(amount)
}

async function expectAllowance(
  contract: Awaited<ReturnType<typeof deploy>>["contract"],
  amount: number,
  owner: Wallet,
  spenderAddress: string
) {
  const ctAllowance = await contract.allowance(owner.address, spenderAddress)
  let allowance = await owner.decryptValue(ctAllowance)
  expect(allowance).to.equal(amount)
}

describe("Confidential ERC20", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("Deployment", function () {
    it("Deployed address should not be undefined", async function () {
      const { contractAddress } = deployment

      expect(contractAddress).to.not.equal(undefined)
    })

    it("Owner initial balance", async function () {
      const { contract, owner } = deployment

      const my_CTBalance = await contract.balanceOf()

      let my_balance = await owner.decryptValue(my_CTBalance)

      expect(my_balance).to.equal(deploymentInfo.initialSupply)
    })

    it("Function 'name' should be correct", async function () {
      expect(await deployment.contract.name()).to.equal(deploymentInfo.name)
    })

    it("Function 'symbol' should be correct", async function () {
      expect(await deployment.contract.symbol()).to.equal(deploymentInfo.symbol)
    })

    it("Function 'decimals' should be correct", async function () {
      expect(await deployment.contract.decimals()).to.equal(deploymentInfo.decimals)
    })

    it("Function 'totalSupply' should be correct", async function () {
      expect(await deployment.contract.totalSupply()).to.equal(deploymentInfo.initialSupply)
    })
  })

  const transferAmount = 5
  describe(`Transfer ${transferAmount}`, function () {
    it("Transfer - clear", async function () {
      const { contract, owner, otherAccount } = deployment
      const initialBalance = Number(await owner.decryptValue(await deployment.contract.balanceOf()))

      await (
        await contract
          .connect(owner as any)
          ["transfer(address,uint64,bool)"](otherAccount.address, transferAmount, true, { gasLimit })
      ).wait()

      await expectBalance(contract, initialBalance - transferAmount, owner)

      await (
        await contract
          .connect(owner as any)
          ["transfer(address,uint64,bool)"](otherAccount.address, transferAmount, true, { gasLimit })
      ).wait()

      await expectBalance(contract, initialBalance - 2 * transferAmount, owner)
    })

    it("Transfer - Confidential", async function () {
      const { contract, contractAddress, owner, otherAccount } = deployment
      const initialBalance = Number(await owner.decryptValue(await deployment.contract.balanceOf()))

      const func = contract.connect(owner as any)["transfer(address,uint256,bytes,bool)"]
      const selector = func.fragment.selector
      const { ciphertext, signature } = await owner.encryptValue(BigInt(transferAmount), contractAddress, selector) as itUint

      await (await func(otherAccount.address, ciphertext, signature, false, { gasLimit })).wait()
      await expectBalance(contract, initialBalance - transferAmount, owner)
    })

    it("TransferFrom - clear without giving allowance should fail", async function () {
      const { contract, owner, otherAccount } = deployment
      const initialBalance = Number(await owner.decryptValue(await deployment.contract.balanceOf()))

      await (await contract.connect(owner as any).approveClear(otherAccount.address, 0, { gasLimit })).wait()

      const func = contract.connect(owner as any)["transferFrom(address,address,uint64,bool)"]
      await (await func(owner.address, otherAccount.address, transferAmount, true, { gasLimit })).wait()
      await expectBalance(contract, initialBalance, owner)
    })

    it("TransferFrom - clear", async function () {
      const { contract, owner, otherAccount } = deployment

      await (
        await contract.connect(owner as any).approveClear(otherAccount.address, transferAmount, { gasLimit })
      ).wait()

      const func = contract.connect(owner as any)["transferFrom(address,address,uint64,bool)"]
      await (await func(owner.address, otherAccount.address, transferAmount, true, { gasLimit })).wait()
    })

    it("TransferFrom - Confidential", async function () {
      const { contract, contractAddress, owner, otherAccount } = deployment

      const initialBalance = Number(await owner.decryptValue(await deployment.contract.balanceOf()))

      await (
        await contract.connect(owner as any).approveClear(otherAccount.address, transferAmount, { gasLimit })
      ).wait()

      const func = contract.connect(owner as any)["transferFrom(address,address,uint256,bytes,bool)"]
      const selector = func.fragment.selector
      let { ciphertext, signature } = await owner.encryptValue(BigInt(transferAmount), contractAddress, selector) as itUint
      await (
        await func(owner.address, otherAccount.address, ciphertext, signature, false, { gasLimit })
      ).wait()

      await expectBalance(contract, initialBalance - transferAmount, owner)
    })

    it("Approve/Allowance - Confidential", async function () {
      const { contract, contractAddress, owner, otherAccount } = deployment

      await (await contract.connect(owner as any).approveClear(otherAccount.address, 0, { gasLimit })).wait()
      await expectAllowance(contract, 0, owner, otherAccount.address)

      const func = contract.connect(owner as any)["approve(address,uint256,bytes)"]
      const selector = func.fragment.selector
      const { ciphertext, signature } = await owner.encryptValue(BigInt(transferAmount), contractAddress, selector) as itUint
      await (await func(otherAccount.address, ciphertext, signature, { gasLimit })).wait()

      await expectAllowance(contract, transferAmount, owner, otherAccount.address)
    })
  })
})
