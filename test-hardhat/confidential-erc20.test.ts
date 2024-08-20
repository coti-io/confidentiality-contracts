import hre from "hardhat"
import { expect } from "chai"
import { type ConfidentialAccount, decryptUint, buildInputText } from "@coti-io/coti-sdk-typescript"
import { setupAccounts } from "./util/onboard"

export const deploymentInfo = { name: "My Confidential Token", symbol: "CTOK", decimals: 5, initialSupply: 500000000 } as const
const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const tokenContract = await hre.ethers.getContractFactory("ERC20Example")
  const { name, symbol, initialSupply } = deploymentInfo
  const token = await tokenContract
    .connect(owner.wallet)
    .deploy(name, symbol, initialSupply, { gasLimit, from: owner.wallet.address })
  const contract = await token.waitForDeployment()
  // const contract = await hre.ethers.getContractAt("ERC20Example", "0x19c0bb1bf8b923855598405ab9cc88c4a8aa9540")
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

async function expectBalance(
  token: Awaited<ReturnType<typeof deploy>>["contract"],
  amount: number,
  user: ConfidentialAccount
) {
  const ctBalance = await token.connect(user.wallet).balanceOf()
  let balance = decryptUint(ctBalance, user.userKey)
  expect(balance).to.equal(amount)
}

async function expectAllowance(
  contract: Awaited<ReturnType<typeof deploy>>["contract"],
  amount: number,
  owner: ConfidentialAccount,
  spenderAddress: string
) {
  const ctAllowance = await contract.allowance(owner.wallet.address, spenderAddress)
  let allowance = decryptUint(ctAllowance, owner.userKey)
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

      let my_balance = decryptUint(my_CTBalance, owner.userKey)
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
      const initialBalance = Number(decryptUint(await deployment.contract.balanceOf(), owner.userKey))

      await (
        await contract
          .connect(owner.wallet)
          ["transfer(address,uint64,bool)"](otherAccount.wallet.address, transferAmount, true, { gasLimit })
      ).wait()

      await expectBalance(contract, initialBalance - transferAmount, owner)

      await (
        await contract
          .connect(owner.wallet)
          ["transfer(address,uint64,bool)"](otherAccount.wallet.address, transferAmount, true, { gasLimit })
      ).wait()

      await expectBalance(contract, initialBalance - 2 * transferAmount, owner)
    })

    it("Transfer - Confidential", async function () {
      const { contract, contractAddress, owner, otherAccount } = deployment
      const initialBalance = Number(decryptUint(await deployment.contract.balanceOf(), owner.userKey))

      const func = contract.connect(owner.wallet)["transfer(address,uint256,bytes,bool)"]
      const selector = func.fragment.selector
      const { ciphertext, signature } = await buildInputText(BigInt(transferAmount), owner, contractAddress, selector)

      await (await func(otherAccount.wallet.address, ciphertext, signature, false, { gasLimit })).wait()
      await expectBalance(contract, initialBalance - transferAmount, owner)
    })

    it("TransferFrom - clear without giving allowance should fail", async function () {
      const { contract, owner, otherAccount } = deployment
      const initialBalance = Number(decryptUint(await deployment.contract.balanceOf(), owner.userKey))

      await (await contract.connect(owner.wallet).approveClear(otherAccount.wallet.address, 0, { gasLimit })).wait()

      const func = contract.connect(owner.wallet)["transferFrom(address,address,uint64,bool)"]
      await (await func(owner.wallet.address, otherAccount.wallet.address, transferAmount, true, { gasLimit })).wait()
      await expectBalance(contract, initialBalance, owner)
    })

    it("TransferFrom - clear", async function () {
      const { contract, owner, otherAccount } = deployment

      await (
        await contract.connect(owner.wallet).approveClear(otherAccount.wallet.address, transferAmount, { gasLimit })
      ).wait()

      const func = contract.connect(owner.wallet)["transferFrom(address,address,uint64,bool)"]
      await (await func(owner.wallet.address, otherAccount.wallet.address, transferAmount, true, { gasLimit })).wait()
    })

    it("TransferFrom - Confidential", async function () {
      const { contract, contractAddress, owner, otherAccount } = deployment

      const initialBalance = Number(decryptUint(await deployment.contract.balanceOf(), owner.userKey))

      await (
        await contract.connect(owner.wallet).approveClear(otherAccount.wallet.address, transferAmount, { gasLimit })
      ).wait()

      const func = contract.connect(owner.wallet)["transferFrom(address,address,uint256,bytes,bool)"]
      const selector = func.fragment.selector
      let { ciphertext, signature } = await buildInputText(BigInt(transferAmount), owner, contractAddress, selector)
      await (
        await func(owner.wallet.address, otherAccount.wallet.address, ciphertext, signature, false, { gasLimit })
      ).wait()

      await expectBalance(contract, initialBalance - transferAmount, owner)
    })

    it("Approve/Allowance - Confidential", async function () {
      const { contract, contractAddress, owner, otherAccount } = deployment

      await (await contract.connect(owner.wallet).approveClear(otherAccount.wallet.address, 0, { gasLimit })).wait()
      await expectAllowance(contract, 0, owner, otherAccount.wallet.address)

      const func = contract.connect(owner.wallet)["approve(address,uint256,bytes)"]
      const selector = func.fragment.selector
      const { ciphertext, signature } = await buildInputText(BigInt(transferAmount), owner, contractAddress, selector)
      await (await func(otherAccount.wallet.address, ciphertext, signature, { gasLimit })).wait()

      await expectAllowance(contract, transferAmount, owner, otherAccount.wallet.address)
    })
  })
})
