import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "./util/onboard"
import { deploymentInfo } from "./confidential-erc20.test"
import { itUint, Wallet } from "@coti-io/coti-ethers"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const tokenContract = await hre.ethers.getContractFactory("ERC20Example")
  const { name, symbol, initialSupply } = deploymentInfo
  const token = await tokenContract
    .connect(owner as any)
    .deploy(name, symbol, initialSupply, { gasLimit, from: owner.address })
  await token.waitForDeployment()

  const factory = await hre.ethers.getContractFactory("ConfidentialAuction")
  const contract = await factory
    .connect(owner as any)
    .deploy(otherAccount.address, await token.getAddress(), 60 * 60 * 24, true, { gasLimit })
  await contract.waitForDeployment()
  
  return { token, contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

async function expectBalance(
  token: Awaited<ReturnType<typeof deploy>>["token"],
  amount: number,
  wallet: Wallet
) {
  const ctBalance = await token.connect(wallet as any).balanceOf()
  let balance = await wallet.decryptValue(ctBalance)
  expect(balance).to.equal(amount)
}

async function expectBid(
  contract: Awaited<ReturnType<typeof deploy>>["contract"],
  amount: number,
  wallet: Wallet
) {
  const ctBid = await contract.connect(wallet as any).getBid.staticCall()
  let bid = await wallet.decryptValue(ctBid)
  expect(bid).to.equal(amount)
}

describe("Confidential Auction", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("Deployment", function () {
    it("Deployed address should not be undefined", async function () {
      expect(deployment.contractAddress).to.not.equal(undefined)
    })

    it("Function 'bidCounter' should be correct", async function () {
      expect(await deployment.contract.bidCounter()).to.equal(0)
    })

    it("Function 'endTime' should be correct", async function () {
      expect(await deployment.contract.endTime()).not.to.equal(0)
    })

    it("Function 'contractOwner' should be correct", async function () {
      expect(await deployment.contract.contractOwner()).to.equal(deployment.owner.address)
    })

    it("Function 'beneficiary' should be correct", async function () {
      expect(await deployment.contract.beneficiary()).to.equal(deployment.otherAccount.address)
    })
  })

  describe("Bidding", function () {
    const bidAmount = 5
    it(`Bid ${bidAmount}`, async function () {
      const { token, contract, contractAddress, owner } = deployment

      const initialBalance = Number(await owner.decryptValue(await token.connect(owner as any).balanceOf()))

      await (await token.connect(owner as any).approveClear(contractAddress, bidAmount, { gasLimit })).wait()

      const func = contract.connect(owner as any).bid
      const selector = func.fragment.selector

      const { ciphertext, signature } = await owner.encryptValue(bidAmount, contractAddress, selector) as itUint

      await (await func(ciphertext, signature , { gasLimit })).wait()

      await expectBalance(token, initialBalance - bidAmount, owner)

      expectBid(contract, bidAmount, owner)
    })

    it(`Increase Bid ${bidAmount * 2}`, async function () {
      const { token, contract, contractAddress, owner } = deployment

      const initialBalance = Number(await owner.decryptValue(await token.connect(owner as any).balanceOf()))

      await (await token.connect(owner as any).approveClear(contractAddress, bidAmount * 2, { gasLimit })).wait()

      const func = contract.connect(owner as any).bid
      const selector = func.fragment.selector
      
      const { ciphertext, signature } = await owner.encryptValue(bidAmount * 2, contractAddress, selector) as itUint

      await (await func(ciphertext, signature , { gasLimit })).wait()

      await expectBalance(token, initialBalance - bidAmount, owner)

      expectBid(contract, bidAmount * 2, owner)
    })

    it(`Winner`, async function () {
      const { contract, owner } = deployment

      await (await contract.connect(owner as any).stop({ gasLimit })).wait()

      const receipt = await (await contract.connect(owner as any).doIHaveHighestBid({ gasLimit })).wait()

      const ctBool = (receipt!.logs[0] as any).args[0]

      let isHighestBid = await owner.decryptValue(ctBool)

      expect(isHighestBid).to.eq(1)
    })
  })
})
