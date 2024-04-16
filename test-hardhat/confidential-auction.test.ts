import hre from "hardhat"
import { expect } from "chai"
import { decryptValue, prepareIT } from "./util/crypto"

const gasLimit = 12000000

async function deploy() {
  const [owner] = await hre.ethers.getSigners()
  const otherAccount = hre.ethers.Wallet.createRandom(hre.ethers.provider)

  const tokenAddress = "0x19c0bb1bf8b923855598405ab9cc88c4a8aa9540"
  const token = await hre.ethers.getContractAt("ERC20Example", tokenAddress)

  const factory = await hre.ethers.getContractFactory("ConfidentialAuction")
  const contract = await factory
    .connect(owner)
    .deploy(otherAccount.address, tokenAddress, 60 * 60 * 24, true, { gasLimit })
  await contract.waitForDeployment()
  // const contract = await hre.ethers.getContractAt("ConfidentialAuction", "0xFA71F49669d65dbb91d268780828cB2449CB473c")
  //   console.log(`contractAddress ${await contract.getAddress()}`)
  return { token, contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

async function expectBalance(token: Awaited<ReturnType<typeof deploy>>["token"], amount: number) {
  const ctBalance = await token.balanceOf()
  let balance = decryptValue(ctBalance)
  expect(balance).to.equal(amount)
}

async function expectBid(contract: Awaited<ReturnType<typeof deploy>>["contract"], amount: number) {
  const ctBalance = await contract.getBid.staticCall()
  let bid = decryptValue(ctBalance)
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
    it(`Bid $${bidAmount}`, async function () {
      const { token, contract, contractAddress, owner } = deployment

      const initialBalance = decryptValue(await token.connect(owner).balanceOf())

      await (await token.connect(owner).approveClear(contractAddress, bidAmount, { gasLimit })).wait()

      const func = contract.connect(owner).bid
      const selector = func.fragment.selector
      const { ctInt, signature } = await prepareIT(BigInt(bidAmount), owner, contractAddress, selector)
      await (await func(ctInt, signature, { gasLimit })).wait()

      await expectBalance(token, initialBalance - bidAmount)

      expectBid(contract, bidAmount)
    })

    it(`Increase Bid $${bidAmount * 2}`, async function () {
      const { token, contract, contractAddress, owner } = deployment

      const initialBalance = decryptValue(await token.connect(owner).balanceOf())

      await (await token.connect(owner).approveClear(contractAddress, bidAmount * 2, { gasLimit })).wait()

      const func = contract.connect(owner).bid
      const selector = func.fragment.selector
      const { ctInt, signature } = await prepareIT(BigInt(bidAmount * 2), owner, contractAddress, selector)
      await (await func(ctInt, signature, { gasLimit })).wait()

      await expectBalance(token, initialBalance - bidAmount)

      expectBid(contract, bidAmount * 2)
    })

    it(`Winner`, async function () {
      const { contract, owner } = deployment

      await (await contract.connect(owner).stop({ gasLimit })).wait()

      const ctBool = await contract.connect(owner).doIHaveHighestBid.staticCall({ gasLimit })
      let bool = decryptValue(ctBool)
      expect(bool).to.eq(1)
    })
  })
})
