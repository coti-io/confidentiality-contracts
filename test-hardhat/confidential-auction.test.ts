import hre from "hardhat"
import { expect } from "chai"
import { type ConfidentialAccount, decryptUint, buildInputText } from "@coti-io/coti-sdk-typescript"
import { setupAccounts } from "./util/onboard"
import { deploymentInfo } from "./confidential-erc20.test"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const tokenContract = await hre.ethers.getContractFactory("ERC20Example")
  const { name, symbol, initialSupply } = deploymentInfo
  const token = await tokenContract
    .connect(owner.wallet)
    .deploy(name, symbol, initialSupply, { gasLimit, from: owner.wallet.address })
  await token.waitForDeployment()

  const factory = await hre.ethers.getContractFactory("ConfidentialAuction")
  const contract = await factory
    .connect(owner.wallet)
    .deploy(otherAccount.wallet.address, await token.getAddress(), 60 * 60 * 24, true, { gasLimit })
  await contract.waitForDeployment()
  // const contract = await hre.ethers.getContractAt("ConfidentialAuction", "0xFA71F49669d65dbb91d268780828cB2449CB473c")
  //   console.log(`contractAddress ${await contract.getAddress()}`)
  return { token, contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

async function expectBalance(
  token: Awaited<ReturnType<typeof deploy>>["token"],
  amount: number,
  user: ConfidentialAccount
) {
  const ctBalance = await token.connect(user.wallet).balanceOf()
  let balance = decryptUint(ctBalance, user.userKey)
  expect(balance).to.equal(amount)
}

async function expectBid(
  contract: Awaited<ReturnType<typeof deploy>>["contract"],
  amount: number,
  user: ConfidentialAccount
) {
  const ctBalance = await contract.connect(user.wallet).getBid.staticCall()
  let bid = decryptUint(ctBalance, user.userKey)
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
      expect(await deployment.contract.contractOwner()).to.equal(deployment.owner.wallet.address)
    })

    it("Function 'beneficiary' should be correct", async function () {
      expect(await deployment.contract.beneficiary()).to.equal(deployment.otherAccount.wallet.address)
    })
  })

  describe("Bidding", function () {
    const bidAmount = 5
    it(`Bid ${bidAmount}`, async function () {
      const { token, contract, contractAddress, owner } = deployment

      const initialBalance = Number(decryptUint(await token.connect(owner.wallet).balanceOf(), owner.userKey))

      await (await token.connect(owner.wallet).approveClear(contractAddress, bidAmount, { gasLimit })).wait()

      const func = contract.connect(owner.wallet).bid
      const selector = func.fragment.selector
      const { ctInt, signature } = await buildInputText(BigInt(bidAmount), owner, contractAddress, selector)
      await (await func(ctInt, signature, { gasLimit })).wait()

      await expectBalance(token, initialBalance - bidAmount, owner)

      expectBid(contract, bidAmount, owner)
    })

    it(`Increase Bid ${bidAmount * 2}`, async function () {
      const { token, contract, contractAddress, owner } = deployment

      const initialBalance = Number(decryptUint(await token.connect(owner.wallet).balanceOf(), owner.userKey))

      await (await token.connect(owner.wallet).approveClear(contractAddress, bidAmount * 2, { gasLimit })).wait()

      const func = contract.connect(owner.wallet).bid
      const selector = func.fragment.selector
      const { ctInt, signature } = await buildInputText(BigInt(bidAmount * 2), owner, contractAddress, selector)
      await (await func(ctInt, signature, { gasLimit })).wait()

      await expectBalance(token, initialBalance - bidAmount, owner)

      expectBid(contract, bidAmount * 2, owner)
    })

    it(`Winner`, async function () {
      const { contract, owner } = deployment

      await (await contract.connect(owner.wallet).stop({ gasLimit })).wait()

      const receipt = await (await contract.connect(owner.wallet).doIHaveHighestBid({ gasLimit })).wait()

      const ctBool = (receipt!.logs[0] as any).args[0]

      let isHighestBid = decryptUint(ctBool, owner.userKey)
      expect(isHighestBid).to.eq(1)
    })
  })
})
