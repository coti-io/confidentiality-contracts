import hre from "hardhat"
import { expect } from "chai"
import { decryptValue, prepareIT } from "./util/crypto"

const deploymentInfo = { name: "Soda", symbol: "SOD", decimals: 5, initialSupply: 500000000 } as const
const gasLimit = 12000000

async function deploy() {
  const [owner] = await hre.ethers.getSigners()
  const otherAccount = hre.ethers.Wallet.createRandom(hre.ethers.provider)

  const tokenContract = await hre.ethers.getContractFactory("ERC20Example")
  const { name, symbol, initialSupply } = deploymentInfo
  const token = await tokenContract.deploy(name, symbol, initialSupply, { gasLimit, from: owner.address })
  const contract = await token.waitForDeployment()
  // const contract = await hre.ethers.getContractAt("ERC20Example", "0x19c0bb1bf8b923855598405ab9cc88c4a8aa9540")
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

async function expectBalance(contract: Awaited<ReturnType<typeof deploy>>["contract"], amount: number) {
  const ctBalance = await contract.balanceOf()
  let my_balance = decryptValue(ctBalance)
  expect(my_balance).to.equal(amount)
}

async function expectAllowance(
  contract: Awaited<ReturnType<typeof deploy>>["contract"],
  amount: number,
  ownerAddress: string,
  spenderAddress: string
) {
  const ctAllowance = await contract.allowance(ownerAddress, spenderAddress)
  let allowance = decryptValue(ctAllowance)
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
      const { contract } = deployment

      const my_CTBalance = await contract.balanceOf()

      let my_balance = decryptValue(my_CTBalance)
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
      const initlalBalance = decryptValue(await deployment.contract.balanceOf())

      await (
        await contract
          .connect(owner)
          ["transfer(address,uint64,bool)"](otherAccount.address, transferAmount, true, { gasLimit })
      ).wait()

      await expectBalance(contract, initlalBalance - transferAmount)

      await (
        await contract
          .connect(owner)
          ["transfer(address,uint64,bool)"](otherAccount.address, transferAmount, true, { gasLimit })
      ).wait()

      await expectBalance(contract, initlalBalance - 2 * transferAmount)
    })

    it("Transfer - Confidential", async function () {
      const { contract, contractAddress, owner, otherAccount } = deployment
      const initlalBalance = decryptValue(await deployment.contract.balanceOf())

      const func = contract.connect(owner)["transfer(address,uint256,bytes,bool)"]
      const selector = func.fragment.selector
      const { ctInt, signature } = await prepareIT(BigInt(transferAmount), owner, contractAddress, selector)

      await (await func(otherAccount.address, ctInt, signature, false, { gasLimit })).wait()
      await expectBalance(contract, initlalBalance - transferAmount)
    })

    it("TransferFrom - clear without giving allowance should fail", async function () {
      const { contract, owner, otherAccount } = deployment
      const initlalBalance = decryptValue(await deployment.contract.balanceOf())

      await (await contract.connect(owner).approveClear(otherAccount.address, 0, { gasLimit })).wait()

      const func = contract.connect(owner)["transferFrom(address,address,uint64,bool)"]
      await (await func(owner.address, otherAccount.address, transferAmount, true, { gasLimit })).wait()
      await expectBalance(contract, initlalBalance)
    })

    it("TransferFrom - clear", async function () {
      const { contract, owner, otherAccount } = deployment

      await (await contract.connect(owner).approveClear(otherAccount.address, transferAmount, { gasLimit })).wait()

      const func = contract.connect(owner)["transferFrom(address,address,uint64,bool)"]
      await (await func(owner.address, otherAccount.address, transferAmount, true, { gasLimit })).wait()
    })

    it("TransferFrom - Confidential", async function () {
      const { contract, contractAddress, owner, otherAccount } = deployment

      const initlalBalance = decryptValue(await deployment.contract.balanceOf())

      await (await contract.connect(owner).approveClear(otherAccount.address, transferAmount, { gasLimit })).wait()

      const func = contract.connect(owner)["transferFrom(address,address,uint256,bytes,bool)"]
      const selector = func.fragment.selector
      let { ctInt, signature } = await prepareIT(BigInt(transferAmount), owner, contractAddress, selector)
      await (await func(owner.address, otherAccount.address, ctInt, signature, false, { gasLimit })).wait()

      await expectBalance(contract, initlalBalance - transferAmount)
    })

    it("Approve/Allowance - Confidential", async function () {
      const { contract, contractAddress, owner, otherAccount } = deployment

      await (await contract.connect(owner).approveClear(otherAccount.address, 0, { gasLimit })).wait()
      await expectAllowance(contract, 0, owner.address, otherAccount.address)

      const func = contract.connect(owner)["approve(address,uint256,bytes)"]
      const selector = func.fragment.selector
      const { ctInt, signature } = await prepareIT(BigInt(transferAmount), owner, contractAddress, selector)
      await (await func(otherAccount.address, ctInt, signature, { gasLimit })).wait()

      await expectAllowance(contract, transferAmount, owner.address, otherAccount.address)
    })
  })
})
