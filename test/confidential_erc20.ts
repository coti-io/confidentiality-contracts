import hre from "hardhat"
import { expect } from "chai"
import { decryptValue, prepareIT } from "./util/crypto"

const deploymentInfo = { name: "Soda", symbol: "SOD", decimals: 5, initialSupply: 500000000 } as const

async function deploy() {
  const [owner] = await hre.ethers.getSigners()
  const otherAccount = hre.ethers.Wallet.createRandom(hre.ethers.provider)

  const recoverContractFactory = await hre.ethers.getContractFactory("RecoverMessage")
  const recoverContract = await (await recoverContractFactory.deploy()).waitForDeployment()
  console.log(`recoverContract address ${await recoverContract.getAddress()}`)
  // const tokenContract = await hre.ethers.getContractFactory("ConfidentialERC20")
  // const { name, symbol, initialSupply } = deploymentInfo
  // const token = await tokenContract.deploy(name, symbol, initialSupply, { gasLimit: 12000000, from: owner.address })
  // const contract = await token.waitForDeployment()
  const contract = await hre.ethers.getContractAt("ConfidentialERC20", "0x19c0bb1bf8b923855598405ab9cc88c4a8aa9540")
  return { contract, recoverContract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

async function expectBalance(contract: Awaited<ReturnType<typeof deploy>>["contract"], amount: number) {
  const ctBalance = await contract.balanceOf()
  let my_balance = decryptValue(ctBalance)
  expect(my_balance).to.equal(amount)
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
  describe(`Transfer $${transferAmount}`, function () {
    it("Transfer clear", async function () {
      const { contract, owner, otherAccount } = deployment

      await (
        await contract.connect(owner)["transfer(address,uint64,bool)"](otherAccount.address, transferAmount, true, { gasLimit: 12000000 })
      ).wait()

      await expectBalance(contract, deploymentInfo.initialSupply - transferAmount)

      await (
        await contract.connect(owner)["transfer(address,uint64,bool)"](otherAccount.address, transferAmount, true, { gasLimit: 12000000 })
      ).wait()

      await expectBalance(contract, deploymentInfo.initialSupply - 2 * transferAmount)
    })

    it.only("Transfer", async function () {
      const { contract, contractAddress, owner, otherAccount, recoverContract } = deployment

      const selector = contract["transfer(address,uint256,bytes,bool)"].fragment.selector
      console.log(`selector ${selector}`)

      const { ctInt, signature } = await prepareIT(transferAmount.toString(), owner, contractAddress, recoverContract, selector)
      await (
        await contract.connect(owner)["transfer(address,uint256,bytes,bool)"](otherAccount.address, ctInt, signature, true, { gasLimit: 12000000 })
      ).wait()
    })
  })
})
