import hre from "hardhat"
import { expect } from "chai"
import { decryptValue, prepareIT } from "./util/crypto"

const gasLimit = 12000000

async function deploy() {
  const [owner] = await hre.ethers.getSigners()
  const otherAccount = hre.ethers.Wallet.createRandom(hre.ethers.provider)

  const factory = await hre.ethers.getContractFactory("NFTExample")
  const contract = await factory.connect(owner).deploy({ gasLimit })
  await contract.waitForDeployment()
  // const contract = await hre.ethers.getContractAt("ConfidentialAuction", "0xFA71F49669d65dbb91d268780828cB2449CB473c")
  //   console.log(`contractAddress ${await contract.getAddress()}`)
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe.only("Confidential NFT", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("Deployment", function () {
    it("Deployed address should be a valid Ethereum address", async function () {
      expect(deployment.contractAddress).to.match(/^0x[a-fA-F0-9]{40}$/)
    })

    it("Name should match deployment name", async function () {
      expect(await deployment.contract.name()).to.equal("Example")
    })

    it("Symbol should match deployment symbol", async function () {
      expect(await deployment.contract.symbol()).to.equal("EXL")
    })

    it("Owner of first token should be deployer", async function () {
      const tokenId = 0
      expect(await deployment.contract.ownerOf(tokenId)).to.equal(deployment.owner.address)
    })
  })

  describe("Minting", function () {
    it("Should mint new token to owner", async function () {
      const { contract, owner } = deployment

      const startTokenIds = await deployment.contract.totalSupply()

      await contract.connect(owner).mint(owner.address)

      const endTokenIds = await deployment.contract.totalSupply()

      expect(endTokenIds).to.equal(startTokenIds + BigInt(1))

      const newTokenId = startTokenIds
      expect(await contract.ownerOf(newTokenId)).to.equal(owner.address)
    })

    it("Should fail to mint if not owner", async function () {
      const { contract, otherAccount } = deployment

      await expect(contract.connect(otherAccount).mint(otherAccount.address)).to.be.revertedWith(
        "Ownable: caller is not the owner"
      )
    })
  })

  describe("Transfers", function () {
    it("Should transfer token to other account", async function () {
      const { contract, owner, otherAccount } = deployment

      await contract.connect(owner).mint(owner.address)
      const tokenId = 0

      await contract.connect(owner).transferFrom(owner.address, otherAccount.address, tokenId)

      expect(await contract.ownerOf(tokenId)).to.equal(otherAccount.address)
    })

    it("Should fail to transfer from non-owner", async function () {
      const { contract, owner, otherAccount } = deployment

      await contract.connect(owner).mint(owner.address)
      const tokenId = 0

      await expect(
        contract.connect(otherAccount).transferFrom(owner.address, otherAccount.address, tokenId)
      ).to.be.revertedWith("ERC721: transfer caller is not owner nor approved")
    })
  })
})
