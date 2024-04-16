import hre from "hardhat"
import { expect } from "chai"
import { decryptValue, prepareIT } from "./util/crypto"
import { setupAccounts } from "./util/onboard"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("NFTExample")
  const contract = await factory.connect(owner.wallet).deploy({ gasLimit })
  await contract.waitForDeployment()
  // const contract = await hre.ethers.getContractAt("NFTExample", "0x1Da1088ae90438f137826F7F4902914B503765dA")
  // console.log(`contractAddress ${await contract.getAddress()}`)
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("Confidential NFT", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("Deployment", function () {
    it("Deployed address should be a valid Ethereum address", async function () {
      expect(hre.ethers.isAddress(deployment.contractAddress)).to.eq(true)
    })

    it("Name should match deployment name", async function () {
      expect(await deployment.contract.name()).to.equal("Example")
    })

    it("Symbol should match deployment symbol", async function () {
      expect(await deployment.contract.symbol()).to.equal("EXL")
    })

    it("Owner of first token should be deployer", async function () {
      const tokenId = 0
      expect(await deployment.contract.ownerOf(tokenId)).to.equal(deployment.owner.wallet.address)
    })

    it("Total supply should be 1", async function () {
      expect(await deployment.contract.totalSupply()).to.equal(1)
    })

    it("Contract owner should be the owner", async function () {
      expect(await deployment.contract.owner()).to.equal(deployment.owner.wallet.address)
    })
  })

  describe("Minting", function () {
    it("Should mint new token to otherAccount", async function () {
      const { contract, owner, otherAccount } = deployment

      const startTokenIds = await deployment.contract.totalSupply()

      await expect(
        (await contract.connect(owner.wallet).mint(otherAccount.wallet.address, { gasLimit })).wait()
      ).to.emit(contract, "Minted")

      const endTokenIds = await deployment.contract.totalSupply()

      const newTokenId = startTokenIds
      expect(await contract.ownerOf(newTokenId)).to.equal(otherAccount.wallet.address)
      expect(endTokenIds).to.equal(startTokenIds + BigInt(1))
    })

    it("Should fail to mint if not owner", async function () {
      const { contract, otherAccount } = deployment

      const tx = await contract.connect(otherAccount.wallet).mint(otherAccount.wallet.address, { gasLimit })
      let reverted = true
      try {
        await tx.wait()
        reverted = false
      } catch (error) {}
      expect(reverted).to.eq(true, "Should have reverted")
    })
  })

  describe("Transfers", function () {
    it("Should transfer token to other account", async function () {
      const { contract, owner, otherAccount } = deployment

      const tokenId = await deployment.contract.totalSupply()
      await (await contract.connect(owner.wallet).mint(owner.wallet.address, { gasLimit })).wait()

      await (await contract.connect(owner.wallet).approve(otherAccount.wallet.address, tokenId, { gasLimit })).wait()

      await (
        await contract
          .connect(owner.wallet)
          .transferFrom(owner.wallet.address, otherAccount.wallet.address, tokenId, { gasLimit })
      ).wait()
      expect(await contract.ownerOf(tokenId)).to.equal(otherAccount.wallet.address)
    })

    it("Should fail transfer token to other account for when no allowance", async function () {
      const { contract, owner, otherAccount } = deployment

      const tokenId = await deployment.contract.totalSupply()
      await (await contract.connect(owner.wallet).mint(owner.wallet.address, { gasLimit })).wait()

      const tx = await contract
        .connect(otherAccount.wallet)
        .transferFrom(owner.wallet.address, otherAccount.wallet.address, tokenId, { gasLimit })
      let reverted = true
      try {
        await tx.wait()
        reverted = false
      } catch (error) {}
      expect(reverted).to.eq(true, "Should have reverted")
    })

    it("Should fail to transfer from non-owner", async function () {
      const { contract, owner, otherAccount } = deployment

      const tokenId = await deployment.contract.totalSupply()
      await (await contract.connect(owner.wallet).mint(owner.wallet.address, { gasLimit })).wait()

      const tx = await contract
        .connect(otherAccount.wallet)
        .transferFrom(owner.wallet.address, otherAccount.wallet.address, tokenId, { gasLimit })
      let reverted = true
      try {
        await tx.wait()
        reverted = false
      } catch (error) {}
      expect(reverted).to.eq(true, "Should have reverted")

      // await expect(
      //   (
      //     await contract.connect(otherAccount.wallet).transferFrom(owner.wallet.address, otherAccount.wallet.address, tokenId, { gasLimit })
      //   ).wait()
      // ).to.be.revertedWith("ERC721: transfer caller is not owner nor approved")
    })
  })

  describe("URI", function () {
    it("should return 0 for token URI if not set", async function () {
      const { contract, owner } = deployment

      const tokenId = 0
      const ctURI = await contract.connect(owner.wallet).tokenURI(tokenId)
      const uri = decryptValue(ctURI, owner.userKey)
      expect(uri).to.equal(0)
    })

    it("should allow owner to set token URI", async function () {
      const { contract, contractAddress, owner } = deployment

      const tokenId = 0
      const uri = 11

      const func = contract.connect(owner.wallet).setTokenURI
      const selector = func.fragment.selector
      let { ctInt, signature } = await prepareIT(BigInt(uri), owner, contractAddress, selector)
      await (await func(tokenId, ctInt, signature, { gasLimit })).wait()

      const ctRetrievedUri = await contract.tokenURI(tokenId)
      expect(decryptValue(ctRetrievedUri, owner.userKey)).to.equal(uri)
    })

    it("should revert when non-owner tries to set token URI", async function () {
      const { contract, contractAddress, otherAccount } = deployment

      const tokenId = 0
      const uri = 11

      const func = contract.connect(otherAccount.wallet).setTokenURI
      const selector = func.fragment.selector
      let { ctInt, signature } = await prepareIT(BigInt(uri), otherAccount, contractAddress, selector)

      const tx = await func(tokenId, ctInt, signature, { gasLimit })
      let reverted = true
      try {
        await tx.wait()
        reverted = false
      } catch (error) {}
      expect(reverted).to.eq(true, "Should have reverted")
    })

    it("should emit MetadataUpdate event on setting token URI", async function () {
      const { contract, contractAddress, owner } = deployment

      const tokenId = 0
      const uri = 11

      const func = contract.connect(owner.wallet).setTokenURI
      const selector = func.fragment.selector
      let { ctInt, signature } = await prepareIT(BigInt(uri), owner, contractAddress, selector)

      const ctRetrievedUri = await contract.tokenURI(tokenId)
      expect(decryptValue(ctRetrievedUri, owner.userKey)).to.equal(uri)

      await expect((await func(tokenId, ctInt, signature, { gasLimit })).wait())
        .to.emit(contract, "MetadataUpdate")
        .withArgs(tokenId)
    })
  })
})
