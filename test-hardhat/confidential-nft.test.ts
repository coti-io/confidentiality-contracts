import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "./util/onboard"
import { decryptString, encryptString } from "./util/string-encryption"

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
      expect(await contract.balanceOf(otherAccount.wallet.address)).to.equal(BigInt(1))
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

  describe("URI", function () {
    it("should return 0 for token URI if not set", async function () {
      const { contract, owner } = deployment

      const tokenId = 0
      const ctURI = await contract.connect(owner.wallet).tokenURI(tokenId)
      const uri = decryptString(ctURI, owner)
      expect(uri).to.equal("")
    })

    it("should allow owner to set token URI", async function () {
      const { contract, contractAddress, owner } = deployment

      const tokenId = BigInt(0)
      const uri = 'https://api.pudgypenguins.io/lil/9040'

      const encryptedTokenURI = await encryptString(uri, owner, contractAddress, contract.setTokenURI.fragment.selector)

      await (await contract
        .connect(owner.wallet)
        .setTokenURI(tokenId, encryptedTokenURI.map((val) => val.ciphertext), encryptedTokenURI.map((val) => val.signature), { gasLimit }))
        .wait()
      
      const ctRetrievedUri = await contract.tokenURI(tokenId)

      expect(decryptString(ctRetrievedUri, owner)).to.equal(uri)
    })

    it("should revert when non-owner tries to set token URI", async function () {
      const { contract, contractAddress, otherAccount } = deployment

      const tokenId = BigInt(0)
      const uri = ''

      const encryptedTokenURI = await encryptString(uri, otherAccount, contractAddress, contract.setTokenURI.fragment.selector)

      const tx = await contract
        .connect(otherAccount.wallet)
        .setTokenURI(tokenId, encryptedTokenURI.map((val) => val.ciphertext), encryptedTokenURI.map((val) => val.signature), { gasLimit })
      
      expect(tx).to.be.reverted
    })

    it("should emit MetadataUpdate event on setting token URI", async function () {
      const { contract, contractAddress, owner } = deployment

      const tokenId = BigInt(0)
      const uri = 'https://api.pudgypenguins.io/lil/18707'

      const encryptedTokenURI = await encryptString(uri, owner, contractAddress, contract.setTokenURI.fragment.selector)

      const receipt = await (await contract
        .connect(owner.wallet)
        .setTokenURI(tokenId, encryptedTokenURI.map((val) => val.ciphertext), encryptedTokenURI.map((val) => val.signature), { gasLimit }))
        .wait()
      
      await expect(receipt)
        .to.emit(contract, "MetadataUpdate")
        .withArgs(tokenId)
    })
  })

  describe("Transfers", function () {
    describe("Successful transfer", function () {
      const tokenId = BigInt(0)
      const tokenURI = 'https://api.pudgypenguins.io/lil/18707'

      before(async function () {
        const { contract, owner, otherAccount } = deployment

        await (await contract.connect(owner.wallet).approve(otherAccount.wallet.address, tokenId, { gasLimit })).wait()

        await (
          await contract
            .connect(owner.wallet)
            .transferFrom(owner.wallet.address, otherAccount.wallet.address, tokenId, { gasLimit })
        ).wait()
      })

      it("Should transfer token to other account", async function () {
        const { contract, owner, otherAccount } = deployment
  
        expect(await contract.ownerOf(tokenId)).to.equal(otherAccount.wallet.address)
        expect(await contract.balanceOf(owner.wallet.address)).to.equal(BigInt(0))
        expect(await contract.balanceOf(otherAccount.wallet.address)).to.equal(BigInt(2))
      })

      it("Should allow the new owner to decrypt the token URI", async function () {
        const { contract, otherAccount } = deployment

        const encryptedTokenURI = await contract.tokenURI(tokenId)

        const decryptedTokenURI = decryptString(encryptedTokenURI, otherAccount)

        expect(decryptedTokenURI).to.equal(tokenURI)
      })
      
      it("Should not allow the previous owner to decrypt the token URI", async function () {
        const { contract, owner } = deployment

        const encryptedTokenURI = await contract.tokenURI(tokenId)

        const decryptedTokenURI = decryptString(encryptedTokenURI, owner)

        expect(decryptedTokenURI).to.not.equal(tokenURI)
      })
    })

    describe("Failed transfers", function () {
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
        })
      })
    })
})
