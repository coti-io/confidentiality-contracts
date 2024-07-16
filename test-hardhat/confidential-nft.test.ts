import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "./util/onboard"
import { ContractTransactionReceipt } from "ethers"
import { decryptString, buildStringInputText } from "@coti-io/coti-sdk-typescript"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("ConfidentialNFTExample")
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

    it("Contract owner should be the owner", async function () {
      expect(await deployment.contract.owner()).to.equal(deployment.owner.wallet.address)
    })
  })

  describe("Minting", function () {
    const tokenURI = 'https://api.pudgypenguins.io/lil/18707'

    describe("Successful mint", function () {
      let tx: ContractTransactionReceipt | null

      before(async function () {
        const { contract, contractAddress, owner, otherAccount } = deployment
        
        const encryptedTokenURI = await buildStringInputText(tokenURI, owner, contractAddress, contract.mint.fragment.selector)

        tx = await (
          await contract
            .connect(owner.wallet)
            .mint(
              otherAccount.wallet.address,
              encryptedTokenURI.map((val) => val.ciphertext),
              encryptedTokenURI.map((val) => val.signature),
              { gasLimit })
          ).wait()
      })
      
      it("Should emit a 'Minted' event", async function () {
        const { contract } = deployment
  
        expect(tx).to.emit(contract, "Minted")
      })

      it("Should update the owners mapping", async function () {
        const { contract, otherAccount } = deployment
  
        expect(await contract.ownerOf(BigInt(0))).to.equal(otherAccount.wallet.address)
      })

      it("Should update the balances mapping", async function () {
        const { contract, otherAccount } = deployment
  
        expect(await contract.balanceOf(otherAccount.wallet.address)).to.equal(BigInt(1))
      })

    })

    it("Should fail to mint if not owner", async function () {
      const { contract, contractAddress, otherAccount } = deployment

      const encryptedTokenURI = await buildStringInputText(tokenURI, otherAccount, contractAddress, contract.mint.fragment.selector)

      const tx = await contract
        .connect(otherAccount.wallet)
        .mint(
          otherAccount.wallet.address,
          encryptedTokenURI.map((val) => val.ciphertext),
          encryptedTokenURI.map((val) => val.signature),
          { gasLimit }
        )
      
      expect(tx).to.be.reverted
    })

    it("Should fail to mint if the encrypted token URI is faulty", async function () {
      const { contract, contractAddress, otherAccount } = deployment

      const ownerEncryptedTokenURI = await buildStringInputText(tokenURI, otherAccount, contractAddress, contract.mint.fragment.selector)
      const otherAccountEncryptedTokenURI = await buildStringInputText(tokenURI, otherAccount, contractAddress, contract.mint.fragment.selector)

      const tx = await contract
        .connect(otherAccount.wallet)
        .mint(
          otherAccount.wallet.address,
          ownerEncryptedTokenURI.map((val) => val.ciphertext),
          otherAccountEncryptedTokenURI.map((val) => val.signature),
          { gasLimit }
        )
      
      expect(tx).to.be.reverted
    })
  })

  describe("URI", function () {
    it("should return 0 for token URI if not set", async function () {
      const { contract, owner } = deployment

      const tokenId = BigInt(1)
      const ctURI = await contract.connect(owner.wallet).tokenURI(tokenId)
      const uri = decryptString(ctURI, owner.userKey)
      
      expect(uri).to.equal("")
    })
  })

  describe("Transfers", function () {
    describe("Successful transfer", function () {
      const tokenId = BigInt(0)
      const tokenURI = 'https://api.pudgypenguins.io/lil/18707'

      before(async function () {
        const { contract, owner, otherAccount } = deployment

        await (await contract.connect(otherAccount.wallet).approve(owner.wallet.address, tokenId, { gasLimit })).wait()

        await (
          await contract
            .connect(owner.wallet)
            .transferFrom(otherAccount.wallet.address, owner.wallet.address, tokenId, { gasLimit })
        ).wait()
      })

      it("Should transfer token to other account", async function () {
        const { contract, owner, otherAccount } = deployment
  
        expect(await contract.ownerOf(tokenId)).to.equal(owner.wallet.address)
        expect(await contract.balanceOf(owner.wallet.address)).to.equal(BigInt(1))
        expect(await contract.balanceOf(otherAccount.wallet.address)).to.equal(BigInt(0))
      })

      it("Should allow the new owner to decrypt the token URI", async function () {
        const { contract, owner } = deployment

        const encryptedTokenURI = await contract.tokenURI(tokenId)

        const decryptedTokenURI = decryptString(encryptedTokenURI, owner.userKey)

        expect(decryptedTokenURI).to.equal(tokenURI)
      })
      
      it("Should not allow the previous owner to decrypt the token URI", async function () {
        const { contract, otherAccount } = deployment

        const encryptedTokenURI = await contract.tokenURI(tokenId)

        const decryptedTokenURI = decryptString(encryptedTokenURI, otherAccount.userKey)

        expect(decryptedTokenURI).to.not.equal(tokenURI)
      })
    })

    describe("Failed transfers", function () {
      const tokenURI = 'https://api.pudgypenguins.io/lil/9040'

      it("Should fail transfer token to other account for when no allowance", async function () {
        const { contract, contractAddress, owner, otherAccount } = deployment

        const encryptedTokenURI = await buildStringInputText(tokenURI, owner, contractAddress, contract.mint.fragment.selector)
  
        const tokenId = await deployment.contract.totalSupply()
        
        await (
          await contract
            .connect(owner.wallet)
            .mint(
              owner.wallet.address,
              encryptedTokenURI.map((val) => val.ciphertext),
              encryptedTokenURI.map((val) => val.signature),
              { gasLimit }
            )
        ).wait()
  
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
        const { contract, contractAddress, owner, otherAccount } = deployment

        const encryptedTokenURI = await buildStringInputText(tokenURI, owner, contractAddress, contract.mint.fragment.selector)
  
        const tokenId = await deployment.contract.totalSupply()
        
        await (
          await contract
            .connect(owner.wallet)
            .mint(
              owner.wallet.address,
              encryptedTokenURI.map((val) => val.ciphertext),
              encryptedTokenURI.map((val) => val.signature),
              { gasLimit }
            )
        ).wait()
  
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
