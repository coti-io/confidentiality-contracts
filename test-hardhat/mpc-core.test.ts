import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "./util/onboard"
import { itString } from "@coti-io/coti-ethers"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("TestMpcCore")
  const contract = await factory.connect(owner as any).deploy({ gasLimit })
  await contract.waitForDeployment()
  
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

function formatString(str: string) {
    return str.replace(/\0/g, '')
}

describe("MPC Core", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("Set user-encrypted string using an encrypted value", function () {
    const str = "Hello, World!"

    it("Should store the string encrypted using the users key", async function () {
        const { contract, contractAddress, owner } = deployment
    
        const itString = await owner.encryptValue(
            str,
            contractAddress,
            contract.setUserEncryptedString.fragment.selector
        ) as itString

        const tx = await contract
            .connect(owner as any)
            .setUserEncryptedString(itString, { gasLimit })
        
        await tx.wait()
    })

    it("Should retrieve the string encrypted with the users key", async function () {
        const { contract, owner } = deployment

        const userEncryptedString = await contract.getUserEncryptedString()

        const decryptedStr = await owner.decryptValue(userEncryptedString)

        expect(decryptedStr).to.equal(str)
    })

    it("Should fail to decrypt the string encrypted with the users key", async function () {
        const { contract, otherAccount } = deployment

        const userEncryptedString = await contract.getUserEncryptedString()

        const decryptedStr = await otherAccount.decryptValue(userEncryptedString)

        expect(decryptedStr).to.not.equal(str)
    })
  })

  describe("Set network-encrypted string using an encrypted value", function () {
    const str = "Hi, Mom!"

    it("Should store the string encrypted using the network key", async function () {
        const { contract, contractAddress, owner } = deployment
    
        const itString = await owner.encryptValue(
            str,
            contractAddress,
            contract.setNetworkEncryptedString.fragment.selector
        ) as itString

        const tx = await contract
            .connect(owner as any)
            .setNetworkEncryptedString(itString, { gasLimit })
        
        await tx.wait()
    })

    it("Should decrypt the network-encrypted string and store it in clear text", async function () {
        const { contract, owner } = deployment

        const tx = await contract
            .connect(owner as any)
            .decryptNetworkEncryptedString()

        await tx.wait()

        const decryptedStr = await contract.plaintext()

        expect(formatString(decryptedStr)).to.equal(str)
    })
  })

  describe("Set user-encrypted string using a non-encrypted value", function () {
    const str = "Hello darkness, my old friend."

    it("Should store the string encrypted using the users key", async function () {
        const { contract, owner } = deployment

        const tx = await contract
            .connect(owner as any)
            .setPublicString(str, { gasLimit })

        await tx.wait()
    })

    it("Should retrieve the string encrypted with the users key", async function () {
        const { contract, owner } = deployment

        const userEncryptedString = await contract.getUserEncryptedString()

        const decryptedStr = await owner.decryptValue(userEncryptedString)

        expect(decryptedStr).to.equal(str)
    })
  })

  describe("Set isEqual using two encrypted values", function () {
    const a = "ABC"
    const b = "DEF"

    describe("Using eq", function () {
        it("Should set isEqual to true", async function () {
            const { contract, contractAddress, owner } = deployment
    
            const itString = await owner.encryptValue(
                a,
                contractAddress,
                contract.setIsEqual.fragment.selector
            ) as itString
    
            const tx = await contract
                .connect(owner as any)
                .setIsEqual(itString, itString, true, { gasLimit })
            
            await tx.wait()
    
            const isEqual = await contract.isEqual()
    
            expect(isEqual).to.equal(true)
        })
    
        it("Should set isEqual to false", async function () {
            const { contract, contractAddress, owner } = deployment
    
            const itStringA = await owner.encryptValue(
                a,
                contractAddress,
                contract.setIsEqual.fragment.selector
            ) as itString
    
            const itStringB = await owner.encryptValue(
                b,
                contractAddress,
                contract.setIsEqual.fragment.selector
            ) as itString
    
            const tx = await contract
                .connect(owner as any)
                .setIsEqual(itStringA, itStringB, true, { gasLimit })
            
            await tx.wait()
    
            const isEqual = await contract.isEqual()
    
            expect(isEqual).to.equal(false)
        })
    })

    describe("Using ne", function () {
        it("Should set isEqual to false", async function () {
            const { contract, contractAddress, owner } = deployment
    
            const itStringA = await owner.encryptValue(
                a,
                contractAddress,
                contract.setIsEqual.fragment.selector
            ) as itString
    
            const itStringB = await owner.encryptValue(
                b,
                contractAddress,
                contract.setIsEqual.fragment.selector
            ) as itString
    
            const tx = await contract
                .connect(owner as any)
                .setIsEqual(itStringA, itStringB, false, { gasLimit })
            
            await tx.wait()
    
            const isEqual = await contract.isEqual()
    
            expect(isEqual).to.equal(false)
        })

        it("Should set isEqual to false", async function () {
            const { contract, contractAddress, owner } = deployment
    
            const itString = await owner.encryptValue(
                a,
                contractAddress,
                contract.setIsEqual.fragment.selector
            ) as itString
    
            const tx = await contract
                .connect(owner as any)
                .setIsEqual(itString, itString, false, { gasLimit })
            
            await tx.wait()
    
            const isEqual = await contract.isEqual()
    
            expect(isEqual).to.equal(true)
        })
    })
  })
})