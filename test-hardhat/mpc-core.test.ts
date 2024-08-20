import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "./util/onboard"
import { decryptString, buildStringInputText } from "@coti-io/coti-sdk-typescript"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("TestMpcCore")
  const contract = await factory.connect(owner.wallet).deploy({ gasLimit })
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
    
        const itString = buildStringInputText(
            str,
            { wallet: owner.wallet, userKey: owner.userKey },
            contractAddress,
            contract.setUserEncryptedString.fragment.selector
        )

        const tx = await contract
            .connect(owner.wallet)
            .setUserEncryptedString(itString, { gasLimit })
        
        await tx.wait()
    })

    it("Should retrieve the string encrypted with the users key", async function () {
        const { contract, owner } = deployment

        const userEncryptedString = await contract.getUserEncryptedString()

        const decryptedStr = decryptString(userEncryptedString, owner.userKey)

        expect(decryptedStr).to.equal(str)
    })

    it("Should fail to decrypt the string encrypted with the users key", async function () {
        const { contract, otherAccount } = deployment

        const userEncryptedString = await contract.getUserEncryptedString()

        const decryptedStr = decryptString(userEncryptedString, otherAccount.userKey)

        expect(decryptedStr).to.not.equal(str)
    })
  })

  describe("Set network-encrypted string using an encrypted value", function () {
    const str = "Hi, Mom!"

    it("Should store the string encrypted using the network key", async function () {
        const { contract, contractAddress, owner } = deployment
    
        const itString = buildStringInputText(
            str,
            { wallet: owner.wallet, userKey: owner.userKey },
            contractAddress,
            contract.setNetworkEncryptedString.fragment.selector
        )

        const tx = await contract
            .connect(owner.wallet)
            .setNetworkEncryptedString(itString, { gasLimit })
        
        await tx.wait()
    })

    it("Should decrypt the network-encrypted string and store it in clear text", async function () {
        const { contract, owner } = deployment

        const tx = await contract
            .connect(owner.wallet)
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
            .connect(owner.wallet)
            .setPublicString(str, { gasLimit })

        await tx.wait()
    })

    it("Should retrieve the string encrypted with the users key", async function () {
        const { contract, owner } = deployment

        const userEncryptedString = await contract.getUserEncryptedString()

        const decryptedStr = decryptString(userEncryptedString, owner.userKey)

        expect(decryptedStr).to.equal(str)
    })
  })

  describe("Set isEqual using two encrypted values", function () {
    const a = "ABC"
    const b = "DEF"

    describe("Using eq", function () {
        it("Should set isEqual to true", async function () {
            const { contract, contractAddress, owner } = deployment
    
            const itString = buildStringInputText(
                a,
                { wallet: owner.wallet, userKey: owner.userKey },
                contractAddress,
                contract.setIsEqual.fragment.selector
            )
    
            const tx = await contract
                .connect(owner.wallet)
                .setIsEqual(itString, itString, true, { gasLimit })
            
            await tx.wait()
    
            const isEqual = await contract.isEqual()
    
            expect(isEqual).to.equal(true)
        })
    
        it("Should set isEqual to false", async function () {
            const { contract, contractAddress, owner } = deployment
    
            const itStringA = buildStringInputText(
                a,
                { wallet: owner.wallet, userKey: owner.userKey },
                contractAddress,
                contract.setIsEqual.fragment.selector
            )
    
            const itStringB = buildStringInputText(
                b,
                { wallet: owner.wallet, userKey: owner.userKey },
                contractAddress,
                contract.setIsEqual.fragment.selector
            )
    
            const tx = await contract
                .connect(owner.wallet)
                .setIsEqual(itStringA, itStringB, true, { gasLimit })
            
            await tx.wait()
    
            const isEqual = await contract.isEqual()
    
            expect(isEqual).to.equal(false)
        })
    })

    describe("Using ne", function () {
        it("Should set isEqual to true", async function () {
            const { contract, contractAddress, owner } = deployment
    
            const itStringA = buildStringInputText(
                a,
                { wallet: owner.wallet, userKey: owner.userKey },
                contractAddress,
                contract.setIsEqual.fragment.selector
            )
    
            const itStringB = buildStringInputText(
                b,
                { wallet: owner.wallet, userKey: owner.userKey },
                contractAddress,
                contract.setIsEqual.fragment.selector
            )
    
            const tx = await contract
                .connect(owner.wallet)
                .setIsEqual(itStringA, itStringB, false, { gasLimit })
            
            await tx.wait()
    
            const isEqual = await contract.isEqual()
    
            expect(isEqual).to.equal(false)
        })

        it("Should set isEqual to false", async function () {
            const { contract, contractAddress, owner } = deployment
    
            const itString = buildStringInputText(
                a,
                { wallet: owner.wallet, userKey: owner.userKey },
                contractAddress,
                contract.setIsEqual.fragment.selector
            )
    
            const tx = await contract
                .connect(owner.wallet)
                .setIsEqual(itString, itString, false, { gasLimit })
            
            await tx.wait()
    
            const isEqual = await contract.isEqual()
    
            expect(isEqual).to.equal(true)
        })
    })
  })

  describe("Set user-encrypted string using a random value", function () {
    const str = "Hello darkness, my old friend."

    it("It should store the encrypted string using the users key", async function () {
        const { contract, owner } = deployment

        const tx = await contract
            .connect(owner.wallet)
            .setRandomString({ gasLimit })

        await tx.wait()
    })

    it("It should retrieve the string encrypted with the users key", async function () {
        const { contract, owner } = deployment

        const userEncryptedString = await contract.getUserEncryptedString()

        const decryptedStr = decryptString(userEncryptedString, owner.userKey)

        expect(decryptedStr).to.not.equal(str)
    })
  })
})