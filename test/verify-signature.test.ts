import hre, { ethers } from "hardhat"
import { expect } from "chai"

describe("ECDSA Verify Signature", function () {
  it.skip("test", async function () {
    const contract = await (await (await hre.ethers.getContractFactory("RecoverMessage")).deploy()).waitForDeployment()

    const [owner] = await hre.ethers.getSigners()
    const hash = ethers.solidityPackedKeccak256(["string"], ["hello"])
    const message = ethers.getBytes(hash)
    const signature = await owner.signMessage(message)
    const verified = ethers.verifyMessage(message, signature)
    expect(verified).to.eq(owner.address)

    expect(await contract.recoverECDSA(message, signature)).to.eq(owner.address)
  })
})
