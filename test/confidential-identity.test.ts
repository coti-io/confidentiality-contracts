import hre from "hardhat"
import { expect } from "chai"
import { decryptValue, prepareIT } from "./util/crypto"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await hre.ethers.getSigners()

  const factory = await hre.ethers.getContractFactory("ConfidentialIdentityRegistry")
  const contract = await factory.connect(owner).deploy({ gasLimit })
  await contract.waitForDeployment()
  // const contract = await hre.ethers.getContractAt("ConfidentialAuction", "0xFA71F49669d65dbb91d268780828cB2449CB473c")
  //   console.log(`contractAddress ${await contract.getAddress()}`)
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("Confidential Identity", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()

    const tx1 = await deployment.contract.addRegistrar(deployment.owner.address, 1, { gasLimit })
    const tx2 = await deployment.contract.addDid(deployment.owner.address, { gasLimit })
    const tx3 = await deployment.contract.addDid(deployment.otherAccount.address, { gasLimit })
    await Promise.all([tx1, tx2, tx3].map((tx) => tx.wait()))
  })

  const idAge = 18
  it(`Set Age Id ${idAge}`, async function () {
    const { contract, contractAddress, owner } = deployment

    const func = contract.connect(owner).setIdentifier
    const selector = func.fragment.selector
    const { ctInt, signature } = await prepareIT(BigInt(idAge), owner, contractAddress, selector)
    await (await func(owner.address, "age", ctInt, signature, { gasLimit })).wait()

    await (await contract.grantAccess(deployment.owner.address, ["age"], { gasLimit })).wait()
    const ctAge = await contract.getIdentifier.staticCall(deployment.owner.address, "age", { gasLimit })
    expect(decryptValue(ctAge)).to.eq(idAge)
  })

  it("Should revert when trying to get identifier without access", async function () {
    const { contract, otherAccount, owner } = deployment

    await expect(
      contract
        .connect(otherAccount)
        .getIdentifier.staticCall(owner.address, "age", { gasLimit, from: otherAccount.address })
    ).to.be.revertedWith("User didn't give you permission to access this identifier.")
  })

  it("Should get identifier if access is granted", async function () {
    const { contract, otherAccount, owner } = deployment

    await (await contract.connect(owner).grantAccess(otherAccount.address, ["age"], { gasLimit })).wait()
    console.log(`after graning access`)
    const ctAge = await contract
      .connect(otherAccount)
      .getIdentifier.staticCall(owner.address, "age", { gasLimit, from: otherAccount.address })
    expect(decryptValue(ctAge, Buffer.from(process.env.USER_KEY2 || "", "hex"))).to.eq(idAge)
  })
})
