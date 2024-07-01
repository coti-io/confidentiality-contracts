import hre from "hardhat"
import { expect } from "chai"
import { decryptUint, prepareUintIT } from "@coti-io/coti-sdk-typescript"
import { setupAccounts } from "./util/onboard"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("ConfidentialIdentityRegistry")
  const contract = await factory.connect(owner.wallet).deploy({ gasLimit })
  await contract.waitForDeployment()
  // const contract = await hre.ethers.getContractAt("ConfidentialAuction", "0xFA71F49669d65dbb91d268780828cB2449CB473c")
  //   console.log(`contractAddress ${await contract.getAddress()}`)
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("Confidential Identity", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()

    const tx1 = await deployment.contract.addRegistrar(deployment.owner.wallet.address, 1, { gasLimit })
    const tx2 = await deployment.contract.addDid(deployment.owner.wallet.address, { gasLimit })
    const tx3 = await deployment.contract.addDid(deployment.otherAccount.wallet.address, { gasLimit })
    await Promise.all([tx1, tx2, tx3].map((tx) => tx.wait()))
  })

  const idAge = 18
  it(`Set Age Id ${idAge}`, async function () {
    const { contract, contractAddress, owner } = deployment

    const func = contract.connect(owner.wallet).setIdentifier
    const selector = func.fragment.selector
    const { ctInt, signature } = await prepareUintIT(BigInt(idAge), owner, contractAddress, selector)
    await (await func(owner.wallet.address, "age", ctInt, signature, { gasLimit })).wait()

    await (await contract.grantAccess(deployment.owner.wallet.address, ["age"], { gasLimit })).wait()
    const ctAge = await contract.getIdentifier.staticCall(deployment.owner.wallet.address, "age", { gasLimit })
    expect(decryptUint(ctAge, owner.userKey)).to.eq(idAge)
  })

  it("Should revert when trying to get identifier without access", async function () {
    const { contract, otherAccount, owner } = deployment

    await expect(
      contract
        .connect(otherAccount.wallet)
        .getIdentifier.staticCall(owner.wallet.address, "age", { gasLimit, from: otherAccount.wallet.address })
    ).to.be.revertedWith("User didn't give you permission to access this identifier.")
  })

  it("Should get identifier if access is granted", async function () {
    const { contract, otherAccount, owner } = deployment

    await (await contract.connect(owner.wallet).grantAccess(otherAccount.wallet.address, ["age"], { gasLimit })).wait()

    const ctAge = await contract
      .connect(otherAccount.wallet)
      .getIdentifier.staticCall(owner.wallet.address, "age", { gasLimit, from: otherAccount.wallet.address })
    expect(decryptUint(ctAge, otherAccount.userKey)).to.eq(idAge)
  })
})
