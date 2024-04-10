import hre from "hardhat"
import { expect } from "chai"
import { decryptValue, prepareIT } from "./util/crypto"

const gasLimit = 12000000

async function deploy() {
  const [owner] = await hre.ethers.getSigners()
  const otherAccount = hre.ethers.Wallet.createRandom(hre.ethers.provider)

  const factory = await hre.ethers.getContractFactory("ConfidentialIdentityRegistry")
  const contract = await factory.connect(owner).deploy({ gasLimit })
  await contract.waitForDeployment()
  // const contract = await hre.ethers.getContractAt("ConfidentialAuction", "0xFA71F49669d65dbb91d268780828cB2449CB473c")
  //   console.log(`contractAddress ${await contract.getAddress()}`)
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe.only("Confidential Identity", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()

    await deployment.contract.addRegistrar(deployment.owner.address, 1, { gasLimit })
    await deployment.contract.addDid(deployment.owner.address, { gasLimit })
  })

  const idAge = 18
  it(`Set Age Id $${idAge}`, async function () {
    const { contract, contractAddress, owner } = deployment

    const func = contract.connect(owner).setIdentifier
    const selector = func.fragment.selector
    const { ctInt, signature } = await prepareIT(BigInt(idAge), owner, contractAddress, selector)
    await (await func(owner.address, "age", ctInt, signature, { gasLimit })).wait()

    await contract.grantAccess(deployment.owner.address, ["age"], { gasLimit })
    const ctAge = await contract.getIdentifier.staticCall(deployment.owner.address, "age", { gasLimit })
    expect(decryptValue(ctAge)).to.eq(idAge)
  })
})
