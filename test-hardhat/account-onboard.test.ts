import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "./util/onboard"
import { generateRSAKeyPair } from "@coti-io/coti-sdk-typescript"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("AccountOnboard")
  const contract = await factory.connect(owner as any).deploy({ gasLimit })
  await contract.waitForDeployment()
  
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("Account Onboard", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  it('Should successfully onboard the account', async function () {
    const { owner } = deployment

    await owner.generateOrRecoverAes()

    expect(owner.getUserOnboardInfo()?.aesKey).to.not.equal('')
  })

  it('Should revert when the signature is empty', async function () {
    const { owner, contract } = deployment

    const { publicKey } = generateRSAKeyPair()

    const tx = await contract
        .connect(owner as any)
        .onboardAccount(publicKey, '0x')
    
    expect(tx).to.be.reverted
  })
})
