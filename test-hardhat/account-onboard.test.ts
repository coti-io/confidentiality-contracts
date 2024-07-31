import hre from "hardhat"
import { expect } from "chai"
import { ConfidentialAccount, generateRSAKeyPair } from "@coti-io/coti-sdk-typescript"
import { setupAccounts } from "./util/onboard"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("AccountOnboard")
  const contract = await factory.connect(owner.wallet).deploy({ gasLimit })
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

    const account = await ConfidentialAccount.onboard(owner.wallet)

    expect(account.userKey).to.not.equal('')
  })

//   it('Should revert when reusing inputs from a different accounts onboard tx', async function () {
//     expect(true).to.equal(false)
//   })

  it('Should revert when the signature is empty', async function () {
    const { owner, contract } = deployment

    const { publicKey } = generateRSAKeyPair()

    const tx = await contract
        .connect(owner.wallet)
        .onboardAccount(publicKey, '0x')
    
    expect(tx).to.be.reverted
  })
})
