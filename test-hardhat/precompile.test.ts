import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "./util/onboard"

const gasLimit = 12000000
let last_random_value = 0

function buildTest(
  contractName: string,
  func: string,
  resFunc: string,
  params: (bigint | number | boolean)[],
  ...expectedResults: (number | boolean | bigint)[]
) {
  it(`${contractName}.${func}(${params}) should return ${expectedResults}`, async function () {
    const [owner] = await setupAccounts()

    const factory = await hre.ethers.getContractFactory(contractName, owner.wallet)
    const contract = await factory.deploy({ gasLimit })
    await contract.waitForDeployment()

    await (await contract.getFunction(func)(...params, { gasLimit })).wait()
    const result = await contract.getFunction(resFunc)()
    if (resFunc === "getRandom" || resFunc === "getRandomBounded") {
      expect(result).to.not.equal(expectedResults[0])
      last_random_value = result
    } else if (expectedResults.length === 1) {
      expect(result).to.equal(expectedResults[0])
    } else {
      expect(result).to.deep.equal(expectedResults)
    }
  })
}

function buildTestWithUser(contractName: string, func: string, resFunc: string, param: bigint | number | boolean) {
  it(`${contractName}.${func}(${params}, <address>) should return the correct user decrypted value`, async function () {
    const [owner] = await setupAccounts()

    const factory = await hre.ethers.getContractFactory(contractName, owner.wallet)
    const contract = await factory.deploy({ gasLimit })
    await contract.waitForDeployment()

    await (await contract.getFunction(func)(param, owner.wallet.address, { gasLimit: 12000000 })).wait()
    const results = await contract.getFunction(resFunc)()
    for (const result of results) {
      expect(owner.decryptUint(result)).to.equal(param)
    }
  })
}

const params = [10, 5]
const shift = 2
const bit = false
const numBits = 7
const bool_a = true
const bool_b = false
const [a, b] = params
describe("Precompile", function () {
  buildTest("PrecompilesArythmeticTestsContract", "addTest", "getAddResult", params, a + b)
  buildTest("PrecompilesArythmeticTestsContract", "subTest", "getSubResult", params, a - b)
  buildTest("PrecompilesArythmeticTestsContract", "mulTest", "getMulResult", params, a * b)

  buildTest("PrecompilesMiscellaneousTestsContract", "divTest", "getDivResult", params, a / b)
  buildTest("PrecompilesMiscellaneousTestsContract", "remTest", "getRemResult", params, a % b)

  buildTest("PrecompilesBitwiseTestsContract", "andTest", "getAndResult", params, a & b)
  buildTest("PrecompilesBitwiseTestsContract", "orTest", "getOrResult", params, a | b)
  buildTest("PrecompilesBitwiseTestsContract", "xorTest", "getXorResult", params, a ^ b)

  buildTest("PrecompilesMinMaxTestsContract", "minTest", "getMinResult", params, Math.min(a, b))
  buildTest("PrecompilesMinMaxTestsContract", "maxTest", "getMaxResult", params, Math.max(a, b))
  buildTest("PrecompilesComparison2TestsContract", "eqTest", "getEqResult", params, a == b)
  buildTest("PrecompilesComparison2TestsContract", "neTest", "getNeResult", params, a != b)
  buildTest("PrecompilesComparison2TestsContract", "geTest", "getGeResult", params, a >= b)
  buildTest("PrecompilesComparison1TestsContract", "gtTest", "getGtResult", params, a > b)
  buildTest("PrecompilesComparison1TestsContract", "leTest", "getLeResult", params, a <= b)
  buildTest("PrecompilesComparison1TestsContract", "ltTest", "getLtResult", params, a < b)
  buildTest("PrecompilesMiscellaneousTestsContract", "muxTest", "getMuxResult", [bit, a, b], bit === false ? a : b)

  buildTest("PrecompilesTransferTestsContract", "transferTest", "getResults", [a, b, b], a - b, b + b, true)
  buildTest("PrecompilesTransferScalarTestsContract", "transferScalarTest", "getResults", [a, b, b], a - b, b + b, true)
  buildTest("PrecompilesOffboardToUserKeyTestContract", "offboardOnboardTest", "getOnboardOffboardResult", [a, a, a, a], a)
  buildTest("PrecompilesMiscellaneousTestsContract", "notTest", "getBoolResult", [!!a], !a)

  buildTestWithUser("PrecompilesOffboardToUserKeyTestContract", "offboardToUserTest", "getCTs", a)
  buildTest("PrecompilesMiscellaneous1TestsContract", "randomTest", "getRandom", [], last_random_value)
  buildTest("PrecompilesMiscellaneous1TestsContract", "randomBoundedTest", "getRandomBounded", [numBits], last_random_value)
  buildTest(
    "PrecompilesMiscellaneous1TestsContract",
    "booleanTest",
    "getBooleanResults",
    [bool_a, bool_b, bit],
    bool_a && bool_b,
    bool_a || bool_b,
    bool_a != (bool_b as boolean),
    !bool_a,
    bool_a === (bool_b as boolean),
    bool_a != (bool_b as boolean),
    bit ? bool_b : bool_a,
    bool_a
  )


  // buildTest(
  //   "PrecompilesShiftTestsContract",
  //   "shlTest",
  //   "getAllShiftResults",
  //   [a, shift],
  //   ...[2, 4, 8, 16].map((x) => BigInt(a << shift) & BigInt(`0x${"f".repeat(x)}`))
  // )
  // buildTest("PrecompilesShiftTestsContract", "shrTest", "getResult", params, a >> b)
})
