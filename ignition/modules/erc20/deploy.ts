import { buildModule } from "@nomicfoundation/hardhat-ignition/modules"

const INITIAL_BALANCE = 500000000

const Deploy = buildModule("DeployConfidentialERC20", (m) => {
  const token = m.contract("ConfidentialERC20", ["Soda", "SOD", INITIAL_BALANCE])

  return { token }
})

export default Deploy
