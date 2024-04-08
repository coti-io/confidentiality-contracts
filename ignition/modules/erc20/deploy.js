const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

const INITIAL_BALANCE = 500000000

module.exports = buildModule("DeployPrivateERC20", (m) => {
  const token = m.contract("PrivateERC20", ["Soda", "SOD", INITIAL_BALANCE])

  return { token }
})
