const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

const INITIAL_BALANCE = 500000000

module.exports = buildModule("PrivateERC20", (m) => {
  const erc20 = m.contract("PrivateERC20", ["Soda", "SOD", INITIAL_BALANCE])

  const balance = m.call(erc20, "balanceOf")

  return { erc20, balance }
})
