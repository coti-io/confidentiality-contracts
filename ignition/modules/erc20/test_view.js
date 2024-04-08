const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");
const deploy = require("./deploy")

module.exports = buildModule("TestPrivateERC20", (m) => {
  const { token } = m.useModule(deploy);

  console.log("************* View functions *************");
  const contractName = m.call(token, "name");
  console.log("Function call result name:", contractName);

  const symbol = m.call(token, "symbol");
  console.log("Function call result symbol:", symbol);

  const decimals = m.call(token, "decimals");
  console.log("Function call result decimals:", decimals);

  const totalSupply = m.call(token, "totalSupply");
  console.log("Function call result totalSupply:", totalSupply);
});
