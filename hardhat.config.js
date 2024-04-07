require("@nomicfoundation/hardhat-ignition-ethers")

const accounts = process.env.SIGNING_KEY ? [process.env.SIGNING_KEY] : undefined

module.exports = {
  defaultNetwork: "cotiv2",
  solidity: "0.8.24",
  networks: {
    cotiv2: {
      url: "https://node.sodalabs.net",
      chainId: 50505050,
      accounts,
    },
  },
}
