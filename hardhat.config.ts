import { HardhatUserConfig } from "hardhat/config"
import "@nomicfoundation/hardhat-toolbox"

const accounts = process.env.SIGNING_KEY ? [process.env.SIGNING_KEY] : undefined

const config: HardhatUserConfig = {
  defaultNetwork: "cotiv2",
  solidity: "0.8.24",
  networks: {
    // hardhat: {},
    cotiv2: {
      url: "https://node.sodalabs.net",
      chainId: 50505050,
      accounts,
    },
  },
}

export default config
