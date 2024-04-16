import { HardhatUserConfig } from "hardhat/config"
import "@nomicfoundation/hardhat-toolbox"
import dotenv from "dotenv"
dotenv.config()

const config: HardhatUserConfig = {
  defaultNetwork: "cotiv2",
  solidity: "0.8.24",
  networks: {
    // hardhat: {},
    cotiv2: {
      url: "https://node.sodalabs.net",
      chainId: 50505050,
    },
    devnet: {
      url: "https://devnet.coti.io",
      chainId: 13068200,
    },
  },
  paths:{
    tests:'test-hardhat',
  }
}

export default config
