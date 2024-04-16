import { HardhatUserConfig } from "hardhat/config"
import "@nomicfoundation/hardhat-toolbox"
import dotenv from "dotenv"
dotenv.config()

const config: HardhatUserConfig = {
  defaultNetwork: "devnet",
  solidity: "0.8.24",
  networks: {
    // hardhat: {},
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
