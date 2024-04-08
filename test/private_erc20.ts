import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { expect } from "chai";
import hre from "hardhat";

describe("Private ERC20", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Network to that snapshot in every test.
  async function deploy() {
    const [owner, otherAccount] = await hre.ethers.getSigners();

    const Lock = await hre.ethers.getContractFactory("PrivateERC20");
    const lock = await Lock.deploy("Soda", "SOD", 500000000, { gasLimit: 12000000 });
    const contract = await lock.waitForDeployment();
    return { address: await contract.getAddress(), owner, otherAccount };
  }

  describe("Deployment", function () {
    it("Deployed address should not be undefined", async function () {
      const { address } = await deploy();

      expect(address).to.not.equal(undefined);
    });
  });
  
});
