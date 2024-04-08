import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { block_size, decrypt, prepareIT, hexBase } from "../soda-sdk/js/crypto.js";
import { expect } from "chai";
import hre from "hardhat";

const user_key = Buffer.from(process.env.USER_KEY ?? "", "hex");

function decryptValue(myCTBalance: any, userKey: any) {
  // Convert CT to bytes
  let ctString = myCTBalance.toString(hexBase);
  let ctArray = Buffer.from(ctString, "hex");
  while (ctArray.length < 32) {
    // When the first bits are 0, bigint bit size is less than 32 and need to re-add the bits
    ctString = "0" + ctString;
    ctArray = Buffer.from(ctString, "hex");
  }
  // Split CT into two 128-bit arrays r and cipher
  const cipher = ctArray.subarray(0, block_size);
  const r = ctArray.subarray(block_size);

  // Decrypt the cipher
  const decryptedMessage = decrypt(userKey, r, cipher);

  // console.log the decrypted cipher
  const decryptedBalance = parseInt(decryptedMessage.toString("hex"), block_size);

  return decryptedBalance;
}

describe("Private ERC20", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Network to that snapshot in every test.
  let deployment: Awaited<ReturnType<typeof deploy>>;

  before(async function () {
    const balance = await hre.ethers.provider.getBalance("0x40a60fF0F7bab9720BA6B7542d4480C9f4F7Ee8E");
    console.log("balance before: ", balance.toString());
    deployment = await deploy();

    const balanceAfter = await hre.ethers.provider.getBalance("0x40a60fF0F7bab9720BA6B7542d4480C9f4F7Ee8E");
    console.log("balance after: ", balanceAfter.toString());
  });

  async function deploy() {
    const [owner, otherAccount] = await hre.ethers.getSigners();

    const tokenContract = await hre.ethers.getContractFactory("PrivateERC20");
    const token = await tokenContract.deploy("Soda", "SOD", 500000000, { gasLimit: 12000000 });
    const contract = await token.waitForDeployment();
    return { contract, address: await contract.getAddress(), owner, otherAccount };
  }

  describe("Deployment", function () {
    it("Deployed address should not be undefined", async function () {
      const { address } = deployment;

      expect(address).to.not.equal(undefined);
    });

    it("Sender should have all the tokens", async function () {
      const { contract } = deployment;

      const my_CTBalance = await contract.balanceOf();

      let my_balance = decryptValue(my_CTBalance, user_key);
      expect(my_balance).to.equal(500000000);
    });
  });
});
