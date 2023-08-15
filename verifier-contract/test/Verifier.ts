import { expect } from "chai";
import { ethers } from "hardhat";
import * as fs from "fs/promises";

describe("Verifier", function () {
    it("Should verify success", async function () {
      // verifier contract bytecode and calldata
      const CONTRACT_BYTECODE = await fs.readFile("./deployment_code.txt", "utf-8");
      const CALLDATA = await fs.readFile("./calldata.txt", "utf-8");

      // verifier contract deployer
      const signer = await ethers.getSigners();
      const factory = ethers.ContractFactory.fromSolidity(
        { bytecode: CONTRACT_BYTECODE, abi: [] },
        signer[0]
      );

      // depoly verifier contract
      const verifier = await factory.deploy();
      await verifier.deployed();

      // depoly rollup contract
      const Rollup = await ethers.getContractFactory("Rollup");
      const rollup = await Rollup.deploy(verifier.address);
      await rollup.deployed();

      expect(await rollup.verify(CALLDATA)).equal(true);
    });
});
