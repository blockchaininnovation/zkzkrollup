import { expect } from "chai";
import { ethers } from "hardhat";
import * as fs from "fs/promises";

describe("Verifier", function () {
    let rollup;

    beforeEach(async () => {
      // verifier contract bytecode and calldata
      const CONTRACT_BYTECODE = await fs.readFile("./deployment_code.txt", "utf-8");

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
      rollup = await Rollup.deploy(verifier.address);
      await rollup.deployed();
    })

    it("Should update state root", async function () {
      const proof = await fs.readFile("./calldata.txt", "utf-8");
      const currentRoot = "0x"
      const newRoot = "0x2bae4558bd55acffed88900450df52615f0f101574fcbac3d106bb407a196065"
      const transactions = "0x1b5b9ccb3e8d006a5230de9bda23ff91edc794d4f56410560830b418528e446c"

      // current root check
      const current_root = await rollup.getStateRoot();
      expect(current_root).equal(currentRoot);

      // update root check
      await rollup.batch(currentRoot, newRoot, transactions, proof)
      const new_root = await rollup.getStateRoot()
      expect(new_root).equal(newRoot);
    });
});
