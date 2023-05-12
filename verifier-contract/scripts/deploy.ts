const hre = require("hardhat");
import * as fs from "fs/promises";

async function readFile(path: string): Promise<string> {
  try {
    const data = await fs.readFile(path, "utf-8");
    return data;
  } catch (err) {
    console.error(err);
    return "";
  }
}

async function main() {
  const CONTRACT_BYTECODE = await readFile("./deployment_code.txt");
  const CALLDATA = await readFile("./calldata.txt");

  const signer = await hre.ethers.getSigners();
  const factory = hre.ethers.ContractFactory.fromSolidity(
    { bytecode: CONTRACT_BYTECODE, abi: [] },
    signer[0]
  );
  const contract = await factory.deploy();
  await contract.deployed();

  const Verifier = await hre.ethers.getContractFactory("Verifier");
  const verifier = await Verifier.deploy(contract.address);
  await verifier.deployed();

  const ret = await verifier.verify(CALLDATA);
  console.log(ret);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
