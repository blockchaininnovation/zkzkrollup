// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import { IRollup } from "./IRollup.sol";

contract Rollup is IRollup {
    // on-chain users state root
    bytes merkleRoot;
    // deposit transaction index
    uint64 depositIndex;
    // individual number index
    uint64 individualNumberIndex;
    // ayer 2 operator address
    address operator;
    // deposit function verifier contract
    address depositVerifier;
    // batch function verifier contract
    address batchVerifier;
    // withdraw function verifier contract
    address withdrawVerifier;

    // on-chain withdraw Merkle tree key is EdDSA address
    mapping(address => withdrawInfo) withdrawTreeInfo;

    // on-chain deposit Merkle tree key is `depositIndex`
    mapping(uint64 => leafInfo) depositTreeInfo;

    /**
     * on-chain deposit information
     * individualNumber individual number index
     * jubjubAddress EdDSA depositor address
     */
    struct leafInfo {
        uint64 individualNumber;
        address jubjubAddress;
    }

    constructor(address _batchVerifier) {
        operator = msg.sender;
        batchVerifier = _batchVerifier;
    }

    function deposit(
        address from,
        uint256 public_key_x,
        uint256 public_key_y,
        uint32 amount,
        uint256 left_cipher_x,
        uint256 left_cipher_y,
        uint256 right_cipher_x,
        uint256 right_cipher_y,
        bytes calldata proof
    ) external {}

    function withdraw(
        address to,
        address from,
        uint32 amount,
        uint256 left_cipher_x,
        uint256 left_cipher_y,
        uint256 right_cipher_x,
        uint256 right_cipher_y,
        bytes calldata proof
    ) external {}

    function batch(
        bytes memory current_root,
        bytes memory new_root,
        bytes calldata transactions,
        bytes calldata proof
    ) external {}

    function verify(bytes calldata input) external view returns (bool) {
        (bool success, ) = batchVerifier.staticcall(input);
        return success;
    }
}
