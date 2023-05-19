// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

contract Verifier {
    address yulVerifier;

    constructor(address _yulVerifier) {
        yulVerifier = _yulVerifier;
    }

    function verify(bytes calldata input) external view returns (bool) {
        (bool success, ) = yulVerifier.staticcall(input);
        return success;
    }
}
