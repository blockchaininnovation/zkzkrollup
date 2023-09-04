// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

interface IRollup {
    /**
     * @dev on-chain users state root
     */
    bytes merkleRoot;

    /**
     * @dev on-chain users state root
     */
    uint64 depositIndex;

    /**
     * @dev individual number index
     */
    uint64 individualNumberIndex;

    /**
     * @dev on-chain deposit information
     * @param individualNumber individual number index
     * @param jubjubAddress EdDSA depositor address
     */
    struct leafInfo {
        uint64 individualNumber;
        address jubjubAddress;
    }

    /**
     * @dev on-chain deposit Merkle tree
     * key is `depositIndex`
     */
    mapping(uint64 => leafInfo) depositTreeInfo;

    /**
     * @dev on-chain withdraw information
     * @param is_withdraw is withdraw done
     * @param left_cipher_x Left cipher text x coordinate
     * @param left_cipher_y Left cipher text y coordinate
     * @param right_cipher_x Right cipher text x coordinate
     * @param right_cipher_y Right cipher text y coordinate
     */
    struct withdrawInfo {
        bool is_withdraw;
        uint256 left_cipher_x;
        uint256 left_cipher_y;
        uint256 right_cipher_x;
        uint256 right_cipher_y;
    }

    /**
     * @dev on-chain deposit Merkle tree
     * key is EdDSA address
     */
    mapping(address => withdrawInfo) withdrawTreeInfo;

    /**
     * @dev Emitted when `amount` is deposited by one account (`from`)
     *
     * Address format and cipher text are aligned with Zether.
     * https://crypto.stanford.edu/~buenz/papers/zether.pdf#page=9
     *
     * @param individual_number Individual Number accosiated to EdDSA address
     * @param from EdDSA depositor address
     * @param public_key_x EdDSA depositor address x coordinate
     * @param public_key_y EdDSA depositor address y coordinate
     * @param left_cipher_x Left cipher text x coordinate
     * @param left_cipher_y Left cipher text y coordinate
     * @param right_cipher_x Right cipher text x coordinate
     * @param right_cipher_y Right cipher text y coordinate
     *
     * contract add `deposit` transaction to treeInfo and update `merkleRoot`
     */
    event Deposit(
        uint64 individual_number,
        address from,
        uint256 public_key_x,
        uint256 public_key_y,
        uint256 left_cipher_x,
        uint256 left_cipher_y,
        uint256 right_cipher_x,
        uint256 right_cipher_y,
    );

    /**
     * @dev Deposit when `amount` of ETH to contract
     *
     * @param from EdDSA depositor address
     * @param public_key_x EdDSA depositor address x coordinate
     * @param public_key_y EdDSA depositor address y coordinate
     * @param amount deposit ETH amount
     * @param left_cipher_x Left cipher text x coordinate
     * @param left_cipher_y Left cipher text y coordinate
     * @param right_cipher_x Right cipher text x coordinate
     * @param right_cipher_y Right cipher text y coordinate
     * @param proof zero knowledge proof proves follows statement
     *
     * Proof Statement
     * 1. `from` is hash of `public_key_x` and `public_key_y`
     * 2. `left_cipher_x`, `left_cipher_y` and `right_cipher_x`, `right_cipher_y`
     *    are encrypted number of `amount`
     * 3. `left_cipher_x`, `left_cipher_y` and `right_cipher_x`, `right_cipher_y`
     *    are encrypted by `from` private key
     *
     * Constract Process
     * 1. verify proof, revert if invalid
     * 2. check `amount` and msg.value are the same, revert if invalid
     * 3. construct `leafInfo` and store it to `treeInfo` by refering current
     *    `depositIndex` and `individualNumberIndex`
     * 4. emit `Deposit` event
     * 5. increment `depositIndex` and `individualNumberIndex`
     *
     */
    function deposit(
        address: from,
        uint256 public_key_x,
        uint256 public_key_y,
        uint32 amount,
        uint256 left_cipher_x,
        uint256 left_cipher_y,
        uint256 right_cipher_x,
        uint256 right_cipher_y,
        bytes calldata proof
    );

    /**
     * @dev Withdraw ETH to `to` address
     *
     * @param to ECDSA receipt address
     * @param from EdDSA depositor address
     * @param amount withdraw ETH amount
     * @param left_cipher_x Left cipher text x coordinate
     * @param left_cipher_y Left cipher text y coordinate
     * @param right_cipher_x Right cipher text x coordinate
     * @param right_cipher_y Right cipher text y coordinate
     * @param proof zero knowledge proof proves follows statement
     *
     * Proof Statement
     * 1. knowledge of `from` address private key
     * 2. `left_cipher_x`, `left_cipher_y` and `right_cipher_x`, `right_cipher_y`
     *    are encrypted number of `amount`
     * 3. `left_cipher_x`, `left_cipher_y` and `right_cipher_x`, `right_cipher_y`
     *    are encrypted by `from` private key
     *
     * Contract does following steps
     * 1. verify proof, revert if invalid
     * 2. check if withdraw transaction is in `withdrawTreeInfo`
     * 3. turn `is_withdraw` to true
     * 4. transfer `amount` ETH to `to` address
     *
     */
    function withdraw(
        address: to,
        address: from,
        uint32 amount,
        uint256 left_cipher_x,
        uint256 left_cipher_y,
        uint256 right_cipher_x,
        uint256 right_cipher_y,
        bytes calldata proof
    );

    /**
     * @dev Update Merkle tree root
     *
     * Note that `transactions` is only for data availability.
     *
     * Contract does following steps
     * 1. verify `proof`
     * 2. update Merkle root to `new_root`
     */
    function batch(
        bytes: current_root,
        bytes: new_root,
        bytes calldata: transactions,
        bytes calldata proof
    )
}
