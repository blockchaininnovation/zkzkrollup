// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

interface IRollup {
    /**
     * @dev on-chain users state root
     */
    bytes merkleRoot;

    /**
     * @dev on-chain users information
     */
    struct leafInfo {
        uint32 index;
        uint64 batch;
        address ethAddress;
    }

    /**
     * @dev on-chain users Merkle tree
     */
    mapping(uint256 => leafInfo) treeInfo;

    /**
     * @dev Emitted when `amount` is deposited by one account (`from`)
     *
     * Note that `from` is EdDSA-based address.
     * Address format is aligned with Zether.
     * https://crypto.stanford.edu/~buenz/papers/zether.pdf#page=9
     * Encrypted balance is expressed as following params
     * left_cipher_x, left_cipher_y, right_cipher_x, right_cipher_y
     * EdDSA-based address is expressed as following params
     * from, public_key_x, public_key_y
     */
    event Deposit(
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
     * Note that `from` is EdDSA-based address.
     * Users do following steps
     * 1. generate EdDSA-based address locally.
     * 2. encrypt `amount` by EdDSA-based private key
     * 3. generate `proof` for valid encryption
     *
     * Contract does following steps
     * 1. verify `proof`
     * 2. add deposit transaction to deposit queue
     * 3. increment deposit index
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
     * Note that `to` is ECDSA-based address
     * Note that `from` is EdDSA-based address.
     * Users do following steps
     * 1. check the raw `amount` by decrypting encrypted balance.
     * 2. generate `proof` for valid decryption
     *
     * Contract does following steps
     * 1. verify `proof`
     * 2. check whether the transaction is in withdraw queue
     * 3. delete transaction from withdraw queue
     * 4. transfer `amount` ETH to `to`
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
