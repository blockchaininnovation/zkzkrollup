# ZkZk Rollup Merkle Tree

## Markle Proof

1. A Merkle tree including all the transactions in the batch
2. Merkle proofs for transactions to prove inclusion in the batch
3. Merkle proofs for each sender-receiver pair in transactions to prove those accounts are part of the rollup's state tree
4. A set of intermediate state roots, derived from updating the state root after applying state updates for each transaction (i.e., decreasing sender accounts and increasing receiver accounts)

### Transaction Merkle Tree

Check whether all the transactions are in the batch.

### Membership Proof

Check whether the transactions sender-receiver pair are in the Markle tree.

### Update Proof

Check whether all the intermediate state roots are valid.

### Operator Precomputation

- Off-Circuit

1. Receive users transaction
2. Verify signature
3. Check whether the account is in Merkle tree
4. Process transaction and generate intermediate Proof
5. Compute transaction Merkle tree root

- On-Circuit

1. Pass transactions, intermediate Proof
2. Prove signature verification
3. Prove the sender-receiver pair is in Merkle tree
4. Prove the Merkle tree update by intermediate proof
5. Prove the transaction in transaction Merkle root
