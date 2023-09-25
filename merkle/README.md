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
