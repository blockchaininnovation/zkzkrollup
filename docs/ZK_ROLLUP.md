# Zk Rollup

## Actor

- User
Transfer asset.
- Blockchain
Store state.
- Operator
Organize sidechain.

## Functionalities

### User

- genSideChainKey
generate sidechain key pair

### Blockchain

State
- deposits(pubkey_x, pubkey_y, balance, nonce)
- updates(pubkey_x, pubkey_y, balance, nonce)
Key is `queueNumber`.

- updateState
Verify proof and update merkle root  
public inputs has newRoot, txRoot and oldRoot  
**Q. How do we recover the sidechain state?**

- deposit
User State: (pub x, pub y, amount, nonce?)  
appends user state to pending deposits array storage

???
```ts
uint tmpDepositSubtreeHeight = 0;
uint tmp = queueNumber;
while(tmp % 2 == 0){
    uint[] memory array = new uint[](2);
    array[0] = pendingDeposits[pendingDeposits.length - 2];
    array[1] = pendingDeposits[pendingDeposits.length - 1];
    pendingDeposits[pendingDeposits.length - 2] = mimcMerkle.hashMiMC(
        array
    );
    removeDeposit(pendingDeposits.length - 1);
    tmp = tmp / 2;
    tmpDepositSubtreeHeight++;
}
if (tmpDepositSubtreeHeight > depositSubtreeHeight){
    depositSubtreeHeight = tmpDepositSubtreeHeight;
}
```

- processDeposit
coordinator adds deposits to balance tree with specifying subtree index.  

- withdraw
txInfo(pubkeyX, pubkeyY, index, toX ,toY, nonce, amount, token_type_from, txRoot)  
**Q. How do we withdraw when operator doesn't work?**

**state root will be invalid if users withdraw asset before operator synchronization**.
