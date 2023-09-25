use rusqlite::{params, Connection, Result};

use std::collections::BTreeMap;

use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::halo2curves::pasta::Fp;
use rand::rngs::OsRng;
use smt::poseidon::{FieldHasher, Poseidon};
use smt::smt::{gen_empty_hashes, SparseMerkleTree};

#[derive(Debug)]
struct Account {
    _id: u32,
    public_key_for_eddsa: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug)]
struct State {
    account_id: u32,
    balance_encrypted: String,
    created_at: String,
    updated_at: String,
}
struct StateWithPubKey {
    account_id: u32,
    balance_encrypted: String,
    public_key_for_eddsa: String,
}

fn open_my_db() -> Result<Connection, rusqlite::Error> {
    let path = "./zkzkrollup.db";
    let con = Connection::open(&path)?;
    println!("{}", con.is_autocommit());
    Ok(con)
}

fn insert_address(con: &Connection, a: &Account) -> Result<usize, rusqlite::Error> {
    return Ok(con.execute(
        "insert into account (_id, public_key_for_eddsa) values (?1, ?2)",
        params![a._id, a.public_key_for_eddsa],
    )?);
}

fn select_accounts_all(con: &Connection) -> Vec<Account> {
    let mut stmt = con.prepare("select * from account").unwrap();
    let accounts = stmt
        .query_map(params![], |row| {
            Ok(Account {
                _id: row.get(0).unwrap(),
                public_key_for_eddsa: row.get(1).unwrap(),
                created_at: row.get(2).unwrap(),
                updated_at: row.get(3).unwrap(),
            })
        })
        .unwrap();

    let mut ret = Vec::new();
    for a in accounts {
        println!("{:?}", a.unwrap());
        ret.push(a.unwrap());
    }

    return ret;
}

fn select_state_with_pubkey(con: &Connection) -> Vec<StateWithPubKey> {
    let mut stmt = con.prepare("select s.account_id, s.balance_encrypted, a.publick_key_for_eddsa from state s, account a where s.account_id = a._id").unwrap();
    let results = stmt
        .query_map(params![], |row| {
            Ok(StateWithPubKey {
                account_id: row.get(0).unwrap(),
                balance_encrypted: row.get(1).unwrap(),
                public_key_for_eddsa: row.get(2).unwrap(),
            })
        })
        .unwrap();

    let mut ret = Vec::new();
    for a in results {
        ret.push(a.unwrap());
    }

    return ret;
}

fn convert_hex_to_u8_array(hex_string: &str) -> Result<[u8; 64], hex::FromHexError> {
    let stripped = if hex_string.starts_with("0x") {
        &hex_string[2..]
    } else {
        hex_string
    };
    let vec = hex::decode(stripped)?;
    let mut arr = [0u8; 64];
    for (place, element) in arr.iter_mut().zip(vec.iter()) {
        *place = *element;
    }
    Ok(arr)
}

fn create_merkle_tree(con: &Connection) {
    let poseidon = Poseidon::<Fp, 2>::new();
    let default_leaf = [0u8; 64];

    let leaves: BTreeMap<u32, Fp> = BTreeMap::new();

    const HEIGHT: usize = 8;
    let mut smt: SparseMerkleTree<Fp, Poseidon<Fp, 2>, HEIGHT> =
        SparseMerkleTree::new(&leaves, &poseidon.clone(), &default_leaf).unwrap();

    let states_with_pubkey = select_state_with_pubkey(con);
    for s in states_with_pubkey {
        let index = s.account_id;
        let value = s.public_key_for_eddsa + &s.balance_encrypted;
        // バイト列に変更
        // バイト列の31バイトずつに結合した列を作る
        // それぞれの31バイトをハッシュにする．
        // TODO その前に，DBに入れる値はHexそのものを入れるようにする．
        // 元の値（public_key_for_eddsa，balance_encrypted）の値の範囲をまず調べる必要がある．
        // pubkey: x, yそれぞれが31byte．
        // balance: 31*4 byte

        let hash = poseidon.hash(value);

        smt.tree.insert(index, hash);
    }
}

fn main() {
    let con = open_my_db().unwrap();
    let a = Account {
        _id: 1,
        public_key_for_eddsa: String::from("aaa"),
        created_at: String::from(""),
        updated_at: String::from(""),
    };
    let b = Account {
        _id: 2,
        public_key_for_eddsa: String::from("bbb"),
        created_at: String::from(""),
        updated_at: String::from(""),
    };

    insert_address(&con, &a);
    insert_address(&con, &b);
    select_accounts_all(&con)
}
