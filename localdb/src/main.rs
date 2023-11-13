use log::error;
use rusqlite::Map;
use rusqlite::{params, Connection, Result};

use std::collections::BTreeMap;

use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::halo2curves::pasta::Fp;
use smt::poseidon::{FieldHasher, Poseidon};
use smt::smt::SparseMerkleTree;

use chrono::Local;
use env_logger;
use log::info;
use std::env;
use std::io::Write;

#[derive(Debug)]
struct Account {
    _id: u32,
    public_key_for_eddsa: String, //x,y座標を直列に並べたものをHEXで．
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
    Ok(con)
}

fn insert_account(con: &Connection, a: &Account) -> Result<usize, rusqlite::Error> {
    return Ok(con.execute(
        "insert into account (_id, public_key_for_eddsa) values (?1, ?2)",
        params![a._id, a.public_key_for_eddsa],
    )?);
}

fn delete_all_account(con: &Connection) -> Result<usize, rusqlite::Error> {
    return Ok(con.execute("delete from account", ())?);
}
fn insert_state(con: &Connection, s: &State) -> Result<usize, rusqlite::Error> {
    return Ok(con.execute(
        "insert into state (account_id, balance_encrypted) values (?1, ?2)",
        params![s.account_id, s.balance_encrypted],
    )?);
}

fn delete_all_state(con: &Connection) -> Result<usize, rusqlite::Error> {
    return Ok(con.execute("delete from state", ())?);
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
    return accounts.map(|a| a.unwrap()).collect();
}

fn select_state_with_pubkey(con: &Connection) -> Vec<StateWithPubKey> {
    let mut stmt = con.prepare("select s.account_id, s.balance_encrypted, a.public_key_for_eddsa from state s, account a where s.account_id = a._id").unwrap();
    let results = stmt
        .query_map(params![], |row| {
            Ok(StateWithPubKey {
                account_id: row.get(0).unwrap(),
                balance_encrypted: row.get(1).unwrap(),
                public_key_for_eddsa: row.get(2).unwrap(),
            })
        })
        .unwrap();

    return results.map(|s| s.unwrap()).collect();
}

fn convert_hex_to_u8_array(hex_string: &str) -> Result<[u8; 31 * 6], hex::FromHexError> {
    let stripped = if hex_string.starts_with("0x") {
        &hex_string[2..]
    } else {
        hex_string
    };
    let vec = hex::decode(stripped)?;
    let mut arr = [0u8; 31 * 6];
    for (place, element) in arr.iter_mut().zip(vec.iter()) {
        *place = *element;
    }
    Ok(arr)
}

const HEIGHT: usize = 8;

fn create_merkle_tree(con: &Connection) -> SparseMerkleTree<Fp, Poseidon::<Fp, 2>, HEIGHT> {
    let default_leaf = [0u8; 64];

    let poseidon: Poseidon<Fp, 2> = Poseidon::<Fp, 2>::new();
    let leaves: BTreeMap<u32, Fp> = BTreeMap::new();

    let mut smt: SparseMerkleTree<Fp, Poseidon<Fp, 2>, HEIGHT> =
        SparseMerkleTree::new(&leaves, &poseidon.clone(), &default_leaf).unwrap();

    let states_with_pubkey = select_state_with_pubkey(con);
    for s in states_with_pubkey {
        let index = s.account_id;
        let value_hex = s.public_key_for_eddsa + &s.balance_encrypted;
        // バイト列に変更
        // バイト列の31バイトずつに結合した列を作る
        // それぞれの31バイトをハッシュにする．
        // TODO その前に，DBに入れる値はHexそのものを入れるようにする．
        // 元の値（public_key_for_eddsa，balance_encrypted）の値の範囲をまず調べる必要がある．
        // pubkey: x, yそれぞれが31byte．
        // balance: 31*4 byte
        let value = convert_hex_to_u8_array(&value_hex).unwrap();
        // hashのinputには2バイトしか入れられないようなので，上記31*6バイトを2バイトに圧縮．というか2バイトずつに分けて3バイト分足し合わせる．
        //TODO 宣言している配列の長さとvalue[...]で部分列をとっているところの長さがあってない気がするがこれでいいか要確認．
        let v1: [u8; 64] = value[0..(31 * 6 / 2 - 1)].try_into().unwrap();
        let v2: [u8; 64] = value[(31 * 6 / 2)..(31 * 6 - 1)].try_into().unwrap();

        let inputs = [Fp::from_bytes_wide(&v1), Fp::from_bytes_wide(&v2)];

        let hash = poseidon.hash(inputs);

        smt.tree.insert(From::from(index), hash.unwrap());
    }

    return smt;
}

fn log_config() {
    env::set_var("RUST_LOG", "info");
    env_logger::Builder::from_default_env()
        .format(|buf, record| {
            writeln!(
                buf,
                "{}:{: >03} {} [{}] - {}",
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                Local::now().format("%Y-%m-%dT%H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .init();
}

fn main() {
    log_config();

    info!("into main()");
    let con = open_my_db().unwrap();

    // アカウントデータをいくつか入れる．
    insert_account_sample_data(&con);

    // ステートデータをいくつか入れる．
    insert_state_sample_data(&con);

    // マークルツリーを出力

    // ステートを変更する

    // マークルツリーを出力
}

fn insert_state_sample_data(con: &Connection) {
    let dtstr = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    // TODO 暗号化データなどをHEX形式で保存．
    let s1 = State {
        account_id: 1,
        balance_encrypted: String::from(""),
        created_at: dtstr.clone(),
        updated_at: dtstr.clone(),
    };
    let s2 = State {
        account_id: 2,
        balance_encrypted: String::from(""),
        created_at: dtstr.clone(),
        updated_at: dtstr.clone(),
    };

    match delete_all_state(&con) {
        Ok(s) => info!("ok: {}", s),
        Err(err) => error!("error: {}", err),
    };
    match insert_state(&con, &s1) {
        Ok(s) => info!("ok: {}", s),
        Err(err) => error!("error: {}", err),
    };
    match insert_state(&con, &s2) {
        Ok(s) => info!("ok: {}", s),
        Err(err) => error!("error: {}", err),
    };
    let states = select_state_with_pubkey(&con);
    for s in states {
        info!(
            "state={} {} {}",
            s.account_id, s.balance_encrypted, s.public_key_for_eddsa
        );
    }
}
fn insert_account_sample_data(con: &Connection) {
    let dtstr = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let a = Account {
        _id: 1,
        public_key_for_eddsa: String::from("aaa"),
        created_at: dtstr.clone(),
        updated_at: dtstr.clone(),
    };
    let b = Account {
        _id: 2,
        public_key_for_eddsa: String::from("bbb"),
        created_at: dtstr.clone(),
        updated_at: dtstr.clone(),
    };

    match delete_all_account(&con) {
        Ok(s) => info!("ok: {}", s),
        Err(err) => error!("error: {}", err),
    };
    match insert_account(&con, &a) {
        Ok(s) => info!("ok: {}", s),
        Err(err) => error!("error: {}", err),
    };
    match insert_account(&con, &b) {
        Ok(s) => info!("ok: {}", s),
        Err(err) => error!("error: {}", err),
    };
    let accounts = select_accounts_all(&con);
    for a in accounts {
        info!("account={}", a._id);
    }
}
