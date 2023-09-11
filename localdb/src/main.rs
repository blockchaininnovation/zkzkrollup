use rusqlite::{params, Connection, Result};

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

fn select_address_all(con: &Connection) {
    let mut stmt = con.prepare("select * from account").unwrap();
    let addresses = stmt
        .query_map(params![], |row| {
            Ok(Account {
                _id: row.get(0).unwrap(),
                public_key_for_eddsa: row.get(1).unwrap(),
                created_at: row.get(2).unwrap(),
                updated_at: row.get(3).unwrap(),
            })
        })
        .unwrap();

    for a in addresses {
        println!("{:?}", a.unwrap());
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
    select_address_all(&con)
}
