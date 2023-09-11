drop table if exists account;
create table account(
    _id integer not null primary key,
    public_key_for_eddsa text not null,
    created_at TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime')),
    updated_at TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime'))
);
create unique index idx_account_01 on account(public_key_for_eddsa);

drop table if exists state;
create table state(
    account_id integer not null primary key,
    balance_encrypted text not null,
    created_at TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime')),
    updated_at TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime'))
);

