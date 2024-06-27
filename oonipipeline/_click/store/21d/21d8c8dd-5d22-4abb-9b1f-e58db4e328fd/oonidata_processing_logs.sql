ATTACH TABLE _ UUID '75dfa717-4b8e-4f8c-9974-6bf3755948bd'
(
    `key` String,
    `timestamp` DateTime('UTC'),
    `runtime_ms` Nullable(UInt64),
    `bytes` Nullable(UInt64),
    `msmt_count` Nullable(UInt32),
    `comment` Nullable(String)
)
ENGINE = MergeTree
ORDER BY (timestamp, key)
SETTINGS index_granularity = 8192
