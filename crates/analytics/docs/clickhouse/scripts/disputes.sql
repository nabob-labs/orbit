CREATE TABLE dispute_queue (
    `dispute_id` String,
    `dispute_amount` UInt32,
    `currency` String,
    `dispute_stage` LowCardinality(String),
    `dispute_status` LowCardinality(String),
    `payment_id` String,
    `attempt_id` String,
    `merchant_id` String,
    `connector_status` String,
    `connector_dispute_id` String,
    `connector_reason` Nullable(String),
    `connector_reason_code` Nullable(String),
    `challenge_required_by` Nullable(DateTime) CODEC(T64, LZ4),
    `connector_created_at` Nullable(DateTime) CODEC(T64, LZ4),
    `connector_updated_at` Nullable(DateTime) CODEC(T64, LZ4),
    `created_at` DateTime CODEC(T64, LZ4),
    `modified_at` DateTime CODEC(T64, LZ4),
    `connector` LowCardinality(String),
    `evidence` Nullable(String),
    `profile_id` Nullable(String),
    `merchant_connector_id` Nullable(String),
    `organization_id` String,
    `sign_flag` Int8
) ENGINE = Kafka SETTINGS kafka_broker_list = 'kafka0:29092',
kafka_topic_list = 'orbit-dispute-events',
kafka_group_name = 'hyper',
kafka_format = 'JSONEachRow',
kafka_handle_error_mode = 'stream';

CREATE TABLE dispute (
    `dispute_id` String,
    `dispute_amount` UInt32,
    `currency` String,
    `dispute_stage` LowCardinality(String),
    `dispute_status` LowCardinality(String),
    `payment_id` String,
    `attempt_id` String,
    `merchant_id` LowCardinality(String),
    `connector_status` String,
    `connector_dispute_id` String,
    `connector_reason` Nullable(String),
    `connector_reason_code` Nullable(String),
    `challenge_required_by` Nullable(DateTime) CODEC(T64, LZ4),
    `connector_created_at` Nullable(DateTime) CODEC(T64, LZ4),
    `connector_updated_at` Nullable(DateTime) CODEC(T64, LZ4),
    `created_at` DateTime DEFAULT now() CODEC(T64, LZ4),
    `modified_at` DateTime DEFAULT now() CODEC(T64, LZ4),
    `connector` LowCardinality(String),
    `evidence` String DEFAULT '{}',
    `profile_id` Nullable(String),
    `merchant_connector_id` Nullable(String),
    `inserted_at` DateTime DEFAULT now() CODEC(T64, LZ4),
    `organization_id` String,
    `sign_flag` Int8,
    INDEX connectorIndex connector TYPE bloom_filter GRANULARITY 1,
    INDEX disputeStatusIndex dispute_status TYPE bloom_filter GRANULARITY 1,
    INDEX disputeStageIndex dispute_stage TYPE bloom_filter GRANULARITY 1
) ENGINE = CollapsingMergeTree(sign_flag) PARTITION BY toStartOfDay(created_at)
ORDER BY
    (created_at, merchant_id, dispute_id) TTL inserted_at + toIntervalMonth(18) SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW dispute_mv TO dispute (
    `dispute_id` String,
    `dispute_amount` UInt32,
    `currency` String,
    `dispute_stage` LowCardinality(String),
    `dispute_status` LowCardinality(String),
    `payment_id` String,
    `attempt_id` String,
    `merchant_id` String,
    `connector_status` String,
    `connector_dispute_id` String,
    `connector_reason` Nullable(String),
    `connector_reason_code` Nullable(String),
    `challenge_required_by` Nullable(DateTime64(3)),
    `connector_created_at` Nullable(DateTime64(3)),
    `connector_updated_at` Nullable(DateTime64(3)),
    `created_at` DateTime64(3),
    `modified_at` DateTime64(3),
    `connector` LowCardinality(String),
    `evidence` Nullable(String),
    `profile_id` Nullable(String),
    `merchant_connector_id` Nullable(String),
    `organization_id` String,
    `inserted_at` DateTime64(3),
    `sign_flag` Int8
) AS
SELECT
    dispute_id,
    dispute_amount,
    currency,
    dispute_stage,
    dispute_status,
    payment_id,
    attempt_id,
    merchant_id,
    connector_status,
    connector_dispute_id,
    connector_reason,
    connector_reason_code,
    challenge_required_by,
    connector_created_at,
    connector_updated_at,
    created_at,
    modified_at,
    connector,
    evidence,
    profile_id,
    merchant_connector_id,
    organization_id,
    now() AS inserted_at,
    sign_flag
FROM
    dispute_queue
WHERE
    length(_error) = 0;

CREATE MATERIALIZED VIEW dispute_parse_errors (
    `topic` String,
    `partition` Int64,
    `offset` Int64,
    `raw` String,
    `error` String
) ENGINE = MergeTree
ORDER BY
    (topic, partition, offset) SETTINGS index_granularity = 8192 AS
SELECT
    _topic AS topic,
    _partition AS partition,
    _offset AS offset,
    _raw_message AS raw,
    _error AS error
FROM
    dispute_queue
WHERE
    length(_error) > 0;