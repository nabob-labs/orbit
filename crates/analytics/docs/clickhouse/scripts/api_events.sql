CREATE TABLE api_events_queue (
    `merchant_id` String,
    `payment_id` Nullable(String),
    `refund_id` Nullable(String),
    `payment_method_id` Nullable(String),
    `payment_method` Nullable(String),
    `payment_method_type` Nullable(String),
    `customer_id` Nullable(String),
    `user_id` Nullable(String),
    `connector` Nullable(String),
    `request_id` String,
    `flow_type` LowCardinality(String),
    `api_flow` LowCardinality(String),
    `api_auth_type` LowCardinality(String),
    `request` String,
    `response` Nullable(String),
    `error` Nullable(String),
    `authentication_data` Nullable(String),
    `status_code` UInt32,
    `created_at_timestamp` DateTime64(3),
    `latency` UInt128,
    `user_agent` String,
    `ip_addr` String,
    `hs_latency` Nullable(UInt128),
    `http_method` LowCardinality(String),
    `url_path` Nullable(String),
    `dispute_id` Nullable(String)
) ENGINE = Kafka SETTINGS kafka_broker_list = 'kafka0:29092',
kafka_topic_list = 'orbit-api-log-events',
kafka_group_name = 'hyper',
kafka_format = 'JSONEachRow',
kafka_handle_error_mode = 'stream';

CREATE TABLE api_events (
    `merchant_id` LowCardinality(String),
    `payment_id` Nullable(String),
    `refund_id` Nullable(String),
    `payment_method_id` Nullable(String),
    `payment_method` Nullable(String),
    `payment_method_type` Nullable(String),
    `customer_id` Nullable(String),
    `user_id` Nullable(String),
    `connector` Nullable(String),
    `request_id` String,
    `flow_type` LowCardinality(String),
    `api_flow` LowCardinality(String),
    `api_auth_type` LowCardinality(String),
    `request` String,
    `response` Nullable(String),
    `error` Nullable(String),
    `authentication_data` Nullable(String),
    `status_code` UInt32,
    `created_at` DateTime64(3),
    `inserted_at` DateTime DEFAULT now() CODEC(T64, LZ4),
    `latency` UInt128,
    `user_agent` String,
    `ip_addr` String,
    `hs_latency` Nullable(UInt128),
    `http_method` LowCardinality(String),
    `url_path` Nullable(String),
    `dispute_id` Nullable(String),
    `masked_response` Nullable(String),
    INDEX flowIndex flow_type TYPE bloom_filter GRANULARITY 1,
    INDEX apiIndex api_flow TYPE bloom_filter GRANULARITY 1,
    INDEX statusIndex status_code TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree PARTITION BY toStartOfDay(created_at)
ORDER BY
    (
        created_at,
        merchant_id,
        flow_type,
        status_code,
        api_flow
    ) TTL inserted_at + toIntervalMonth(18) SETTINGS index_granularity = 8192;

CREATE TABLE api_events_audit (
    `merchant_id` LowCardinality(String),
    `payment_id` String,
    `refund_id` Nullable(String),
    `payment_method_id` Nullable(String),
    `payment_method` Nullable(String),
    `payment_method_type` Nullable(String),
    `customer_id` Nullable(String),
    `user_id` Nullable(String),
    `connector` Nullable(String),
    `request_id` String,
    `flow_type` LowCardinality(String),
    `api_flow` LowCardinality(String),
    `api_auth_type` LowCardinality(String),
    `request` String,
    `response` Nullable(String),
    `error` Nullable(String),
    `authentication_data` Nullable(String),
    `status_code` UInt32,
    `created_at` DateTime64(3),
    `inserted_at` DateTime DEFAULT now() CODEC(T64, LZ4),
    `latency` UInt128,
    `user_agent` String,
    `ip_addr` String,
    `hs_latency` Nullable(UInt128),
    `http_method` LowCardinality(Nullable(String)),
    `url_path` Nullable(String),
    `dispute_id` Nullable(String),
    `masked_response` Nullable(String)
) ENGINE = MergeTree PARTITION BY merchant_id
ORDER BY
    (merchant_id, payment_id) TTL inserted_at + toIntervalMonth(18) SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW api_events_parse_errors (
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
    api_events_queue
WHERE
    length(_error) > 0;

CREATE MATERIALIZED VIEW api_events_audit_mv TO api_events_audit (
    `merchant_id` String,
    `payment_id` String,
    `refund_id` Nullable(String),
    `payment_method_id` Nullable(String),
    `payment_method` Nullable(String),
    `payment_method_type` Nullable(String),
    `customer_id` Nullable(String),
    `user_id` Nullable(String),
    `connector` Nullable(String),
    `request_id` String,
    `flow_type` LowCardinality(String),
    `api_flow` LowCardinality(String),
    `api_auth_type` LowCardinality(String),
    `request` String,
    `response` Nullable(String),
    `error` Nullable(String),
    `authentication_data` Nullable(String),
    `status_code` UInt32,
    `created_at` DateTime64(3),
    `inserted_at` DateTime DEFAULT now() CODEC(T64, LZ4),
    `latency` UInt128,
    `user_agent` String,
    `ip_addr` String,
    `hs_latency` Nullable(UInt128),
    `http_method` LowCardinality(Nullable(String)),
    `url_path` Nullable(String),
    `dispute_id` Nullable(String),
    `masked_response` Nullable(String)
) AS
SELECT
    merchant_id,
    payment_id,
    refund_id,
    payment_method_id,
    payment_method,
    payment_method_type,
    customer_id,
    user_id,
    connector,
    request_id,
    flow_type,
    api_flow,
    api_auth_type,
    request,
    response,
    error,
    authentication_data,
    status_code,
    created_at_timestamp AS created_at,
    now() AS inserted_at,
    latency,
    user_agent,
    ip_addr,
    hs_latency,
    http_method,
    url_path,
    dispute_id,
    response AS masked_response
FROM
    api_events_queue
WHERE
    (length(_error) = 0)
    AND (payment_id IS NOT NULL);

CREATE MATERIALIZED VIEW api_events_mv TO api_events (
    `merchant_id` String,
    `payment_id` Nullable(String),
    `refund_id` Nullable(String),
    `payment_method_id` Nullable(String),
    `payment_method` Nullable(String),
    `payment_method_type` Nullable(String),
    `customer_id` Nullable(String),
    `user_id` Nullable(String),
    `connector` Nullable(String),
    `request_id` String,
    `flow_type` LowCardinality(String),
    `api_flow` LowCardinality(String),
    `api_auth_type` LowCardinality(String),
    `request` String,
    `response` Nullable(String),
    `error` Nullable(String),
    `authentication_data` Nullable(String),
    `status_code` UInt32,
    `created_at` DateTime64(3),
    `inserted_at` DateTime DEFAULT now() CODEC(T64, LZ4),
    `latency` UInt128,
    `user_agent` String,
    `ip_addr` String,
    `hs_latency` Nullable(UInt128),
    `http_method` LowCardinality(Nullable(String)),
    `url_path` Nullable(String),
    `dispute_id` Nullable(String),
    `masked_response` Nullable(String)
) AS
SELECT
    merchant_id,
    payment_id,
    refund_id,
    payment_method_id,
    payment_method,
    payment_method_type,
    customer_id,
    user_id,
    connector,
    request_id,
    flow_type,
    api_flow,
    api_auth_type,
    request,
    response,
    error,
    authentication_data,
    status_code,
    created_at_timestamp AS created_at,
    now() AS inserted_at,
    latency,
    user_agent,
    ip_addr,
    hs_latency,
    http_method,
    url_path,
    dispute_id,
    response AS masked_response
FROM
    api_events_queue
WHERE
    length(_error) = 0;