#!/bin/bash
# db/init.sh：建角色、資料表與權限。
# PostgreSQL container 第一次啟動（volume 是空的）時自動執行；之後要重建就刪掉 volume 再起一次。
# 需要的環境變數：POSTGRES_USER、POSTGRES_DB、ETL_DB_PASSWORD、AGENT_DB_PASSWORD
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v etl_pw="$ETL_DB_PASSWORD" -v agent_pw="$AGENT_DB_PASSWORD" <<'SQL'
-- 兩個角色：ETL 寫入用、agent 查詢用。agent 的 SQL 是模型產生的，權限只給 SELECT，
-- 連線預設唯讀交易、單一語句 5 秒逾時，就算 run_sql 的字串檢查被繞過，資料庫這層也擋得住
CREATE ROLE vuln_etl LOGIN PASSWORD :'etl_pw';
CREATE ROLE vuln_agent LOGIN PASSWORD :'agent_pw';
ALTER ROLE vuln_agent SET default_transaction_read_only = on;
ALTER ROLE vuln_agent SET statement_timeout = '5s';
GRANT CREATE ON SCHEMA public TO vuln_etl;

-- 資料表由 vuln_etl 建立，ETL 就是擁有者
SET ROLE vuln_etl;

CREATE TABLE cve (
    cve_id        text PRIMARY KEY,
    published     timestamptz NOT NULL,
    last_modified timestamptz NOT NULL,
    description   text,
    cvss_score    double precision,
    severity      text,
    cwe           text            -- 逗號分隔，例如 CWE-79,CWE-89
);
CREATE INDEX ON cve (published);
CREATE INDEX ON cve (cvss_score);

-- 一個 CVE 影響多個產品，拆成一對多；vendor、product 取自 CPE 字串的第 4、5 段
CREATE TABLE cve_product (
    cve_id  text REFERENCES cve ON DELETE CASCADE,
    cpe     text,
    vendor  text NOT NULL,
    product text NOT NULL,
    PRIMARY KEY (cve_id, cpe)
);
CREATE INDEX ON cve_product (product);
CREATE INDEX ON cve_product (vendor);

-- KEV 收錄的 CVE 可能很舊，不一定在 cve 表的時間範圍，所以不設外鍵
CREATE TABLE kev (
    cve_id     text PRIMARY KEY,
    vendor     text,
    product    text,
    date_added date,
    due_date   date
);

CREATE TABLE epss (
    cve_id     text PRIMARY KEY,
    epss       double precision NOT NULL,
    percentile double precision NOT NULL,
    score_date date NOT NULL
);
CREATE INDEX ON epss (epss);

-- 每次 ETL 一列；watermark 是這次資料的時間點，NVD 下次增量從上次成功的 watermark 開始抓
CREATE TABLE etl_runs (
    id          bigserial PRIMARY KEY,
    source      text NOT NULL,
    status      text NOT NULL CHECK (status IN ('running', 'success', 'failed')),
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    rows        integer,
    watermark   timestamptz,
    error       text
);

-- agent 只看得到四張資料表，etl_runs 不開放
GRANT SELECT ON cve, cve_product, kev, epss TO vuln_agent;
RESET ROLE;
SQL
