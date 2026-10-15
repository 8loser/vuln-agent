# src/vuln_agent/db.py
import os
import psycopg
from dotenv import load_dotenv

load_dotenv()

def connect(role: str) -> psycopg.Connection:
    """連到 docker compose 起的 PostgreSQL。role 是 etl（可寫）或 agent（唯讀），
    對應 db/init.sh 建的 vuln_etl、vuln_agent，密碼從 .env 的 ETL_DB_PASSWORD、AGENT_DB_PASSWORD 讀。"""
    return psycopg.connect(host="localhost", port=5432, dbname="vuln", user=f"vuln_{role}",
                           password=os.environ[f"{role.upper()}_DB_PASSWORD"], connect_timeout=5)
