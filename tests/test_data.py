# tests/test_data.py：ETL 跑完後的資料斷言；要先 docker compose up 並跑過 ETL
import pytest

from vuln_agent.tools import query

TABLES = ("cve", "cve_product", "kev", "epss")

def one(sql: str):
    return next(iter(query(sql)[0].values()))

@pytest.mark.parametrize("table", TABLES)
def test_tables_not_empty(table):
    assert one(f"SELECT count(*) FROM {table}") > 0

@pytest.mark.parametrize("table", TABLES)
def test_cve_id_format(table):
    assert one(f"SELECT count(*) FROM {table} WHERE cve_id !~ '^CVE-\\d{{4}}-\\d{{4,}}$'") == 0

def test_kev_cves_have_nvd_data():
    # ETL 每次都用 hasKev 整批抓 KEV 的 CVE；CISA 當天剛加、NVD 還沒同步的少數幾筆可以容許
    assert one("SELECT count(*) FROM kev LEFT JOIN cve USING (cve_id) WHERE cve.cve_id IS NULL") <= 5

def test_score_ranges():
    assert one("SELECT count(*) FROM cve WHERE cvss_score NOT BETWEEN 0 AND 10") == 0
    assert one("SELECT count(*) FROM epss WHERE epss NOT BETWEEN 0 AND 1") == 0
