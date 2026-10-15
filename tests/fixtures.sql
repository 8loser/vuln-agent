-- tests/fixtures.sql：CI 用的測試資料，編號與分數都是假的，只為了讓 tests/ 在沒有真實資料時也能跑
-- 本機測試直接用 ETL 抓的真實資料，不需要載入這個檔案
INSERT INTO cve VALUES
    ('CVE-2000-0001', now() - interval '3 days',  now(), 'test: kev, high epss', 9.8, 'CRITICAL', 'CWE-89'),
    ('CVE-2000-0002', now() - interval '5 days',  now(), 'test: kev',            8.1, 'HIGH',     'CWE-79'),
    ('CVE-2000-0003', now() - interval '10 days', now(), 'test: kev',            7.5, 'HIGH',     NULL),
    ('CVE-2000-0004', now() - interval '20 days', now(), 'test: kev',            6.5, 'MEDIUM',   'CWE-79,CWE-89'),
    ('CVE-2000-0005', now() - interval '1 day',   now(), 'test: not in kev',     9.1, 'CRITICAL', 'CWE-22'),
    ('CVE-2000-0006', now() - interval '40 days', now(), 'test: not in kev',     5.3, 'MEDIUM',   NULL);
INSERT INTO cve_product VALUES
    ('CVE-2000-0001', 'cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*', 'f5', 'nginx'),
    ('CVE-2000-0005', 'cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*', 'openssl', 'openssl');
INSERT INTO kev VALUES
    ('CVE-2000-0001', 'F5', 'NGINX', current_date - 2, current_date + 19),
    ('CVE-2000-0002', 'Microsoft', 'Windows', current_date - 4, current_date + 17),
    ('CVE-2000-0003', 'Microsoft', 'Exchange', current_date - 9, current_date + 12),
    ('CVE-2000-0004', 'Apache', 'HTTP Server', current_date - 19, current_date + 2);
INSERT INTO epss VALUES
    ('CVE-2000-0001', 0.94, 0.99, current_date),
    ('CVE-2000-0002', 0.40, 0.95, current_date),
    ('CVE-2000-0005', 0.02, 0.60, current_date),
    ('CVE-2000-0007', 0.01, 0.30, current_date);
