"""One-command, idempotent setup of the DVWA target on native Windows (no Docker/WSL).

    python range/dvwa/setup_dvwa.py

Installs under ~/tools (override with AEGIS_TOOLS):
  php/        PHP 8.3 NTS x64 (official windows.php.net build), php.ini with mysqli/pdo_mysql/gd/mbstring/curl
  mariadb/    MariaDB 10.11 portable zip (official archive.mariadb.org), data in mariadb_data/ on 127.0.0.1:3307
  dvwa/       DVWA 2.5 (github.com/digininja/DVWA, tag 2.5), config for that database, security level "low"

PHP and MariaDB downloads are verified against pinned SHA-256 values; the DVWA zip is fetched from the
tagged GitHub release (no published checksum). Every download goes into its own directory under
_downloads/ and is extracted with a path-traversal check. Everything binds to 127.0.0.1 only; DVWA is
deliberately vulnerable and must never be exposed. The range (eval/rangectl.py, app="dvwa") starts and
stops the PHP server per run and resets DVWA's login lockouts and guestbook.

These GPL/BSD/PHP-licensed programs are run as separate processes and never linked into AEGIS.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import zipfile
from http.cookiejar import CookieJar
from pathlib import Path

TOOLS = Path(os.environ.get("AEGIS_TOOLS", str(Path.home() / "tools")))
DL = TOOLS / "_downloads"
PHP_ZIP = "php-8.3.36-1-nts-Win32-vs16-x64.zip"
PHP_URL = f"https://downloads.php.net/~windows/releases/{PHP_ZIP}"
PHP_SHA = "1a097d52b7a68622cdc723073b61cc70caf79c941218ff65b2d8441dbc6b10d4"
MDB_ZIP = "mariadb-10.11.19-winx64.zip"
MDB_URL = f"https://archive.mariadb.org/mariadb-10.11.19/winx64-packages/{MDB_ZIP}"
MDB_SHA = "398ea30e5036010bbebe01d2b1804280424dcc2626e36d8e95155c04d25a0490"
DVWA_URL = "https://api.github.com/repos/digininja/DVWA/zipball/2.5"
DB_PORT = "3307"


def fetch(url: str, dest: Path, sha: str | None) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        print("downloading", url)
        req = urllib.request.Request(url, headers={"User-Agent": "aegis-setup"})
        with urllib.request.urlopen(req, timeout=600) as r, dest.open("wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
    if sha:
        got = hashlib.sha256(dest.read_bytes()).hexdigest()
        if got != sha:
            dest.unlink()
            raise SystemExit(f"checksum mismatch for {dest.name}: {got} != {sha}")
        print("sha256 ok:", dest.name)
    return dest


def extract(z: Path, dest: Path) -> None:
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(z) as f:
        for m in f.namelist():
            if not str((dest / m).resolve()).startswith(str(dest)):
                raise SystemExit("unsafe path in archive: " + m)
        f.extractall(dest)


def main() -> int:
    # --- PHP ----------------------------------------------------------------------------------------
    php = TOOLS / "php"
    if not (php / "php.exe").exists():
        extract(fetch(PHP_URL, DL / "php" / PHP_ZIP, PHP_SHA), php)
    ini = php / "php.ini"
    if not ini.exists():
        s = (php / "php.ini-development").read_text(encoding="utf-8")
        s = s.replace(';extension_dir = "ext"', 'extension_dir = "ext"')
        for e in ("mysqli", "pdo_mysql", "gd", "mbstring", "curl", "fileinfo", "openssl"):
            s = s.replace(f";extension={e}", f"extension={e}")
        s = s.replace("allow_url_include = Off", "allow_url_include = On").replace("allow_url_fopen = Off", "allow_url_fopen = On")
        ini.write_text(s, encoding="utf-8")

    # --- MariaDB --------------------------------------------------------------------------------------
    mdb = TOOLS / "mariadb"
    if not (mdb / "bin" / "mysqld.exe").exists():
        tmp = TOOLS / "_mariadb_x"
        extract(fetch(MDB_URL, DL / "mariadb" / MDB_ZIP, MDB_SHA), tmp)
        (tmp / "mariadb-10.11.19-winx64").rename(mdb)
        tmp.rmdir()
    data = TOOLS / "mariadb_data"
    if not data.exists():
        subprocess.run([str(mdb / "bin" / "mysql_install_db.exe"), f"--datadir={data}", "--password="], check=True)
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "eval"))
    import rangectl
    rangectl._ensure_mariadb(Path(__file__).resolve().parents[2] / "logs")
    sql = ("CREATE DATABASE IF NOT EXISTS dvwa; "
           "CREATE USER IF NOT EXISTS 'dvwa'@'127.0.0.1' IDENTIFIED BY 'p@ssw0rd'; "
           "CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd'; "
           "GRANT ALL ON dvwa.* TO 'dvwa'@'127.0.0.1'; GRANT ALL ON dvwa.* TO 'dvwa'@'localhost';")
    subprocess.run([str(mdb / "bin" / "mysql.exe"), "-u", "root", "-h", "127.0.0.1", "-P", DB_PORT, "-e", sql], check=True)

    # --- DVWA -------------------------------------------------------------------------------------------
    dvwa = TOOLS / "dvwa"
    if not dvwa.exists():
        tmp = TOOLS / "_dvwa_x"
        extract(fetch(DVWA_URL, DL / "dvwa" / "DVWA-2.5.zip", None), tmp)
        (next(tmp.iterdir())).rename(dvwa)
        tmp.rmdir()
    cfg = dvwa / "config" / "config.inc.php"
    if not cfg.exists():
        cfg.write_text((dvwa / "config" / "config.inc.php.dist").read_text(encoding="utf-8"), encoding="utf-8")

    # --- DVWA's own database setup, through its setup page -------------------------------------------------
    env = dict(os.environ, DB_PORT=DB_PORT, DEFAULT_SECURITY_LEVEL="low")
    proc = subprocess.Popen([str(php / "php.exe"), "-c", str(ini), "-S", "127.0.0.1:4280", "-t", str(dvwa)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        time.sleep(3)
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
        base = "http://127.0.0.1:4280"
        tok = lambda h: (re.search(r"name=['\"]user_token['\"] value=['\"]([0-9a-f]+)['\"]", h) or [None, ""])[1]   # noqa: E731
        h = op.open(base + "/setup.php", timeout=30).read().decode("utf-8", "replace")
        h = op.open(base + "/setup.php", urllib.parse.urlencode(
            {"create_db": "Create / Reset Database", "user_token": tok(h)}).encode(), timeout=60).read().decode("utf-8", "replace")
        print("DVWA database setup:", "Setup successful" in h)
        h = op.open(base + "/login.php", timeout=30).read().decode("utf-8", "replace")
        h = op.open(base + "/login.php", urllib.parse.urlencode(
            {"username": "admin", "password": "password", "Login": "Login", "user_token": tok(h)}).encode(),
            timeout=30).read().decode("utf-8", "replace")
        print("admin login works:", "Logout" in h)
    finally:
        proc.terminate()
    print("done: the range starts DVWA itself (Range(app='dvwa')).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
