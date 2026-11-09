"""db_query: read only. The real defense is a database user with SELECT only;
these checks are a second layer. Works with MariaDB and MySQL."""
from __future__ import annotations

import re

from config import cfg

_ALLOWED_START = re.compile(r"^\s*(select|show|describe|desc|explain|with)\b", re.I)
_FORBIDDEN = re.compile(
    r"\b(into\s+(outfile|dumpfile|@)|load_file|sleep|benchmark|lock\s+in\s+share|get_lock|release_lock)\b",
    re.I)
# Writes can only sneak in after a WITH (MySQL 8 allows WITH ... UPDATE/DELETE) or via FOR UPDATE.
_WRITE_WORDS = re.compile(
    r"\b(insert|update|delete|drop|alter|truncate|grant|revoke|call|handler|rename|unlock)\b", re.I)
_STRINGS = re.compile(r"'(?:[^'\\]|\\.|'')*'|\"(?:[^\"\\]|\\.|\"\")*\"|`[^`]*`")


def validate_sql(sql: str) -> str:
    s = sql.strip()
    if s.endswith(";"):
        s = s[:-1].rstrip()
    code = _STRINGS.sub("''", s)  # checks run outside string literals
    if ";" in code:
        raise ValueError("Only one statement")
    if "--" in code or "/*" in code or "#" in code:
        raise ValueError("Comments are not allowed in the query")
    if not _ALLOWED_START.match(code):
        raise ValueError("Only SELECT / SHOW / DESCRIBE / EXPLAIN")
    m = _FORBIDDEN.search(code)
    if not m and not code.lower().startswith("show"):
        m = _WRITE_WORDS.search(code)
    if m:
        raise ValueError(f"Construct not allowed in the query: {m.group(0)}")
    return s


def do_db_query(sql: str, max_rows: int = 100) -> str:
    import pymysql  # late import: the rest of the server works without a database
    import pymysql.cursors

    s = validate_sql(sql)
    if not cfg.db_user:
        raise ValueError("Database not configured (MCP_DB_USER)")
    max_rows = max(1, min(max_rows, cfg.db_max_rows))
    conn = pymysql.connect(host=cfg.db_host, port=cfg.db_port, user=cfg.db_user,
                           password=cfg.db_password, database=cfg.db_name, charset="utf8mb4",
                           connect_timeout=5, read_timeout=20, write_timeout=10, autocommit=True,
                           cursorclass=pymysql.cursors.SSCursor)  # without loading the whole result into memory
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT VERSION()")
        mariadb = "mariadb" in str(cur.fetchone()[0]).lower()
        cur.close()
        cur = conn.cursor()
        if mariadb:
            cur.execute("SET SESSION max_statement_time=10")  # seconds
        else:
            cur.execute("SET SESSION MAX_EXECUTION_TIME=10000")  # milliseconds
        cur.execute("SET SESSION TRANSACTION READ ONLY")
        cur.execute(s)
        cols = [d[0] for d in (cur.description or [])]
        rows = cur.fetchmany(max_rows + 1)
    finally:
        # Cut the connection without draining the remaining rows (SSCursor would drain on close):
        # drop the references to the pending result so nothing tries to read it afterwards.
        if cur is not None:
            cur._result = None
            cur.connection = None
        conn._result = None
        try:
            conn._force_close()
        except Exception:
            pass
    more = len(rows) > max_rows
    rows = rows[:max_rows]
    out = [" | ".join(cols)] + [" | ".join("NULL" if v is None else str(v)[:200] for v in r) for r in rows]
    if more:
        out.append(f"...[limited to {max_rows} rows]")
    return "\n".join(out)
