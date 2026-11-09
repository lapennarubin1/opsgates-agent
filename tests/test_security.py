import json
import os

import pytest
from pathlib import Path

import security
from config import cfg
from security import redact, resolve_inside
from tools import commands, db, files, system


# ------------------------------------------------------------------ redacción
@pytest.mark.parametrize("raw,secret", [
    ("password=SuperSecreta123", "SuperSecreta123"),
    ("secret = abc123XYZ", "abc123XYZ"),
    ('"api_key": "sk-live-9999"', "sk-live-9999"),
    ("DB_PASSWORD='con espacios y comillas'", "con espacios y comillas"),
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig", "eyJhbGciOiJIUzI1NiJ9"),
    ("mysql://admin:p4ss@localhost/db", "p4ss"),
    ("auth_token: tok_abcdef123456", "tok_abcdef123456"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3Nza\nxyz\n-----END OPENSSH PRIVATE KEY-----", "AAAAB3Nza"),
    ("md5_cred=0123456789abcdef", "0123456789abcdef"),
])
def test_redact_oculta_secretos(raw, secret):
    assert secret not in redact(raw)


def test_redact_no_toca_texto_normal():
    txt = "SIP/1001 registrado en 10.0.0.5, 3 canales activos"
    assert redact(txt) == txt


# ------------------------------------------------------------------ rutas
def test_ruta_dentro_ok(env):
    f = env["root"] / "a.txt"
    f.write_text("hola")
    assert resolve_inside(str(f), cfg.read_roots) == f


def test_ruta_fuera_rechazada(env):
    with pytest.raises(ValueError):
        resolve_inside(str(env["outside"] / "secreto.txt"), cfg.read_roots)


def test_traversal_rechazado(env):
    with pytest.raises(ValueError):
        resolve_inside(str(env["root"] / ".." / "outside" / "secreto.txt"), cfg.read_roots)


def test_symlink_hacia_fuera_rechazado(env):
    link = env["root"] / "enlace"
    os.symlink(env["outside"] / "secreto.txt", link)
    with pytest.raises(ValueError):
        files.do_read_file(str(link))


def test_prefijo_parecido_no_cuela(env):
    hermano = env["root"].parent / (env["root"].name + "-otro")
    hermano.mkdir()
    (hermano / "x.txt").write_text("x")
    with pytest.raises(ValueError):
        resolve_inside(str(hermano / "x.txt"), cfg.read_roots)


def test_ruta_relativa_rechazada(env):
    with pytest.raises(ValueError):
        resolve_inside("a.txt", cfg.read_roots)


@pytest.mark.parametrize("name", [".env", ".env.production", "clave.pem", "x.key", "id_rsa", "device.json"])
def test_ficheros_protegidos(env, name):
    f = env["root"] / name
    f.write_text("password=zzz")
    with pytest.raises(ValueError):
        files.do_read_file(str(f))
    with pytest.raises(ValueError):
        files.do_write_file(str(f), "x", confirm=True)


def test_search_ignora_protegidos(env):
    (env["root"] / ".env").write_text("TOKEN=abc")
    (env["root"] / "ok.py").write_text("TOKEN=abc")
    res = files.do_search_files("TOKEN", str(env["root"]))
    assert "ok.py" in res and ".env" not in res


# ------------------------------------------------------------------ escritura
def test_write_sin_confirm_no_escribe(env):
    f = env["root"] / "c.conf"
    f.write_text("uno\n")
    out = files.do_write_file(str(f), "dos\n")
    assert "NOT written" in out and f.read_text() == "uno\n"


def test_write_confirm_hace_backup(env):
    f = env["root"] / "c.conf"
    f.write_text("uno\n")
    out = files.do_write_file(str(f), "dos\n", confirm=True)
    assert f.read_text() == "dos\n"
    backups = list(cfg.backup_dir.iterdir())
    assert len(backups) == 1 and backups[0].read_text() == "uno\n"
    assert "Backup" in out


def test_write_fuera_rechazado(env):
    with pytest.raises(ValueError):
        files.do_write_file(str(env["outside"] / "n.txt"), "x", confirm=True)


def test_edit_unico_y_ambiguo(env):
    f = env["root"] / "e.txt"
    f.write_text("a=1\nb=2\nb=2\n")
    with pytest.raises(ValueError):
        files.do_edit_file(str(f), "b=2", "b=3", confirm=True)  # aparece 2 veces
    files.do_edit_file(str(f), "a=1", "a=9", confirm=True)
    assert f.read_text().startswith("a=9")


# ------------------------------------------------------------------ comandos
def test_comando_no_permitido(env):
    with pytest.raises(ValueError):
        commands.do_run_command("rm -rf /", cwd=str(env["root"]))
    with pytest.raises(ValueError):
        commands.do_run_command("python3 -c 'print(1)'", cwd=str(env["root"]))


def test_comando_permitido_y_confinado(env):
    (env["root"] / "a.txt").write_text("hola")
    out = commands.do_run_command("cat a.txt", cwd=str(env["root"]))
    assert "hola" in out
    with pytest.raises(ValueError):
        commands.do_run_command("cat /etc/passwd", cwd=str(env["root"]))
    with pytest.raises(ValueError):
        commands.do_run_command("cat ../outside/secreto.txt", cwd=str(env["root"]))
    with pytest.raises(ValueError):
        commands.do_run_command("grep --file=/etc/passwd x", cwd=str(env["root"]))


def test_sin_shell_pipes_son_literales(env):
    (env["root"] / "a.txt").write_text("hola")
    out = commands.do_run_command("cat a.txt | wc -l", cwd=str(env["root"]))
    assert "No such file" in out or "rc=1" in out  # '|' llega como argumento, no se interpreta


def test_comando_que_modifica_pide_confirm(env):
    with pytest.raises(ValueError):
        commands.do_run_command("touch nuevo.txt", cwd=str(env["root"]))
    commands.do_run_command("touch nuevo.txt", cwd=str(env["root"]), confirm=True)
    assert (env["root"] / "nuevo.txt").exists()


def test_env_del_servicio_no_se_filtra(env, monkeypatch):
    monkeypatch.setenv("MCP_DB_PASSWORD", "NO_DEBE_SALIR")
    cfg.run_allowed = cfg.run_allowed + ["env"]
    try:
        out = commands.do_run_command("env", cwd=str(env["root"]))
    finally:
        cfg.run_allowed.remove("env")
    assert "NO_DEBE_SALIR" not in out


def test_timeout(env):
    cfg.run_allowed.append("sleep")
    try:
        with pytest.raises(ValueError):
            commands.do_run_command("sleep 5", cwd=str(env["root"]), timeout=1)
    finally:
        cfg.run_allowed.remove("sleep")


def test_sesion_lee_salida(env):
    cfg.run_allowed.append("echo")
    try:
        msg = commands.do_start_session("echo hola-sesion", cwd=str(env["root"]))
        sid = msg.split()[1]
        out = commands.do_read_session(sid, wait=1)
        assert "hola-sesion" in out
        commands.do_stop_session(sid)
    finally:
        cfg.run_allowed.remove("echo")


# ------------------------------------------------------------------ sistema
def test_wildcard_permite_cualquier_nombre_valido():
    # Por defecto (config general, no de un proyecto) no hay lista cerrada de servicios:
    # la protección es que restart/reload siguen exigiendo confirm=true, y sudo real
    # (deploy/sudoers.d) es la única lista cerrada que de verdad importa.
    assert cfg.services == {"*"} and cfg.restartable == {"*"}
    system._check("cualquier-servicio-random", cfg.services)
    assert "NOT restarted" in system.do_service_restart("asterisk")  # sin confirm: nunca ejecuta


@pytest.mark.parametrize("name", ["foo;bar", "foo bar", "foo/bar", "foo$(x)", "foo`x`", "", "../etc"])
def test_wildcard_rechaza_nombres_con_caracteres_raros(name):
    with pytest.raises(ValueError):
        system._check(name, cfg.services)


def test_lista_cerrada_configurada_sigue_funcionando():
    # Si alguien SÍ configura una lista (MCP_SERVICES=...), vuelve a ser cerrada.
    with pytest.raises(ValueError):
        system._check("ssh", {"myapp-staging", "mariadb"})
    system._check("mariadb", {"myapp-staging", "mariadb"})  # no lanza


def test_restart_sin_confirm_no_ejecuta():
    assert "NOT restarted" in system.do_service_restart("myapp-staging")


@pytest.mark.parametrize("cmd", [
    "pjsip show endpoints; rm -rf /", "core show channels\nmodule unload x", "pjsip show x | sh",
    "module unload app_dial", "core restart now", "dialplan reload",
])
def test_asterisk_cli_rechaza(cmd):
    with pytest.raises(ValueError):
        system.do_asterisk_cli(cmd)


def test_tail_log_solo_en_logs(env):
    (env["logs"] / "a.log").write_text("\n".join(f"l{i}" for i in range(10)))
    assert system.do_tail_log(str(env["logs"] / "a.log"), 3).splitlines() == ["l7", "l8", "l9"]
    with pytest.raises(ValueError):
        system.do_tail_log(str(env["outside"] / "secreto.txt"))


# ------------------------------------------------------------------ SQL
@pytest.mark.parametrize("sql", [
    "SELECT * FROM leads", "select 1;", "SHOW TABLES", "DESCRIBE crm_leads", "EXPLAIN SELECT 1",
    "SELECT * FROM t WHERE note = 'drop; -- #1'", "SELECT REPLACE(phone,'+','') FROM t",
    "SHOW CREATE TABLE crm_leads", "SELECT created_at, updated_at FROM t",
    "WITH x AS (SELECT 1 AS a) SELECT a FROM x",
])
def test_sql_permitido(sql):
    db.validate_sql(sql)


@pytest.mark.parametrize("sql", [
    "DELETE FROM leads", "UPDATE leads SET a=1", "DROP TABLE x", "SELECT 1; DROP TABLE x",
    "SELECT * FROM t INTO OUTFILE '/tmp/x'", "SELECT LOAD_FILE('/etc/passwd')", "SELECT SLEEP(10)",
    "SELECT 1 -- x", "SELECT 1 /* x */", "INSERT INTO t VALUES (1)", "SELECT * FROM t FOR UPDATE",
    "WITH x AS (SELECT 1) DELETE FROM t", "SELECT 1 INTO @a", "SELECT GET_LOCK('a', 10)",
    "SELECT 1;DROP TABLE t", "SELECT 'a'; DELETE FROM t",
])
def test_sql_rechazado(sql):
    with pytest.raises(ValueError):
        db.validate_sql(sql)


# ------------------------------------------------------------------ límites y auditoría
def test_rate_limit(env):
    cfg.rate_per_minute = 3
    security.reset_rate_limit()
    for _ in range(3):
        security.rate_limit()
    with pytest.raises(ValueError):
        security.rate_limit()


def test_auditoria_no_guarda_contenido(env):
    import audit
    big = "x" * 500
    audit.log("write_file", {"path": "/a", "content": big}, True, 5)
    line = json.loads(cfg.audit_file.read_text().splitlines()[-1])
    assert line["params"]["content"]["len"] == 500 and big not in cfg.audit_file.read_text()


def test_agent_own_files_not_writable(env, tmp_path):
    from config import cfg
    from tools import commands, files
    saved = cfg.state_dir
    state = env["root"] / "opsgate-state"
    state.mkdir()
    (state / "meter.json").write_text("{}")
    cfg.state_dir = state
    try:
        with pytest.raises(ValueError, match="own (files|configuration)"):
            files.do_write_file(str(state / "meter.json"), '{"pending": 0}', confirm=True)
        with pytest.raises(ValueError, match="own (files|configuration)"):
            files.do_edit_file(str(state / "meter.json"), "{}", "[]", confirm=True)
        with pytest.raises(ValueError, match="own (files|configuration)"):
            commands.do_run_command(f"touch {state}/x", confirm=True)
        assert (state / "meter.json").read_text() == "{}"
    finally:
        cfg.state_dir = saved


def test_oauth_db_not_readable(env):
    from tools import files
    (env["root"] / "oauth.db").write_text("x")
    with pytest.raises(ValueError, match="Protected"):
        files.do_read_file(str(env["root"] / "oauth.db"))


@pytest.mark.parametrize("cmd", [
    "find {root} -maxdepth 0 -exec id ;", "find {root} -delete", "find {root} -fprint {root}/x",
    "find {root} -execdir id ;", "find {root} -ok id ;", "find {root} -okdir id ;", "find {root} -fls {root}/x",
    "find {root} -name x -fprintf {root}/y %p", "find -- {root} -delete",
    "tree -o {root}/out {root}", "tree -R -H . {root}", "file -C -m {root}/x", "file --compile {root}/x"])
def test_commands_that_execute_or_write_are_refused(env, cmd):
    from tools import commands
    root = env["root"]
    (root / "keep.txt").write_text("keep")
    with pytest.raises(ValueError, match="not allowed"):
        commands.do_run_command(cmd.format(root=root), str(root), 5, True)
    assert (root / "keep.txt").exists() and not (root / "x").exists() and not (root / "out").exists()


def test_proc_environ_is_protected(env):
    from config import cfg
    from tools import commands, files
    saved = cfg.read_roots
    cfg.read_roots = [Path("/")]
    try:
        with pytest.raises(ValueError, match="Protected"):
            files.do_read_file("/proc/self/environ")
        with pytest.raises(ValueError, match="Protected"):
            commands.do_run_command("cat /proc/self/environ", "/", 5, False)
    finally:
        cfg.read_roots = saved


def test_ps_environment_and_git_textconv(env, tmp_path):
    import subprocess
    from tools import commands
    with pytest.raises(ValueError, match="environments"):
        commands.do_run_command("ps auxe", str(env["root"]), 5, False)
    assert "[rc=0]" in commands.do_run_command("ps -e", str(env["root"]), 5, False)
    repo = env["root"] / "repo"
    repo.mkdir()
    marker = tmp_path / "pwned"
    genv = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    run = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, env=genv)  # noqa: E731
    run("init", "-q")
    run("config", "user.email", "t@t"); run("config", "user.name", "t")
    run("config", "diff.evil.textconv", f"sh -c 'touch {marker}; cat' --")
    (repo / ".gitattributes").write_text("*.bin diff=evil\n")
    (repo / "a.bin").write_bytes(b"\x00one")
    run("add", "."); run("commit", "-qm", "1")
    (repo / "a.bin").write_bytes(b"\x00two")
    run("commit", "-qam", "2")
    for c in ("git log -p", "git show HEAD", "git diff HEAD~1"):
        with pytest.raises(ValueError, match="run a program"):  # refused outright now
            commands.do_run_command(c, str(repo), 10, False)
    assert not marker.exists(), "a repository diff driver was executed"
    # second layer: even without the config check, diff/log/show never run text conversions
    import unittest.mock as um
    with um.patch.object(commands, "_check_git_repo", lambda w: None):
        for c in ("git log -p", "git show HEAD", "git diff HEAD~1"):
            commands.do_run_command(c, str(repo), 10, False)
    assert not marker.exists(), "a repository diff driver was executed"


@pytest.mark.parametrize("raw,secret", [
    ("define('DB_PASSWORD', 'S3cretWPpass99');", "S3cretWPpass99"),
    ("define( 'AUTH_KEY',         'put your unique phrase here' );", "unique phrase"),
    ("define('NONCE_SALT', 'abc def');", "abc def"),
    ("password RealNginxSecret123", "RealNginxSecret123"),
    ('API_PASSWORD "QuotedPass789"', "QuotedPass789"),
    ("  'password' => 'ArrayPass1',", "ArrayPass1"),
    ("requirepass redisPass42", "redisPass42"),
    ("masterauth redisMaster9", "redisMaster9"),
    ("12\trequirepass numberedPass", "numberedPass"),
    ("/etc/redis.conf:812:requirepass grepPass", "grepPass"),
    ("smtp_pass=x1Secret", "x1Secret"),
    ("DB_PASS: hunter2hunter", "hunter2hunter"),
    ('DATABASES = {"default": {"PASSWORD": "djangoPass"}}', "djangoPass"),
])
def test_redact_more_formats(raw, secret):
    out = redact(raw)
    assert secret not in out and security.has_redaction_marker(out)


@pytest.mark.parametrize("txt", [
    "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2",
    "Password reset links expire after one hour.",
    "the token bucket refills every second", "def check(password):", "# token refresh logic",
    "bypass=1 compass=north passenger=3"])
def test_redact_leaves_prose_and_lookalikes(txt):
    assert redact(txt) == txt


@pytest.mark.parametrize("key,value", [
    ("filter.evil.smudge", "sh -c 'touch /tmp/x'"), ("filter.evil.clean", "evil"), ("merge.evil.driver", "evil %O"),
    ("core.sshCommand", "evil"), ("credential.helper", "evil"), ("remote.origin.uploadpack", "evil"),
    ("include.path", "/tmp/evil.config"), ("url.evil.insteadOf", "https://")])
def test_git_refuses_repos_that_configure_programs(env, key, value):
    import subprocess
    from tools import commands
    repo = env["root"] / "r"
    repo.mkdir()
    genv = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, env=genv)
    assert "[rc=0]" in commands.do_run_command("git status", str(repo), 10, False)
    subprocess.run(["git", "-C", str(repo), "config", key, value], check=True, env=genv)
    with pytest.raises(ValueError, match="run a program"):
        commands.do_run_command("git status", str(repo), 10, False)


def test_git_lfs_filters_are_allowed_and_pull_is_fast_forward_only(env):
    import subprocess
    from tools import commands
    repo = env["root"] / "lfs"
    repo.mkdir()
    genv = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, env=genv)
    subprocess.run(["git", "-C", str(repo), "config", "filter.lfs.smudge", "git-lfs smudge -- %f"], check=True, env=genv)
    assert "[rc=0]" in commands.do_run_command("git status", str(repo), 10, False)
    with pytest.raises(ValueError, match="not allowed"):
        commands.do_run_command("git pull --rebase", str(repo), 10, True)
    tokens, _ = commands._prepare("git pull origin main", str(repo), True)
    assert tokens[tokens.index("pull") + 1] == "--ff-only"


def test_agent_state_not_readable(env):
    from config import cfg
    from tools import commands, files
    saved = cfg.state_dir
    state = env["root"] / "state"
    state.mkdir()
    (state / "meter.json").write_text('{"used": 1}')
    cfg.state_dir = state
    try:
        with pytest.raises(ValueError, match="not readable"):
            files.do_read_file(str(state / "meter.json"))
        with pytest.raises(ValueError, match="not readable"):
            commands.do_run_command(f"cat {state}/meter.json", str(env["root"]), 5, False)
    finally:
        cfg.state_dir = saved
    (env["root"] / "env").write_text("OPSGATE_LICENSE_KEY=x")
    with pytest.raises(ValueError, match="Protected"):
        files.do_read_file(str(env["root"] / "env"))


def test_rate_limit_is_per_client(env):
    from config import cfg
    saved = cfg.rate_per_minute
    cfg.rate_per_minute = 3
    security.reset_rate_limit()
    try:
        for _ in range(3):
            security.rate_limit("claude")
        with pytest.raises(ValueError, match="Too many"):
            security.rate_limit("claude")
        security.rate_limit("cursor")  # another app is not blocked by the first one
    finally:
        cfg.rate_per_minute = saved
        security.reset_rate_limit()


@pytest.mark.parametrize("raw,secret", [
    ("machine api.example.com login bob password NetrcPass1", "NetrcPass1"),
    ("<password>XmlPass2</password>", "XmlPass2"),
    ('<DbPassword attr="1">XmlPass3</DbPassword>', "XmlPass3"),
    ('<add key="DbPassword" value="DotNetPass4"/>', "DotNetPass4"),
    ("mysqldump -uroot -pDumpPass5 shop > shop.sql", "DumpPass5"),
    ("mysql -h db -u app -p'Quoted Pass6' app", "Quoted Pass6"),
    ("db.example.com:5432:shop:app:PgPass7", "PgPass7"),
    ("12\tdb.example.com:*:*:app:PgPass8", "PgPass8"),
    ("/root/.pgpass:3: db.example.com:5432:shop:app:PgPass13", "PgPass13"),
    ("/srv/app/.netrc:1: machine h login bob password NetrcPass14", "NetrcPass14"),
    ("/srv/app/web.config:7: <password>XmlPass15</password>", "XmlPass15"),
    ("5:localhost:5432:mydb:appuser:PgPass16", "PgPass16"),
    ("/srv/x/secrets.txt:3: localhost:5432:mydb:appuser:PgPass17", "PgPass17"),
    ("redis-cli -h cache -a RedisPass18 ping", "RedisPass18"),
    ("sshpass -p SshPass19 ssh root@h", "SshPass19"),
    ("docker login -u me -p DockerPass20 registry.example.com", "DockerPass20"),
    ("docker login --password DockerPass21 r.example.com", "DockerPass21"),
    ('{"auths": {"r.example.com": {"auth": "ZG9ja2VyOnBhc3MyMg=="}}}', "ZG9ja2VyOnBhc3MyMg=="),
    ("_auth=bnBtOnBhc3MyMw==", "bnBtOnBhc3MyMw=="),
    ("db:\n  password: |\n    YamlBlockPass24\n  host: x", "YamlBlockPass24"),
    ("/s/app.yml:2:   password: |\n/s/app.yml:3:     YamlBlockPass25\n/s/app.yml:4:   host: x", "YamlBlockPass25"),
    ("2\t  password: >-\n3\t    YamlBlockPass26\n4\t  host: x", "YamlBlockPass26"),
    ("MAPS_KEY=AIzaSyA1234567890abcdefghijklmnopqrstuv", "AIzaSyA1234567890abcdefghijklmnopqrstuv"),
    ("Authorization: Token TokPass9abc", "TokPass9abc"),
    ('"Authorization": "Digest DigPass10"', "DigPass10"),
    ("curl -u admin:CurlPass11 https://x", "CurlPass11"),
    ("curl --user admin:CurlPass12 https://x", "CurlPass12"),
])
def test_redact_config_formats_round_two(raw, secret):
    out = redact(raw)
    assert secret not in out
    assert security.has_redaction_marker(out), out  # writing it back would be refused


@pytest.mark.parametrize("txt", [
    "user:x:1000:1000:User:/home/user:/bin/bash", "12:30:45", "fe80::1", "mysql -u app -p app",
    "<title>Reset your password</title>", "time 10:20:30:40",
    "/srv/app/secrets.py:12:    return None", "auth    required   pam_unix.so", "docker ps -a", "mysql -u app -p app"])
def test_no_false_positives_round_two(txt):
    assert redact(txt) == txt


def test_git_check_covers_other_owners_and_worktree_config(env, tmp_path):
    import shutil
    import subprocess
    from tools import commands
    genv = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    repo = env["root"] / "wt"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, env=genv)
    subprocess.run(["git", "-C", str(repo), "config", "extensions.worktreeConfig", "true"], check=True, env=genv)
    subprocess.run(["git", "-C", str(repo), "config", "--worktree", "filter.x.clean", "evil"], check=True, env=genv)
    with pytest.raises(ValueError, match="run a program"):
        commands.do_run_command("git status", str(repo), 10, False)
    # a repository owned by another user: the check must still see (and refuse) its config
    other = env["root"] / "other"
    other.mkdir()
    subprocess.run(["git", "-C", str(other), "init", "-q"], check=True, env=genv)
    subprocess.run(["git", "-C", str(other), "config", "filter.y.smudge", "evil"], check=True, env=genv)
    if os.geteuid() == 0 and shutil.which("runuser"):
        os.chown(other / ".git", 65534, 65534)  # nobody: "dubious ownership" for the test user
    with pytest.raises(ValueError, match="run a program|Could not inspect"):
        commands.do_run_command("git status", str(other), 10, False)


def test_search_and_list_skip_agent_state(env):
    from config import cfg
    from tools import files
    saved = cfg.state_dir
    state = env["root"] / "st"
    state.mkdir()
    (state / "meter.json").write_text('{"used": 77, "needle": 1}')
    cfg.state_dir = state
    try:
        assert "needle" not in files.do_search_files("needle", str(env["root"]))
        assert "st  [protected]" in files.do_list_dir(str(env["root"]))
    finally:
        cfg.state_dir = saved


def test_yaml_block_stops_at_sibling_keys():
    out = redact("db:\n  password: |\n    YamlBlockPass27\n  host: db.example.com\n")
    assert "YamlBlockPass27" not in out and "host: db.example.com" in out
