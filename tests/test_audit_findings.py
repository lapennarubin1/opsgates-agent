"""Regresión de los hallazgos de la auditoría del 19/10 (cada uno se reprodujo antes del arreglo)."""
import os

import pytest

from config import cfg
from security import has_redaction_marker, redact
from tools import commands, files, system


@pytest.fixture
def tree(env):
    root, out = env["root"], env["outside"]
    (root / "sub").mkdir()
    (root / ".env").write_text("STRINGEE_SECRET=abc123")
    (root / "id_rsa").write_text("CLAVE_SIN_CABECERA")
    (root / "pjsip.conf").write_text("[p1]\npassword=RealPass99\nhost=1.2.3.4\n")
    os.symlink(out / "secreto.txt", root / "enlace")
    return env


def cmd(c, env, **kw):
    return commands.do_run_command(c, cwd=str(env["root"]), **kw)


# --- H1: lectura fuera de las carpetas permitidas por run_command
@pytest.mark.parametrize("c", [
    "cat sub/../../outside/secreto.txt",      # relativa con ../
    "cat ../outside/secreto.txt",
    "grep -f/etc/hostname -e x pjsip.conf",   # ruta pegada a opción corta
    "grep --file=/etc/hostname x pjsip.conf",
    "cat enlace",                             # symlink sin barra
    "head -n1 /proc/self/environ",
    "diff /etc/hostname pjsip.conf",
    "tail ..",
])
def test_h1_rutas_fuera(tree, c):
    with pytest.raises(ValueError):
        cmd(c, tree)


# --- H2: secretos por nombre sin ruta y por recursión
@pytest.mark.parametrize("c", [
    "cat id_rsa", "cat .env", "head .env", "grep SECRET .env", "cat ./sub/../.env",
    "grep -r SECRET .", "grep -R SECRET .", "grep -rn SECRET .", "grep --recursive SECRET .",
    "grep -d recurse SECRET .", "diff -r . sub", "diff -ru . sub",
])
def test_h2_secretos(tree, c):
    with pytest.raises(ValueError):
        cmd(c, tree)


# --- H3: search_files con glob que sale de la raíz
@pytest.mark.parametrize("g", ["../outside/*", "../*", "/etc/*", "sub/../../outside/*"])
def test_h3_glob(tree, g):
    with pytest.raises(ValueError):
        files.do_search_files("SECRETO", str(tree["root"]), glob=g)


def test_h3_search_no_sigue_symlink(tree):
    assert "SECRETO" not in files.do_search_files("SECRETO", str(tree["root"]))


# --- H4: reescribir un fichero leído con secretos ocultos borraba la contraseña real
def test_h4_write_con_redaccion_rechazado(tree):
    f = tree["root"] / "pjsip.conf"
    leido = redact(f.read_text())
    assert "RealPass99" not in leido
    with pytest.raises(ValueError):
        files.do_write_file(str(f), leido.replace("1.2.3.4", "5.6.7.8"), confirm=True)
    assert "RealPass99" in f.read_text()
    # La vía correcta: edit_file sobre la línea concreta conserva la contraseña
    files.do_edit_file(str(f), "host=1.2.3.4", "host=5.6.7.8", confirm=True)
    assert "RealPass99" in f.read_text() and "5.6.7.8" in f.read_text()


def test_h4_edit_new_con_redaccion_rechazado(tree):
    with pytest.raises(ValueError):
        files.do_edit_file(str(tree["root"] / "pjsip.conf"), "host=1.2.3.4", "password=***", confirm=True)


@pytest.mark.parametrize("t,expected", [
    ("password=***", True), ("secret: '***'", True), ("Bearer ***", True), ("mysql://u:***@h", True),
    ("[PRIVATE KEY HIDDEN]", True), ("[TOKEN HIDDEN]", True),
    ("password=nueva123", False), ("x = a ** b", False), ("# *** nota ***", False),
])
def test_marcadores(t, expected):
    assert has_redaction_marker(t) is expected


# --- H5: tokens con formato conocido sin clave delante
@pytest.mark.parametrize("tok", [
    "ghp_" + "a" * 36, "sk-ant-api03-" + "b" * 30, "sk_" + "c" * 40, "AKIA" + "D" * 16,
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlMTIz", "123456789:" + "E" * 35,
])
def test_h5_tokens_sueltos(tok):
    assert tok not in redact(f"valor {tok} fin")


# --- H6: escritura dentro de .git (hooks = ejecución de código)
def test_h6_git(tree):
    (tree["root"] / ".git" / "hooks").mkdir(parents=True)
    with pytest.raises(ValueError):
        files.do_write_file(str(tree["root"] / ".git" / "hooks" / "post-merge"), "#!/bin/sh\nid", confirm=True)
    with pytest.raises(ValueError):
        cmd("cp pjsip.conf .git/config", tree, confirm=True)


# --- H7: opciones peligrosas
@pytest.mark.parametrize("c", [
    "git log --output=x.txt", "git diff --ext-diff", "systemctl status -H root@1.2.3.4 x",
    "systemctl status --host=x y", "date -s 2020-01-01", "ss -K", "journalctl --vacuum-size=1M",
])
def test_h7_opciones(tree, c):
    with pytest.raises(ValueError):
        cmd(c, tree)


# --- H8: cwd con os.chdir era global (carrera entre hilos): ahora no se cambia el cwd del proceso
def test_h8_sin_chdir(tree):
    before = os.getcwd()
    cmd("ls", tree)
    assert os.getcwd() == before


# --- H9: salida binaria no rompe la herramienta
def test_h9_binario(tree):
    (tree["root"] / "b.bin").write_bytes(b"\xff\xfe\x00\x81ok")
    assert "ok" in cmd("cat b.bin", tree)


# --- H10: tail_log lee desde el final
def test_h10_tail_grande(env):
    f = env["logs"] / "big.log"
    with open(f, "w") as fh:
        for i in range(300_000):
            fh.write(f"linea {i}\n")
    assert system.do_tail_log(str(f), 2).splitlines() == ["linea 299998", "linea 299999"]


# --- Asterisk: validación por palabras (igual que el envoltorio root)
@pytest.mark.parametrize("c", ["pjsip show endpoints", "core show channels", "core show uptime",
                               "dialplan show from-internal", "pjsip show endpoint proveedor1"])
def test_asterisk_ok(c):
    system.validate_asterisk(c)


@pytest.mark.parametrize("c", ["pjsip showx", "core show channelsfoo; x", "pjsip reload",
                               "core restart now", "module load x", "dialplan reload", "", "core show $(id)"])
def test_asterisk_rechaza(c):
    with pytest.raises(ValueError):
        system.validate_asterisk(c)


# --- usos legítimos que deben seguir funcionando
@pytest.mark.parametrize("c", ["ls -la", "ls -la sub", "cat pjsip.conf", "head -n 2 pjsip.conf", "wc -l pjsip.conf",
                               "grep -n host pjsip.conf", "grep -in HOST pjsip.conf", "du -sh .", "stat pjsip.conf",
                               "ps aux", "df -h", "uptime"])
def test_legitimos(tree, c):
    assert "[rc=" in cmd(c, tree)


# --- H11: un intérprete general ("python3", "pip", "node" sueltos) sería shell libre encubierto
@pytest.mark.parametrize("c", [
    "python3 -c print(1)", "python3 -c import os;os.system('id')", "pip install evil",
    "pip3 install evil", "node -e console.log(1)", "npm install evil", "npm run build",
])
def test_h11_interprete_general_bloqueado(tree, c):
    with pytest.raises(ValueError):
        cmd(c, tree)
