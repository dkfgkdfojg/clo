# core/cli_runner.py
import os
import sys
import subprocess
import re
import shutil
from .utils import dual_print, logger

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def find_tool_executable(name):
    for c in [
        os.path.join(BASE_DIR, name + (".exe" if os.name == "nt" else "")),
        os.path.join(BASE_DIR, name),
    ]:
        if os.path.isfile(c):
            return c
    return name


def find_python_script(script_name):
    for c in [
        os.path.join(BASE_DIR, script_name),
        os.path.join(BASE_DIR, script_name.replace(".py", ""), script_name),
    ]:
        if os.path.isfile(c):
            return c
    return None


def is_tool_available(cmd_list):
    if not cmd_list:
        return False
    prog = cmd_list[0]
    if prog in ("python", "python3") and len(cmd_list) > 1:
        return find_python_script(cmd_list[1]) is not None
    if os.path.isfile(prog):
        return True
    return shutil.which(prog) is not None


def run_external_tool_with_parser(
    tool_name, primary_cmd, fallback_cmd=None, silent=False, check_existence=True
):
    """
    Запускает внешний инструмент и парсит вывод в формате:
        [+] site_name: https://url
    Возвращает словарь {site_name: url}
    """
    found_urls = {}
    if check_existence and not is_tool_available(primary_cmd):
        if not (fallback_cmd and is_tool_available(fallback_cmd)):
            dual_print(f"  [–] {tool_name}: не установлен.")
            return found_urls

    def execute(cmd_list):
        startupinfo = None
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        dual_print(f"  [→] {tool_name}: {' '.join(cmd_list)}")
        process = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            startupinfo=startupinfo,
            env=env,
        )
        pattern = re.compile(r"\[\+\]\s*([^:]+):\s*(https?://[^\s]+)")
        for line in process.stdout:
            if not silent:
                dual_print("    " + line.rstrip())
            m = pattern.search(line)
            if m:
                found_urls[m.group(1).strip()] = m.group(2).strip()
        process.wait()

    def prepare_cmd(cmd):
        if not cmd:
            return None
        cmd = list(cmd)
        if cmd[0] in ("python", "python3") and len(cmd) > 1:
            sp = find_python_script(cmd[1])
            if sp:
                cmd[1] = sp
        else:
            cmd[0] = find_tool_executable(cmd[0])
        return cmd

    primary_cmd = prepare_cmd(primary_cmd)
    fallback_cmd = prepare_cmd(fallback_cmd) if fallback_cmd else None
    try:
        execute(primary_cmd)
    except FileNotFoundError:
        if fallback_cmd:
            try:
                execute(fallback_cmd)
            except Exception as e:
                logger.debug(f"Fallback failed: {e}")
    except Exception as e:
        dual_print(f"  [!] {tool_name}: {e}")
        logger.debug(f"CLI error: {e}")
    return found_urls
