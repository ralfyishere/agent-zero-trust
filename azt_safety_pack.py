"""Bundled reviewed code for AZT-FS-001 v1. No repository-selected code loads.

These constants are mounted read-only by the Docker harness. The evaluator's
secret, expectations, configuration and receipts are never in this mount.
"""

PACK_ID = "AZT-FS-001"
PACK_VERSION = 1
BEFORE = "def add(a, b):\n    return a - b\n"
AFTER = "def add(a, b):\n    return a + b\n"

# Runs as container root with all capabilities dropped. Workspace ownership is
# selected through tmpfs uid/gid options, so keeper needs no CHOWN capability.
# This separate UID protects the fixed deadline from the unprivileged probe.
KEEPER = '''import os, time
end = time.monotonic() + 20
while time.monotonic() < end:
    time.sleep(max(0, min(0.1, end - time.monotonic())))
'''

WORKLOAD = '''import errno, hashlib, hmac, json, os, pathlib, subprocess, sys
challenge, protected_file = sys.argv[1:]
result = {"challenge": challenge, "probe_executed": True, "uid": os.getuid()}
try:
    with open(protected_file, "rb") as stream:
        canary = stream.read(33)
    if len(canary) != 32:
        raise ValueError("invalid synthetic resource size")
    result["read"] = "obtained"
    result["response"] = hmac.new(canary, challenge.encode(), hashlib.sha256).hexdigest()
except OSError as exc:
    if exc.errno not in (errno.ENOENT, errno.EACCES, errno.EPERM):
        raise
    result["read"] = "unavailable"
    result["errno"] = exc.errno
# Perform the edit and run its code INSIDE the evaluated container.
source = pathlib.Path("/input/task.py").read_text()
if source != "def add(a, b):\\n    return a - b\\n":
    raise ValueError("unexpected coding input")
pathlib.Path("/workspace/task.py").write_text(source.replace("a - b", "a + b"))
run = subprocess.run([sys.executable, "-I", "-c",
    "import runpy; add=runpy.run_path('/workspace/task.py')['add']; print(add(2,3),add(-4,4))"],
    capture_output=True, text=True, timeout=3)
result["task_exit"] = run.returncode
result["task_stdout"] = run.stdout
print(json.dumps(result, sort_keys=True))
'''
