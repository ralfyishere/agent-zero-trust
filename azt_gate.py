"""Authenticated snapshot receipts for an honest workflow gate, not isolation."""
import hashlib
import hmac
import os
import secrets
import stat
import time
from pathlib import Path

from azt_intake import IntakeError, canonical, digest, json_object, open_absolute, read_fd

MAX_TTL_SECONDS = 86400


def engine_digest():
    directory = Path(__file__).parent
    return digest({name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                   for name in ("azt.py", "azt_intake.py", "azt_gate.py", "azt_sensitive.py", "azt_review.py")})


def workspace_id(root):
    root = Path(os.path.abspath(root))
    fd = open_absolute(root, directory=True)
    try:
        meta = os.fstat(fd)
        return digest({"path": str(root), "device": meta.st_dev, "inode": meta.st_ino})
    finally:
        os.close(fd)


def open_store(path, root, create=False):
    if not path:
        raise IntakeError("--state-dir is required; use a private operator directory outside the workspace")
    path, root = Path(os.path.abspath(path)), Path(os.path.abspath(root))
    if path == root or root in path.parents:
        raise IntakeError("state directory must be outside the workspace")
    if create:
        # Only one new directory; never recursively create through untrusted links.
        parent = open_absolute(path.parent, directory=True)
        try:
            try:
                os.mkdir(path.name, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
        finally:
            os.close(parent)
    fd = open_absolute(path, directory=True)
    meta = os.fstat(fd)
    if meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) != 0o700:
        os.close(fd)
        raise IntakeError("state directory must be operator-owned with mode 0700")
    return fd


def read_private(fd, name, limit):
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        raw, meta = read_fd(child, limit)
        if meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1:
            raise IntakeError("state files must be private regular files with one link")
        return raw
    finally:
        os.close(child)


def key_for(fd, create=False):
    if create:
        try:
            keyfd = os.open("issuer.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        except FileExistsError:
            pass
        else:
            try:
                key = secrets.token_bytes(32)
                if os.write(keyfd, key) != len(key):
                    raise IntakeError("key write failed")
                os.fsync(keyfd)
            finally:
                os.close(keyfd)
    key = read_private(fd, "issuer.key", 32)
    if len(key) != 32:
        raise IntakeError("invalid issuer key")
    return key


def binding(root, report, threshold):
    return {"workspace_id": workspace_id(root), "input_digest": report["input_digest"],
            "scope_digest": digest(report["scope"]), "engine_digest": engine_digest(),
            "engine_version": report["version"], "policy": report["policy"], "threshold": threshold}


def issue(root, state_dir, report, threshold, ttl_minutes):
    if type(ttl_minutes) is not int or not 1 <= ttl_minutes <= 1440:
        raise IntakeError("TTL must be between 1 and 1440 minutes")
    if report["decision"] != "pass" or not report["scope"]["complete"]:
        raise IntakeError("cannot admit an incomplete or failing scan")
    payload = dict(binding(root, report, threshold), schema_version=1,
                   receipt_id=secrets.token_hex(16), event="snapshot_admitted",
                   issued_at=int(time.time()), expires_at=int(time.time()) + ttl_minutes * 60,
                   observation="static input inspection only", outcome="pass")
    fd = open_store(state_dir, root, create=True)
    temporary = ".receipt-" + secrets.token_hex(16)
    published = False
    try:
        key = key_for(fd, create=True)
        envelope = {"payload": payload, "authentication": {"algorithm": "HMAC-SHA256",
                    "tag": hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()}}
        raw = canonical(envelope) + b"\n"
        out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            if os.write(out, raw) != len(raw):
                raise IntakeError("receipt write failed")
            os.fsync(out)
        finally:
            os.close(out)
        os.replace(temporary, payload["workspace_id"] + ".json", src_dir_fd=fd, dst_dir_fd=fd)
        published = True
        os.fsync(fd)
    except BaseException:
        if published:
            # Best effort on storage failure. A broken filesystem cannot provide
            # an atomic rollback/durability guarantee; operators must restore it.
            os.unlink(payload["workspace_id"] + ".json", dir_fd=fd)
        raise
    finally:
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass
        os.close(fd)
    return envelope


def verify(root, state_dir, report, threshold, now=None):
    fd = open_store(state_dir, root)
    try:
        key = key_for(fd)
        envelope = json_object(read_private(fd, workspace_id(root) + ".json", 32768).decode("utf-8"))
    finally:
        os.close(fd)
    try:
        payload = envelope["payload"]
        authentication = envelope["authentication"]
        if authentication["algorithm"] != "HMAC-SHA256" or not hmac.compare_digest(
                authentication["tag"], hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()):
            raise IntakeError("invalid receipt authentication")
        if payload["schema_version"] != 1 or payload["event"] != "snapshot_admitted" or payload["outcome"] != "pass":
            raise IntakeError("invalid receipt type")
        now = time.time() if now is None else now
        issued, expires = payload["issued_at"], payload["expires_at"]
        if (type(issued) is not int or type(expires) is not int or not issued <= now < expires
                or not 0 < expires - issued <= MAX_TTL_SECONDS):
            raise IntakeError("expired or future-dated receipt")
        if report["decision"] != "pass" or not report["scope"]["complete"]:
            raise IntakeError("workspace no longer passes intake")
        expected = binding(root, report, threshold)
        if any(payload.get(k) != v for k, v in expected.items()):
            raise IntakeError("snapshot, scope, engine, policy, or threshold changed; re-admission required")
        return {"decision": "pass", "receipt_id": payload["receipt_id"], "expires_at": expires,
                "observation": "current input matches admitted snapshot; no runtime observation"}
    except (KeyError, TypeError, ValueError) as exc:
        raise IntakeError(str(exc) if isinstance(exc, IntakeError) else "invalid receipt") from exc
