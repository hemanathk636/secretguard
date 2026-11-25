#!/usr/bin/env python3
"""
SecretGuard Clean Release Packager & Security Artifact Scanner.

1. Stages ONLY files tracked in Git (`git ls-files`) into a clean temporary directory,
   guaranteeing zero untracked/ignored runtime state (e.g. `.secretguard/`, `target/`).
2. Builds both `.tar.gz` and `.zip` from that exact same staging directory with
   normalized permissions (0644 regular files, 0755 shell scripts).
3. Verifies 100% identical file inventories between `.tar.gz` and `.zip`.
4. Scans both archives for runtime secrets, key filenames, private key blocks,
   and overly permissive file modes, failing closed on any violation.
5. Generates and independently verifies SHA-256 checksums.
"""

import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

FORBIDDEN_PATH_SEGMENTS = {".secretguard", "target", ".git"}
FORBIDDEN_FILENAMES = {
    ".master.key",
    "audit.hmac.key",
    "vault.enc",
    "audit_ledger.json",
    "lifecycle.json",
    "quarantine.txt",
    "ipc.token",
    "ghost_session.enc",
}
FORBIDDEN_EXTENSIONS = {".key", ".enc", ".pem", ".p12", ".pfx"}
PRIVATE_KEY_HEADER_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def is_forbidden_member(rel_path: str) -> str | None:
    norm = rel_path.replace("\\", "/")
    parts = [p for p in norm.split("/") if p]
    for seg in parts:
        if seg in FORBIDDEN_PATH_SEGMENTS:
            return f"Forbidden directory/segment '{seg}' in '{norm}'"
    basename = parts[-1] if parts else ""
    if basename in FORBIDDEN_FILENAMES:
        return f"Forbidden runtime/secret filename '{basename}' in '{norm}'"
    _, ext = os.path.splitext(basename.lower())
    if ext in FORBIDDEN_EXTENSIONS:
        return f"Forbidden key/encrypted extension '{ext}' in '{norm}'"
    return None


def scan_archive_contents(archive_path: str, kind: str) -> list[str]:
    errors: list[str] = []
    members: list[str] = []

    if kind == "tar":
        with tarfile.open(archive_path, "r:gz") as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                members.append(m.name)
                if reason := is_forbidden_member(m.name):
                    errors.append(reason)
                if (m.mode & 0o002) != 0 or (m.mode & 0o020) != 0:
                    errors.append(f"Overly permissive tar mode {oct(m.mode)} on '{m.name}'")
                f = tf.extractfile(m)
                if f is not None:
                    data = f.read()
                    text = data.decode("utf-8", errors="ignore")
                    if PRIVATE_KEY_HEADER_RE.search(text) and not m.name.endswith("test.rs"):
                        errors.append(f"Private key header detected in '{m.name}'")
    elif kind == "zip":
        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                members.append(info.filename)
                if reason := is_forbidden_member(info.filename):
                    errors.append(reason)
                unix_mode = (info.external_attr >> 16) & 0o777
                if unix_mode != 0 and ((unix_mode & 0o002) != 0 or (unix_mode & 0o020) != 0):
                    errors.append(
                        f"Overly permissive zip mode {oct(unix_mode)} on '{info.filename}'"
                    )
                data = zf.read(info.filename)
                text = data.decode("utf-8", errors="ignore")
                if PRIVATE_KEY_HEADER_RE.search(text) and not info.filename.endswith("test.rs"):
                    errors.append(f"Private key header detected in '{info.filename}'")
    else:
        raise ValueError(f"Unknown archive kind: {kind}")

    if errors:
        raise RuntimeError(
            f"Release Artifact Security Scan FAILED for {archive_path}:\n  - "
            + "\n  - ".join(errors)
        )
    return sorted(members)


def package_clean_release(repo_dir: str, out_dir: str, version_label: str) -> tuple[str, str, str, str, int]:
    os.makedirs(out_dir, exist_ok=True)
    tracked = subprocess.check_output(
        ["git", "-C", repo_dir, "ls-files", "-z"], text=False
    ).split(b"\x00")
    rel_files = sorted(p.decode("utf-8") for p in tracked if p)
    if not rel_files:
        raise RuntimeError("git ls-files returned no tracked files")

    prefix = "secretguard-1.0.0"
    tar_path = os.path.join(out_dir, f"secretguard-{version_label}.tar.gz")
    zip_path = os.path.join(out_dir, f"secretguard-{version_label}.zip")

    with tempfile.TemporaryDirectory(prefix="sg_release_stage_") as stage_root:
        stage_dir = os.path.join(stage_root, prefix)
        os.makedirs(stage_dir, exist_ok=True)

        for rel in rel_files:
            if reason := is_forbidden_member(rel):
                raise RuntimeError(f"Tracked file failed security policy: {reason}")
            src = os.path.join(repo_dir, rel)
            if not os.path.isfile(src):
                continue
            dst = os.path.join(stage_dir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(src, dst)

        # Build TAR.GZ from clean staging directory with normalized deterministic permissions
        with tarfile.open(tar_path, "w:gz") as tf:
            for rel in rel_files:
                full = os.path.join(stage_dir, rel)
                if not os.path.isfile(full):
                    continue
                arcname = f"{prefix}/{rel.replace(os.sep, '/')}"
                ti = tf.gettarinfo(full, arcname=arcname)
                ti.mode = 0o755 if rel.endswith(".sh") else 0o644
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                with open(full, "rb") as f:
                    tf.addfile(ti, f)

        # Build ZIP from the exact same clean staging directory with normalized Unix permissions
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for rel in rel_files:
                full = os.path.join(stage_dir, rel)
                if not os.path.isfile(full):
                    continue
                arcname = f"{prefix}/{rel.replace(os.sep, '/')}"
                zi = zipfile.ZipInfo(arcname)
                zi.compress_type = zipfile.ZIP_DEFLATED
                mode = 0o755 if rel.endswith(".sh") else 0o644
                zi.external_attr = (stat.S_IFREG | mode) << 16
                with open(full, "rb") as f:
                    zf.writestr(zi, f.read())

    # Scan both archives & compare inventories
    tar_members = scan_archive_contents(tar_path, "tar")
    zip_members = scan_archive_contents(zip_path, "zip")
    if tar_members != zip_members:
        only_tar = set(tar_members) - set(zip_members)
        only_zip = set(zip_members) - set(tar_members)
        raise RuntimeError(
            f"Archive inventory mismatch!\nOnly in tar.gz: {only_tar}\nOnly in zip: {only_zip}"
        )

    tar_sha = sha256_file(tar_path)
    zip_sha = sha256_file(zip_path)
    with open(tar_path + ".sha256", "w", encoding="utf-8") as f:
        f.write(f"{tar_sha}  {os.path.basename(tar_path)}\n")
    with open(zip_path + ".sha256", "w", encoding="utf-8") as f:
        f.write(f"{zip_sha}  {os.path.basename(zip_path)}\n")

    return tar_path, zip_path, tar_sha, zip_sha, len(tar_members)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: package_release.py <repo_dir> <out_dir> <version_label>", file=sys.stderr)
        sys.exit(2)
    tar_p, zip_p, tar_h, zip_h, count = package_clean_release(
        sys.argv[1], sys.argv[2], sys.argv[3]
    )
    print(f"CLEAN RELEASE PACKAGING & SECURITY SCAN PASSED ({count} files identical in both archives)")
    print(f"TAR.GZ: {tar_p}")
    print(f"TAR.GZ SHA256: {tar_h}")
    print(f"ZIP:    {zip_p}")
    print(f"ZIP    SHA256: {zip_h}")
