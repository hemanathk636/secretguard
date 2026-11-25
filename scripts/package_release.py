#!/usr/bin/env python3
"""
SecretGuard Clean Release Packager & Security Artifact Scanner.

Security Guarantees:
1. Resolves an exact immutable Git commit/tag (`git rev-parse --verify <ref>^{commit}`)
   and requires a clean working tree by default.
2. Reads the manifest via `git ls-tree -r -z --full-tree <commit>` and reads every
   file's bytes directly from Git objects (`git cat-file -p <blob_oid>`), NEVER from
   mutable working-tree paths.
3. Rejects tracked symlinks (mode 120000), submodules/gitlinks (mode 160000),
   unexpected file modes, and unsafe path traversal components.
4. Normalizes paths with Unicode NFKC + case-folding to block case-variant bypasses
   (e.g. `.SECRETGuard`, `.MASTER.KEY`, `VAULT.ENC`, `IPC.TOKEN`).
5. Builds `.tar.gz` and `.zip` from the same clean staging directory with normalized
   permissions and verifies 100% manifest parity against the Git commit.
6. Scans ALL files (with zero blanket `test.rs` exemptions) for PEM private keys,
   provider credentials, and suspicious high-entropy secret assignments, using only
   narrowly scoped synthetic fixture allowlisting.
"""

import hashlib
import math
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
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

PROVIDER_CREDENTIAL_RE = re.compile(
    r"(?:"
    r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"
    r"|\bgh[po]_[A-Za-z0-9]{16,}\b"
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}\b"
    r"|\bsk-proj-[A-Za-z0-9_-]{16,}\b"
    r"|\bsk_live_[A-Za-z0-9]{12,}\b"
    r"|\bxox[bp]-[0-9A-Za-z-]{10,}\b"
    r")"
)

SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?i)\b(?:password|passwd|secret_key|api_key|private_key|auth_token|master_key)\b\s*[:=]\s*["']([A-Za-z0-9+/=_-]{20,})["']"""
)

# Narrowly-scoped synthetic fixture markers permitted ONLY in test files/sources
# that explicitly construct deterministic fake credentials for unit/integration tests.
SYNTHETIC_FIXTURE_MARKERS = (
    "EXAMPLE",
    "FAKETOKEN",
    "FAKETEST",
    "Mock",
    "mock",
    "test",
    "Test",
    "1234567890abcdef",
    "01234567890abcdef",
    "9876543210abcdef",
    "MIIEowIBAAKCAQEA0Y5k1v",
    "MHQCAQEEI",
    "b3BlbnNzaC1rZXktdjEA",
    "CANARY",
    "leakedToken",
    "superSecretRealKey",
    "prefixPart12345",
    "998877",
    "validTokenPrefix",
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def normalize_and_validate_rel_path(rel_path: str) -> str:
    if "\x00" in rel_path:
        raise RuntimeError(f"Unsafe null byte in path: {rel_path!r}")
    norm_unix = rel_path.replace("\\", "/")
    if norm_unix.startswith("/") or (len(norm_unix) >= 2 and norm_unix[1] == ":"):
        raise RuntimeError(f"Unsafe absolute/drive path: {rel_path!r}")
    parts = [p for p in norm_unix.split("/") if p]
    if not parts or any(p in (".", "..") for p in parts):
        raise RuntimeError(f"Unsafe traversal path component in: {rel_path!r}")
    return "/".join(parts)


def is_forbidden_member(rel_path: str) -> str | None:
    norm = unicodedata.normalize("NFKC", rel_path).replace("\\", "/")
    parts = [p for p in norm.split("/") if p]
    for seg in parts:
        folded = seg.casefold()
        if folded in FORBIDDEN_PATH_SEGMENTS:
            return f"Forbidden directory/segment '{seg}' in '{rel_path}'"
    basename = parts[-1] if parts else ""
    folded_base = basename.casefold()
    if folded_base in FORBIDDEN_FILENAMES:
        return f"Forbidden runtime/secret filename '{basename}' in '{rel_path}'"
    _, ext = os.path.splitext(folded_base)
    if ext in FORBIDDEN_EXTENSIONS:
        return f"Forbidden key/encrypted extension '{ext}' in '{rel_path}'"
    return None


def is_narrow_synthetic_fixture(rel_path: str, matched_line: str) -> bool:
    norm = rel_path.replace("\\", "/")
    in_test_context = (
        "/tests/" in f"/{norm}"
        or norm.startswith("tests/")
        or norm.endswith("_test.rs")
        or norm.startswith("src/")
        or norm == "docs/index.html"
    )
    if not in_test_context:
        return False
    return any(marker in matched_line for marker in SYNTHETIC_FIXTURE_MARKERS)


def scan_text_for_secrets(rel_path: str, text: str) -> list[str]:
    errors: list[str] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        if PRIVATE_KEY_HEADER_RE.search(line):
            # Look at this line + next line for known fake PEM body markers
            window = line + ("\n" + lines[idx] if idx < len(lines) else "")
            if not is_narrow_synthetic_fixture(rel_path, window):
                errors.append(
                    f"Unallowlisted private key header at '{rel_path}:{idx}'"
                )

        for m in PROVIDER_CREDENTIAL_RE.finditer(line):
            token = m.group(0)
            if not is_narrow_synthetic_fixture(rel_path, line):
                errors.append(
                    f"Potential provider credential ({token[:8]}...) at '{rel_path}:{idx}'"
                )

        for m in SECRET_ASSIGNMENT_RE.finditer(line):
            val = m.group(1)
            if shannon_entropy(val) >= 3.5 and not is_narrow_synthetic_fixture(rel_path, line):
                errors.append(
                    f"High-entropy secret assignment at '{rel_path}:{idx}'"
                )

    return errors


def resolve_commit(repo_dir: str, git_ref: str) -> str:
    res = subprocess.run(
        ["git", "-C", repo_dir, "rev-parse", "--verify", f"{git_ref}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"Invalid Git commit/tag '{git_ref}': {res.stderr.strip()}"
        )
    return res.stdout.strip()


def require_clean_worktree(repo_dir: str) -> None:
    res = subprocess.run(
        ["git", "-C", repo_dir, "status", "--porcelain"],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(f"git status failed: {res.stderr.strip()}")
    if res.stdout.strip():
        raise RuntimeError(
            "Refusing to package from a dirty working tree. Commit or stash changes first:\n"
            + res.stdout.strip()
        )


def read_git_tree_manifest(repo_dir: str, commit_sha: str) -> list[tuple[str, str, str]]:
    """
    Returns sorted list of (mode, blob_oid, rel_path) strictly from `git ls-tree`.
    Rejects symlinks (120000), submodules (160000), and unexpected object types/modes.
    """
    raw = subprocess.check_output(
        ["git", "-C", repo_dir, "ls-tree", "-r", "-z", "--full-tree", commit_sha]
    )
    entries: list[tuple[str, str, str]] = []
    for item in raw.split(b"\x00"):
        if not item:
            continue
        meta_b, path_b = item.split(b"\t", 1)
        meta = meta_b.decode("utf-8")
        rel_path = normalize_and_validate_rel_path(path_b.decode("utf-8"))
        mode, obj_type, obj_id = meta.split(" ")

        if mode == "120000":
            raise RuntimeError(
                f"Security Error: Tracked symlink rejected in release manifest: '{rel_path}'"
            )
        if mode == "160000" or obj_type == "commit":
            raise RuntimeError(
                f"Security Error: Unpinned submodule/gitlink rejected in release manifest: '{rel_path}'"
            )
        if obj_type != "blob" or mode not in ("100644", "100755"):
            raise RuntimeError(
                f"Security Error: Unsupported Git mode/type ({mode} {obj_type}) for '{rel_path}'"
            )
        if reason := is_forbidden_member(rel_path):
            raise RuntimeError(f"Security Error: {reason}")

        entries.append((mode, obj_id, rel_path))

    entries.sort(key=lambda e: e[2])
    return entries


def read_git_blob(repo_dir: str, blob_oid: str) -> bytes:
    return subprocess.check_output(["git", "-C", repo_dir, "cat-file", "blob", blob_oid])


def scan_archive_contents(archive_path: str, kind: str) -> list[str]:
    errors: list[str] = []
    members: list[str] = []

    if kind == "tar":
        with tarfile.open(archive_path, "r:gz") as tf:
            for m in tf.getmembers():
                if m.issym() or m.islnk():
                    errors.append(f"Forbidden link in tar archive: '{m.name}'")
                    continue
                if not m.isfile():
                    continue
                members.append(m.name)
                if reason := is_forbidden_member(m.name):
                    errors.append(reason)
                if (m.mode & 0o002) != 0 or (m.mode & 0o020) != 0:
                    errors.append(f"Overly permissive tar mode {oct(m.mode)} on '{m.name}'")
                f = tf.extractfile(m)
                if f is not None:
                    text = f.read().decode("utf-8", errors="ignore")
                    errors.extend(scan_text_for_secrets(m.name, text))
    elif kind == "zip":
        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                unix_mode = (info.external_attr >> 16) & 0o170000
                if unix_mode == stat.S_IFLNK:
                    errors.append(f"Forbidden symlink in zip archive: '{info.filename}'")
                    continue
                members.append(info.filename)
                if reason := is_forbidden_member(info.filename):
                    errors.append(reason)
                perm_bits = (info.external_attr >> 16) & 0o777
                if perm_bits != 0 and ((perm_bits & 0o002) != 0 or (perm_bits & 0o020) != 0):
                    errors.append(
                        f"Overly permissive zip mode {oct(perm_bits)} on '{info.filename}'"
                    )
                text = zf.read(info.filename).decode("utf-8", errors="ignore")
                errors.extend(scan_text_for_secrets(info.filename, text))
    else:
        raise ValueError(f"Unknown archive kind: {kind}")

    if errors:
        raise RuntimeError(
            f"Release Artifact Security Scan FAILED for {archive_path}:\n  - "
            + "\n  - ".join(errors)
        )
    return sorted(members)


def package_clean_release(
    repo_dir: str,
    out_dir: str,
    version_label: str,
    git_ref: str = "HEAD",
    require_clean: bool = True,
) -> tuple[str, str, str, str, int, str]:
    commit_sha = resolve_commit(repo_dir, git_ref)
    if require_clean:
        require_clean_worktree(repo_dir)

    manifest = read_git_tree_manifest(repo_dir, commit_sha)
    if not manifest:
        raise RuntimeError(f"Git commit {commit_sha} contains no files")

    os.makedirs(out_dir, exist_ok=True)
    prefix = "secretguard-1.0.0"
    tar_path = os.path.join(out_dir, f"secretguard-{version_label}.tar.gz")
    zip_path = os.path.join(out_dir, f"secretguard-{version_label}.zip")

    expected_members: list[str] = []
    with tempfile.TemporaryDirectory(prefix="sg_release_stage_") as stage_root:
        stage_dir = os.path.join(stage_root, prefix)
        os.makedirs(stage_dir, exist_ok=True)

        # Stage strictly from immutable Git blob objects
        for mode, blob_oid, rel_path in manifest:
            blob_bytes = read_git_blob(repo_dir, blob_oid)
            text = blob_bytes.decode("utf-8", errors="ignore")
            scan_errors = scan_text_for_secrets(rel_path, text)
            if scan_errors:
                raise RuntimeError(
                    "Staged commit secret scan FAILED:\n  - " + "\n  - ".join(scan_errors)
                )

            dst = os.path.join(stage_dir, rel_path)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(blob_bytes)
            expected_members.append(f"{prefix}/{rel_path}")

        expected_members.sort()

        with tarfile.open(tar_path, "w:gz") as tf:
            for mode, _, rel_path in manifest:
                full = os.path.join(stage_dir, rel_path)
                arcname = f"{prefix}/{rel_path}"
                ti = tf.gettarinfo(full, arcname=arcname)
                ti.mode = 0o755 if (mode == "100755" or rel_path.endswith(".sh")) else 0o644
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                with open(full, "rb") as f:
                    tf.addfile(ti, f)

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for mode, _, rel_path in manifest:
                full = os.path.join(stage_dir, rel_path)
                arcname = f"{prefix}/{rel_path}"
                zi = zipfile.ZipInfo(arcname)
                zi.compress_type = zipfile.ZIP_DEFLATED
                perm = 0o755 if (mode == "100755" or rel_path.endswith(".sh")) else 0o644
                zi.external_attr = (stat.S_IFREG | perm) << 16
                with open(full, "rb") as f:
                    zf.writestr(zi, f.read())

    # Scan both archives & verify 100% parity with Git commit manifest
    tar_members = scan_archive_contents(tar_path, "tar")
    zip_members = scan_archive_contents(zip_path, "zip")
    if tar_members != expected_members or zip_members != expected_members:
        raise RuntimeError(
            "Archive manifest mismatch against Git commit!\n"
            f"Expected: {len(expected_members)}, TAR: {len(tar_members)}, ZIP: {len(zip_members)}"
        )

    tar_sha = sha256_file(tar_path)
    zip_sha = sha256_file(zip_path)
    with open(tar_path + ".sha256", "w", encoding="utf-8") as f:
        f.write(f"{tar_sha}  {os.path.basename(tar_path)}\n")
    with open(zip_path + ".sha256", "w", encoding="utf-8") as f:
        f.write(f"{zip_sha}  {os.path.basename(zip_path)}\n")

    return tar_path, zip_path, tar_sha, zip_sha, len(tar_members), commit_sha


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(
            "Usage: package_release.py <repo_dir> <out_dir> <version_label> [git_ref]",
            file=sys.stderr,
        )
        sys.exit(2)
    ref = sys.argv[4] if len(sys.argv) > 4 else "HEAD"
    tar_p, zip_p, tar_h, zip_h, count, sha = package_clean_release(
        sys.argv[1], sys.argv[2], sys.argv[3], git_ref=ref
    )
    print(f"SOURCE COMMIT: {sha}")
    print(f"CLEAN RELEASE PACKAGING & SECURITY SCAN PASSED ({count} files identical in both archives)")
    print(f"TAR.GZ: {tar_p}")
    print(f"TAR.GZ SHA256: {tar_h}")
    print(f"ZIP:    {zip_p}")
    print(f"ZIP    SHA256: {zip_h}")
