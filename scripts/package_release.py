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
PRIVATE_KEY_END_RE = re.compile(
    r"-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
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

# Exact (repo_relative_path, sha256(exact_token)) allowlist for known synthetic test/demo fixtures.
# Never uses substring matching, line-comment matching, or blanket file-path exemptions.
EXACT_CREDENTIAL_FIXTURE_HASHES: set[tuple[str, str]] = {
    ("docs/index.html", "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3"),
    ("docs/index.html", "71964fc921dd311937749e35ce5aeba072feecf9c794bf927ce0a5eb0ee6b8a1"),
    ("docs/index.html", "8841c2397d5af2017f16d8f94da2d34ce7e25b4992bbf8dadc4fef13b06e410e"),
    ("src/immune.rs", "144ab26df98d362fb7f47d20d13a64ad65d8c3962c06e37eaf449ac30be8a196"),
    ("src/lifecycle.rs", "46e973cfd54c145a2a5d33033c6c87c3e9fa4b25aa5eb33c6c9d3d5169d1569b"),
    ("tests/adversarial_audit_test.rs", "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3"),
    ("tests/adversarial_audit_test.rs", "1ca9aa038885384fc66d0f2fbe0473f39bf98df1c18fd874f0fd62fe7d52d5e3"),
    ("tests/adversarial_audit_test.rs", "1ff82f4f862e802a39f72009b1d156d65890d89c6fd15a8d6d05a1710699b09a"),
    ("tests/adversarial_audit_test.rs", "23af0ce2f924b6c354320ecbd20dfbdfaba3706a67d41c431c6b4c02b3dd23c9"),
    ("tests/adversarial_audit_test.rs", "41054f4f064208786f73a55905cd390afa9d009ff7d0c3475b1db198ba4befc1"),
    ("tests/adversarial_audit_test.rs", "7d7e24639d7fcdaf2c16838a49d40ba982da3a9d26b52212816602e0388db11c"),
    ("tests/adversarial_audit_test.rs", "8841c2397d5af2017f16d8f94da2d34ce7e25b4992bbf8dadc4fef13b06e410e"),
    ("tests/broker_test.rs", "148be1d13bfa307cf73859e12da79310ff3acd5d5d7c41a6670735b480216b3d"),
    ("tests/clipboard_test.rs", "a0b83eae65546e7d171351576ca8a9498740ab2e79d21446cc258e5dcba8e165"),
    ("tests/compliance_test.rs", "a0b83eae65546e7d171351576ca8a9498740ab2e79d21446cc258e5dcba8e165"),
    ("tests/dashboard_test.rs", "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3"),
    ("tests/docker_test.rs", "a0b83eae65546e7d171351576ca8a9498740ab2e79d21446cc258e5dcba8e165"),
    ("tests/encoding_test.rs", "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3"),
    ("tests/encoding_test.rs", "7d7e24639d7fcdaf2c16838a49d40ba982da3a9d26b52212816602e0388db11c"),
    ("tests/futuristic_test.rs", "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3"),
    ("tests/futuristic_test.rs", "3281a25da42d21f2a0d92547c054162ae132174eac0a2dfbbf2b133e2bd60e7a"),
    ("tests/futuristic_test.rs", "4e32205ec6992c06217b43a5b6bad1ca84cb576123a1b2341d4ec74da4ff6063"),
    ("tests/mcp_test.rs", "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3"),
    ("tests/mcp_test.rs", "53bcf3371681c53a6aa07536d9432ea654124f5de8188adbff1112d22774accb"),
    ("tests/mcp_test.rs", "8841c2397d5af2017f16d8f94da2d34ce7e25b4992bbf8dadc4fef13b06e410e"),
    ("tests/mcp_test.rs", "d83e21c219f33ebe0fba99f8230b85b9c8956415da6933ad08001894b3621930"),
    ("tests/panic_test.rs", "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3"),
    ("tests/panic_test.rs", "8841c2397d5af2017f16d8f94da2d34ce7e25b4992bbf8dadc4fef13b06e410e"),
    ("tests/panic_test.rs", "a0b83eae65546e7d171351576ca8a9498740ab2e79d21446cc258e5dcba8e165"),
    ("tests/security_guarantees_test.rs", "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3"),
    ("tests/security_guarantees_test.rs", "968fc7411df335652245d3fb4a9756f7b0ee295923c2134aae608eadc903ecd0"),
    ("tests/shield_test.rs", "a0b83eae65546e7d171351576ca8a9498740ab2e79d21446cc258e5dcba8e165"),
    ("tests/swapper_test.rs", "20a394da6f81d1c8d316a4693e959db145c402bcd347d3035411f9a6e06b4564"),
    ("tests/vault_test.rs", "4a327996a82ee1c79d157c482d37778626251aea049570913e5379d69c0a7932"),
    ("tests/vault_test.rs", "8841c2397d5af2017f16d8f94da2d34ce7e25b4992bbf8dadc4fef13b06e410e"),
    ("tests/vault_test.rs", "92d60f0007d5938ffa23a6419ae8246af59939b32aafdb7fc0428332ee02ac8c"),
    ("tests/vault_test.rs", "99c26238fb4afef8c3fbcf19ca8b0ced9f23de87a8704f389ab688d1dcfbc0ff"),
    ("tests/vault_test.rs", "f23831a9dae8f307e06b33fbeaf4284fd6a3b6d32937e68d6de5ac925af41460"),
    ("tests/verifier_test.rs", "563eb2eb728d2162afedaea6fb83787c145363f72886f19b502d9ade3adcb06c"),
    ("tests/verifier_test.rs", "c5304f6f29f7834cf10b021827f71e81312321450333af20f1d3464719903c32"),
    ("tests/verifier_test.rs", "dda2430bd4fd6e198aa6303d5a882595eb18359c1cc385450b9a11590173f68a"),
}

# Exact (repo_relative_path, sha256(full_pem_block)) allowlist for synthetic PEM
# stream-sanitizer test blocks in `tests/vault_test.rs` (never real private keys).
EXACT_PEM_BLOCK_FIXTURE_HASHES: set[tuple[str, str]] = {
    ("tests/vault_test.rs", "00832ad52add789b11e387a8606ba5c76ef950fec25e0ebe4d3e61d64f2a2d0a"),
    ("tests/vault_test.rs", "1a2f5f04dc97d7145cc097dd96037181f9bb1bd752a3e019fea04d54c85b56e8"),
    ("tests/vault_test.rs", "2b5cdb0725696de5633778ac568f7a45d5c05342c32a80cef707ca7a6b19104a"),
    ("tests/vault_test.rs", "350f4e23d888ab2fafc040c10360ee6e5d14ed0cdb431f8943a5c67ed353b73a"),
    ("tests/vault_test.rs", "3b2e59cacdb6faaf60367ab084b8e1ec923d6d35dcbd4490146c843a56da6385"),
    ("tests/vault_test.rs", "429d7179e24153dc470ec5c3a84f24710a25871c039138bd10f47f11a358e136"),
    ("tests/vault_test.rs", "4f20afe58598a36d2a34bb228ffe650a986fd5df8a54e050fed20fbf8ff83f4b"),
    ("tests/vault_test.rs", "6a4e211025986c133351f139036025b573e94e2f3d7d9b2070ff72cbddbd0e32"),
    ("tests/vault_test.rs", "772d21645cff08041014e9f1ce38e88e8013775e1af7b3a8ddc3e30fa7c70dd4"),
    ("tests/vault_test.rs", "8396d7e5dc9a8e3292764e9ecb5f6983721b59d4ad3197aaf3c1dd4a379f01ac"),
    ("tests/vault_test.rs", "89c97a6a31bc2e5963085389b2aa8edca06b37fc90ad4e8eb65ea8e1b5686ce0"),
    ("tests/vault_test.rs", "8be6d7d3ae5e47365aa9e3b1f07a04335e2f6bada13a09b4c6ef84a7fa6551da"),
    ("tests/vault_test.rs", "8d68e13344444b131f8cf10680eff89e166661e09b64cccc4c03e1b406fc0eb4"),
    ("tests/vault_test.rs", "acd22a86ddd1de4fbd4229b311b97600fdb78debf990e33cdb053b4e635e1dd6"),
    ("tests/vault_test.rs", "cb1a98c8b58a5b9a385178f28c15d29de7c8ecc6341672594fad8e4413e6722d"),
    ("tests/vault_test.rs", "cf45fec9cf2fd376d5f60bf2c83cd8966352202593d928e3326d0ef35d1330f2"),
    ("tests/vault_test.rs", "d708aaa7aed6c96c24ee03571d9f8943526494bef62cafc7416c312a7de14301"),
    ("tests/vault_test.rs", "d89c8ff38668baa12b0e0c30b5f6719e49e934ff3a9b7735b906ff9629c45837"),
    ("tests/vault_test.rs", "ddd3a5b6f707da1c31e8a20a1e02cbc4c47f1b1a22b9e24380df8470d7926eaa"),
    ("tests/vault_test.rs", "fc598ebf2053df1b578b837b8cfcbaaa6cd5595a5ce65b47efb29130e51148c6"),
}


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


def _strip_archive_prefix(rel_path: str) -> str:
    norm = rel_path.replace("\\", "/")
    if norm.startswith("secretguard-1.0.0/"):
        return norm[len("secretguard-1.0.0/") :]
    return norm


def is_exact_credential_fixture(rel_path: str, exact_token: str) -> bool:
    repo_rel = _strip_archive_prefix(rel_path)
    token_hash = hashlib.sha256(exact_token.encode("utf-8")).hexdigest()
    return (repo_rel, token_hash) in EXACT_CREDENTIAL_FIXTURE_HASHES


def extract_pem_block(lines: list[str], start_idx: int) -> str:
    block: list[str] = []
    for j in range(start_idx, min(start_idx + 25, len(lines))):
        s = lines[j].strip()
        block.append(s)
        if j > start_idx and PRIVATE_KEY_END_RE.search(s):
            break
        if j > start_idx and (s == "" or s.endswith(";") or s == "];"):
            break
        if j == start_idx and PRIVATE_KEY_END_RE.search(s):
            break
        if j == start_idx and s.startswith("!") and ".contains(" in s:
            break
        if j == start_idx and s.startswith("//"):
            break
        if j == start_idx and s.endswith("\","):
            break
    return "\n".join(block)


def is_exact_pem_block_fixture(rel_path: str, lines: list[str], start_idx: int) -> bool:
    repo_rel = _strip_archive_prefix(rel_path)
    full_block = extract_pem_block(lines, start_idx)
    block_hash = hashlib.sha256(full_block.encode("utf-8")).hexdigest()
    return (repo_rel, block_hash) in EXACT_PEM_BLOCK_FIXTURE_HASHES


def scan_text_for_secrets(rel_path: str, text: str) -> list[str]:
    errors: list[str] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        if PRIVATE_KEY_HEADER_RE.search(line):
            if not is_exact_pem_block_fixture(rel_path, lines, idx - 1):
                errors.append(
                    f"Unallowlisted private key block at '{rel_path}:{idx}'"
                )

        for m in PROVIDER_CREDENTIAL_RE.finditer(line):
            token = m.group(0)
            if not is_exact_credential_fixture(rel_path, token):
                errors.append(
                    f"Potential provider credential ({token[:8]}...) at '{rel_path}:{idx}'"
                )

        for m in SECRET_ASSIGNMENT_RE.finditer(line):
            val = m.group(1)
            if shannon_entropy(val) >= 3.5:
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
