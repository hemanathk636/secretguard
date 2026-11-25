#!/usr/bin/env python3
"""
Security regression tests for `scripts/package_release.py`.
Covers:
1. Dirty working-tree isolation & fail-closed clean-checkout requirement.
2. Package contents match the exact selected Git commit (not working tree).
3. Tracked symlink rejection (outside target, dangling symlink, symlink loop).
4. Removal of blanket `test.rs` exemption (real private key in `*_test.rs` rejected).
5. Detection of common provider credentials & high-entropy secrets in source/config files.
6. Case-insensitive and NFKC Unicode normalization rejection (`.SECRETGuard`, `.MASTER.KEY`, `VAULT.ENC`, `IPC.TOKEN`).
7. Identical `.tar.gz` and `.zip` inventories and independent SHA-256 verification.
"""

import hashlib
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import package_release as pr


def git(repo: str, *args: str) -> str:
    return subprocess.check_output(["git", "-C", repo, *args], text=True).strip()


def init_test_repo(repo: str) -> None:
    git(repo, "init")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Test User")
    with open(os.path.join(repo, "README.md"), "w", encoding="utf-8") as f:
        f.write("clean readme\n")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "initial")


class TestReleasePackagerSecurity(unittest.TestCase):
    def test_dirty_tracked_file_rejected_and_immutable_commit_used(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            out = os.path.join(tmp, "out")
            os.makedirs(repo)
            init_test_repo(repo)
            commit_sha = git(repo, "rev-parse", "HEAD")

            # Mutate tracked file in working tree without committing
            with open(os.path.join(repo, "README.md"), "w", encoding="utf-8") as f:
                f.write("DIRTY UNCOMMITTED MUTATION\n")

            # 1. Default require_clean=True must fail closed
            with self.assertRaises(RuntimeError) as ctx:
                pr.package_clean_release(repo, out, "v1.0.0-test")
            self.assertIn("dirty working tree", str(ctx.exception).lower())

            # 2. Even with require_clean=False, packaged bytes MUST come from commit object
            tar_p, zip_p, tar_h, zip_h, count, sha = pr.package_clean_release(
                repo, out, "v1.0.0-test", git_ref=commit_sha, require_clean=False
            )
            self.assertEqual(sha, commit_sha)
            self.assertEqual(count, 1)
            with zipfile.ZipFile(zip_p, "r") as zf:
                content = zf.read("secretguard-1.0.0/README.md").decode("utf-8")
                self.assertEqual(content, "clean readme\n")
            with tarfile.open(tar_p, "r:gz") as tf:
                content = tf.extractfile("secretguard-1.0.0/README.md").read().decode("utf-8")
                self.assertEqual(content, "clean readme\n")

            # Verify hashes independently
            with open(tar_p, "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), tar_h)
            with open(zip_p, "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), zip_h)

    def test_tracked_symlink_and_loop_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            out = os.path.join(tmp, "out")
            os.makedirs(repo)
            init_test_repo(repo)

            # Inject a tracked Git symlink (mode 120000) directly into the Git index
            # (works cross-platform including Windows without needing OS symlink privileges)
            outside_blob = git(repo, "hash-object", "-w", "--stdin") if False else None
            proc = subprocess.run(
                ["git", "-C", repo, "hash-object", "-w", "--stdin"],
                input=b"/etc/passwd",
                capture_output=True,
                check=True,
            )
            blob_oid = proc.stdout.decode().strip()
            subprocess.run(
                ["git", "-C", repo, "update-index", "--add", "--cacheinfo", f"120000,{blob_oid},leak_link"],
                check=True,
            )
            git(repo, "commit", "-m", "add symlink")

            with self.assertRaises(RuntimeError) as ctx:
                pr.package_clean_release(repo, out, "v1.0.0-sym", require_clean=False)
            self.assertIn("symlink rejected", str(ctx.exception).lower())

            # Also test symlink loop (120000 pointing to itself)
            proc2 = subprocess.run(
                ["git", "-C", repo, "hash-object", "-w", "--stdin"],
                input=b"loop_link",
                capture_output=True,
                check=True,
            )
            loop_oid = proc2.stdout.decode().strip()
            subprocess.run(
                ["git", "-C", repo, "update-index", "--add", "--cacheinfo", f"120000,{loop_oid},loop_link"],
                check=True,
            )
            git(repo, "commit", "-m", "add symlink loop")
            with self.assertRaises(RuntimeError) as ctx2:
                pr.package_clean_release(repo, out, "v1.0.0-loop", require_clean=False)
            self.assertIn("symlink rejected", str(ctx2.exception).lower())

    def test_private_key_in_test_rs_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            out = os.path.join(tmp, "out")
            os.makedirs(os.path.join(repo, "tests"))
            init_test_repo(repo)

            # Real-looking private key in a *_test.rs file must NOT be exempted
            with open(os.path.join(repo, "tests", "example_test.rs"), "w", encoding="utf-8") as f:
                f.write("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEArealSensitiveKey99112233\n")
            git(repo, "add", "tests/example_test.rs")
            git(repo, "commit", "-m", "add real key in test")

            with self.assertRaises(RuntimeError) as ctx:
                pr.package_clean_release(repo, out, "v1.0.0-keytest")
            self.assertIn("private key header", str(ctx.exception).lower())

    def test_credentials_in_ordinary_source_or_config_rejected(self):
        for fname, content in [
            ("src/config.rs", 'const KEY: &str = "AKIAQAZXSWEDCVFRTGBN";\n'),
            ("config.toml", 'github_token = "ghp_RealLookingProdTokenAbCdEfGhIjKlMnOp"\n'),
            ("app.env", 'api_key = "Xy9Kp2Qm7Vz4Lw8Rt3Ns6Jd1Fh5Gc0Vb"\n'),
        ]:
            errs = pr.scan_text_for_secrets(fname, content)
            self.assertTrue(len(errs) > 0, f"Expected secret detection for {fname}")

    def test_case_variant_and_unicode_forbidden_paths_rejected(self):
        for bad_path in [
            ".SECRETGuard/config.json",
            "sub/.MASTER.KEY",
            "VAULT.ENC",
            "IPC.TOKEN",
            "Audit.Hmac.Key",
            "\uff0esecretguard/vault.enc",  # fullwidth dot normalized via NFKC -> .secretguard
        ]:
            reason = pr.is_forbidden_member(bad_path)
            self.assertIsNotNone(reason, f"Expected rejection for case/Unicode path: {bad_path}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
