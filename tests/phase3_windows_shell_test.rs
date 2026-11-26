mod common;

use secretguard::identity::{
    classify_requester_with_hash, IdentityContext, RequesterType, TrustTier,
};
use secretguard::vault::{create_secure_file_exclusive, validate_secure_path};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn workspace_tmp_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("sg_phase3_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[cfg(windows)]
#[test]
fn test_windows_acl_restricted_and_rejects_everyone_and_junctions() {
    let dir = workspace_tmp_dir("win_acl");
    let secret_file = dir.join("vault_secret.enc");

    let mut f = create_secure_file_exclusive(&secret_file, 0o600)
        .expect("create_secure_file_exclusive should succeed and apply protected DACL");
    f.write_all(b"encrypted_payload").unwrap();
    f.sync_all().unwrap();
    drop(f);

    // Must pass strict target validation
    validate_secure_path(&secret_file, true).expect("Protected DACL file must validate cleanly");

    // Verify via icacls that Everyone / Users are NOT granted access
    let icacls_out = Command::new("icacls")
        .arg(&secret_file)
        .output()
        .expect("icacls should run on Windows");
    let acl_text = String::from_utf8_lossy(&icacls_out.stdout);
    assert!(
        !acl_text.contains("Everyone"),
        "Everyone must not appear in restricted DACL: {}",
        acl_text
    );
    assert!(
        !acl_text.contains("BUILTIN\\Users"),
        "BUILTIN\\Users must not appear in restricted DACL: {}",
        acl_text
    );

    // Verify win32::inspect_dacl_and_owner strictly rejects a real Win32 ACL containing Everyone (WinWorldSid) and NULL DACLs
    {
        use secretguard::vault::win32;
        use std::ffi::c_void;

        #[link(name = "advapi32")]
        extern "system" {
            fn GetCurrentProcess() -> *mut c_void;
            fn OpenProcessToken(
                ProcessHandle: *mut c_void,
                DesiredAccess: u32,
                TokenHandle: *mut *mut c_void,
            ) -> i32;
            fn GetTokenInformation(
                TokenHandle: *mut c_void,
                TokenInformationClass: i32,
                TokenInformation: *mut c_void,
                TokenInformationLength: u32,
                ReturnLength: *mut u32,
            ) -> i32;
            fn CloseHandle(hObject: *mut c_void) -> i32;
            fn CreateWellKnownSid(
                WellKnownSidType: i32,
                DomainSid: *const c_void,
                pSid: *mut c_void,
                cbSid: *mut u32,
            ) -> i32;
            fn GetLengthSid(pSid: *const c_void) -> u32;
            fn InitializeAcl(pAcl: *mut c_void, nAclLength: u32, dwAclRevision: u32) -> i32;
            fn AddAccessAllowedAce(
                pAcl: *mut c_void,
                dwAceRevision: u32,
                AccessMask: u32,
                pSid: *const c_void,
            ) -> i32;
        }

        let mut h_token: *mut c_void = std::ptr::null_mut();
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), win32::TOKEN_QUERY, &mut h_token) },
            0
        );
        let mut len = 0u32;
        unsafe {
            GetTokenInformation(h_token, win32::TokenUser, std::ptr::null_mut(), 0, &mut len);
        }
        let mut user_buf = vec![0u8; len as usize];
        assert_ne!(
            unsafe {
                GetTokenInformation(
                    h_token,
                    win32::TokenUser,
                    user_buf.as_mut_ptr() as *mut c_void,
                    len,
                    &mut len,
                )
            },
            0
        );
        unsafe { CloseHandle(h_token) };
        let owner_sid = unsafe { (*(user_buf.as_ptr() as *const win32::TOKEN_USER)).User.Sid };

        // NULL DACL must be rejected
        assert!(
            win32::inspect_dacl_and_owner(owner_sid, std::ptr::null(), &secret_file, true).is_err()
        );

        // Real Win32 ACL granting Everyone (WinWorldSid) must be rejected
        let mut world_sid = [0u8; 68];
        let mut world_len = world_sid.len() as u32;
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    win32::WinWorldSid,
                    std::ptr::null(),
                    world_sid.as_mut_ptr() as *mut c_void,
                    &mut world_len,
                )
            },
            0
        );
        let acl_len =
            ((8 + 8 + unsafe { GetLengthSid(world_sid.as_ptr() as *const c_void) }) + 3) & !3;
        let mut acl_buf = vec![0u8; acl_len as usize];
        assert_ne!(
            unsafe { InitializeAcl(acl_buf.as_mut_ptr() as *mut c_void, acl_len, 2) },
            0
        );
        assert_ne!(
            unsafe {
                AddAccessAllowedAce(
                    acl_buf.as_mut_ptr() as *mut c_void,
                    2,
                    win32::GENERIC_READ,
                    world_sid.as_ptr() as *const c_void,
                )
            },
            0
        );
        assert!(
            win32::inspect_dacl_and_owner(
                owner_sid,
                acl_buf.as_ptr() as *const c_void,
                &secret_file,
                true
            )
            .is_err(),
            "Permissive Everyone ACE must be rejected"
        );
    }

    // Test Windows NTFS junction (reparse point) rejection
    let target_sub = dir.join("real_sub");
    fs::create_dir_all(&target_sub).unwrap();
    let junction = dir.join("junction_sub");
    let mklink = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&target_sub)
        .output()
        .expect("cmd mklink should run");
    if mklink.status.success() {
        let j_file = junction.join("test.enc");
        assert!(
            validate_secure_path(&j_file, true).is_err(),
            "Reparse point junction must be rejected"
        );
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_powershell_hook_no_length_bypass_and_fail_closed() {
    let bin = env!("CARGO_BIN_EXE_secretguard");
    let out = Command::new(bin)
        .args(["hook", "pwsh"])
        .output()
        .expect("hook pwsh should run");
    assert!(out.status.success());
    let script = String::from_utf8_lossy(&out.stdout);

    assert!(
        !script.contains("Length -lt 15"),
        "PowerShell hook must not bypass commands shorter than 15 chars"
    );
    assert!(
        script.contains("return $false"),
        "PowerShell hook must fail closed on secret or error"
    );
    assert!(
        script.contains("-CommandType Application"),
        "PowerShell hook must resolve Application binary to prevent function/alias shadowing"
    );
    assert!(
        script.contains("$prevExit = $global:LASTEXITCODE"),
        "PowerShell hook must preserve caller LASTEXITCODE"
    );
    assert!(
        script.contains("secretguard binary not found"),
        "PowerShell hook must report unavailable binary clearly"
    );

    // Short assignment & multiline secret via `check -`
    let short_pass = common::synth_short_pass();
    let short_cmd = format!("pass={}", short_pass);
    let mut child_short = Command::new(bin)
        .args(["check", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child_short
        .stdin
        .as_mut()
        .unwrap()
        .write_all(short_cmd.as_bytes())
        .unwrap();
    let res_short = child_short.wait_with_output().unwrap();
    assert_eq!(
        res_short.status.code(),
        Some(1),
        "Short secret command (< 15 chars) must be intercepted"
    );

    let openai = common::synth_openai_key();
    let multiline = format!(
        "echo starting\n$env:OPENAI_API_KEY='{}'\necho done\n",
        openai
    );
    let mut child_multi = Command::new(bin)
        .args(["check", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child_multi
        .stdin
        .as_mut()
        .unwrap()
        .write_all(multiline.as_bytes())
        .unwrap();
    let res_multi = child_multi.wait_with_output().unwrap();
    assert_eq!(
        res_multi.status.code(),
        Some(1),
        "Multiline command with secret must be intercepted"
    );
}

#[test]
fn test_vault_get_parent_tty_and_pipe_blocking() {
    // 1. Interactive shell with verified TTY and clean env -> HumanInteractive (Tier3Privileged)
    let clean_env = HashMap::new();
    let (req_type, tier, _) =
        classify_requester_with_hash("powershell.exe", None, &[], true, &clean_env);
    assert_eq!(req_type, RequesterType::HumanInteractive);
    assert_eq!(tier, TrustTier::Tier3Privileged);

    // 2. Shell spawned inside CI or AI agent env -> must NOT escalate to HumanInteractive
    let mut ai_env = HashMap::new();
    ai_env.insert("CLAUDECODE".to_string(), "1".to_string());
    let (ai_req, ai_tier, _) =
        classify_requester_with_hash("powershell.exe", None, &[], true, &ai_env);
    assert_eq!(ai_req, RequesterType::AutonomousAgent);
    assert!(ai_tier < TrustTier::Tier3Privileged);

    let mut ci_env = HashMap::new();
    ci_env.insert("CI".to_string(), "true".to_string());
    let (ci_req, ci_tier, _) =
        classify_requester_with_hash("powershell.exe", None, &[], true, &ci_env);
    assert_eq!(ci_req, RequesterType::BuildOrScript);
    assert!(ci_tier < TrustTier::Tier3Privileged);

    // 3. Piped / non-TTY `vault get` must fail closed
    let dir = workspace_tmp_dir("vault_pipe");
    let bin = env!("CARGO_BIN_EXE_secretguard");
    let out = Command::new(bin)
        .env("SECRETGUARD_DIR", &dir)
        .args(["vault", "get", "ANY_KEY"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("interactive terminal TTY"),
        "Piped vault get must reject non-TTY sessions: {}",
        stderr
    );

    // 4. Current PID with TTY=false stays restricted if non-shell
    let id = IdentityContext::from_pid_with_tty(std::process::id(), false);
    assert!(id.is_ok());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_12_char_entropy_precision_no_false_positives_on_normal_identifiers() {
    let engine = secretguard::SecretGuardEngine::new();
    for clean in [
        "token=v1.2.3-Alpha1",
        "password=User_Login_01",
        "secret=config_dev_01",
    ] {
        let res = engine.scan_and_sanitize(clean);
        assert!(
            !res.has_secret,
            "12-13 char non-secret identifier falsely flagged: {}",
            clean
        );
    }
}

#[cfg(windows)]
#[test]
fn test_powershell_hook_executes_cleanly_in_real_powershell() {
    let bin = env!("CARGO_BIN_EXE_secretguard");
    let bin_dir = std::path::Path::new(bin).parent().unwrap();
    let hook_out = Command::new(bin).args(["hook", "pwsh"]).output().unwrap();
    let hook_script = String::from_utf8_lossy(&hook_out.stdout).to_string();

    // Stub Set-PSReadLineOption to capture the AddToHistoryHandler scriptblock and invoke it directly
    let ps_harness = format!(
        r#"
$env:PATH = "{};" + $env:PATH
$captured = $null
function Set-PSReadLineOption {{
    param([scriptblock]$AddToHistoryHandler)
    $script:captured = $AddToHistoryHandler
}}
{}
if (-not $captured) {{ throw "Handler not registered" }}
$global:LASTEXITCODE = 42
$allowClean = & $captured 'git status'
$afterCleanExit = $LASTEXITCODE
$allowShort = & $captured 'ls'
$allowPipe = & $captured 'dir | Select-Object -First 1'
$blockSecret = & $captured 'pass={short_pass}'
$afterSecretExit = $LASTEXITCODE
$blockChained = & $captured 'ls; pass={short_pass}'
$blockPipe = & $captured 'echo "ключ" | Out-Null; $env:API_TOKEN="{openai_key}"'
$blockAlias = & $captured 'gi env: | Out-Null; secret="{short_pass}"'
$blockQuoted = & $captured 'echo "escaped \"quote\"" ; token=''{gh_token}'''
Write-Output "$allowClean|$afterCleanExit|$allowShort|$allowPipe|$blockSecret|$afterSecretExit|$blockChained|$blockPipe|$blockAlias|$blockQuoted"
"#,
        bin_dir.display(),
        hook_script,
        short_pass = common::synth_short_pass(),
        openai_key = common::synth_openai_key(),
        gh_token = common::synth_github_token()
    );

    let res = Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_harness])
        .output()
        .expect("powershell.exe should run");
    assert!(
        res.status.success(),
        "PowerShell hook execution failed: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    let stdout = String::from_utf8_lossy(&res.stdout).trim().to_string();
    assert_eq!(
        stdout, "True|42|True|True|False|42|False|False|False|False",
        "Hook must allow clean/short/piped commands, block chained/piped/aliased/quoted/Unicode secrets, and preserve LASTEXITCODE=42"
    );
}
