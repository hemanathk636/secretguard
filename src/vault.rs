use crate::SecretGuardEngine;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::Mutex;

/// Process-wide reentrancy lock for terminal hidden input.
/// Guarantees that concurrent calls across threads are strictly serialized,
/// preventing race conditions on terminal echo state, global signal handlers,
/// and terminal interruption atomic flags.
pub static TERMINAL_INPUT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct VaultStore {
    pub secrets: HashMap<String, String>,
}

#[cfg(unix)]
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

#[cfg(unix)]
static TERMINAL_INTERRUPTED: AtomicBool = AtomicBool::new(false);
#[cfg(unix)]
static RECEIVED_SIGNAL: AtomicI32 = AtomicI32::new(0);

#[cfg(unix)]
extern "C" {
    fn getuid() -> u32;
    fn signal(signum: i32, handler: usize) -> usize;
    fn siginterrupt(signum: i32, flag: i32) -> i32;
    fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
    fn open(path: *const std::os::raw::c_char, oflag: i32, mode: u32) -> i32;
    fn openat(dirfd: i32, path: *const std::os::raw::c_char, oflag: i32, mode: u32) -> i32;
    fn close(fd: i32) -> i32;
    fn sigemptyset(set: *mut sigset_t) -> i32;
    fn sigaddset(set: *mut sigset_t, signum: i32) -> i32;
    fn pthread_sigmask(how: i32, set: *const sigset_t, oldset: *mut sigset_t) -> i32;
}

#[cfg(unix)]
#[repr(C)]
#[derive(Copy, Clone)]
struct sigset_t {
    __val: [u64; 16], // 128 bytes, aligned to 8 bytes. Safely accommodates all Unix platforms (Linux: 128B, macOS: 4B, BSD: 16B).
}

#[cfg(unix)]
pub mod unix_signal_constants {
    #[cfg(target_os = "linux")]
    pub const SIG_BLOCK: i32 = 0;
    #[cfg(target_os = "linux")]
    pub const SIG_SETMASK: i32 = 2;

    #[cfg(target_os = "macos")]
    pub const SIG_BLOCK: i32 = 1;
    #[cfg(target_os = "macos")]
    pub const SIG_SETMASK: i32 = 3;

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    compile_error!("SecretGuard strictly supports Linux and macOS on Unix targets. Other Unix variants (e.g. BSD, Solaris) are not supported.");
}

#[cfg(unix)]
pub mod unix_flags {
    pub const O_RDONLY: i32 = 0;
    pub const O_RDWR: i32 = 2;

    #[cfg(target_os = "linux")]
    pub const O_CREAT: i32 = 0o100;
    #[cfg(target_os = "macos")]
    pub const O_CREAT: i32 = 0x0200;

    #[cfg(target_os = "linux")]
    pub const O_EXCL: i32 = 0o200;
    #[cfg(target_os = "macos")]
    pub const O_EXCL: i32 = 0x0800;

    #[cfg(target_os = "linux")]
    pub const O_DIRECTORY: i32 = 0o200000;
    #[cfg(target_os = "macos")]
    pub const O_DIRECTORY: i32 = 0x00100000;

    #[cfg(target_os = "linux")]
    pub const O_NOFOLLOW: i32 = 0o400000;
    #[cfg(target_os = "macos")]
    pub const O_NOFOLLOW: i32 = 0x00000100;

    #[cfg(target_os = "linux")]
    pub const O_CLOEXEC: i32 = 0o2000000;
    #[cfg(target_os = "macos")]
    pub const O_CLOEXEC: i32 = 0x01000000;

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    compile_error!("SecretGuard strictly supports Linux and macOS on Unix targets. Other Unix variants (e.g. BSD, Solaris) are not supported.");
}

#[cfg(unix)]
struct FdGuard(pub i32);

#[cfg(unix)]
impl Drop for FdGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe { close(self.0); }
        }
    }
}

#[cfg(unix)]
extern "C" fn sig_flag_handler(sig: i32) {
    TERMINAL_INTERRUPTED.store(true, Ordering::SeqCst);
    RECEIVED_SIGNAL.store(sig, Ordering::SeqCst);
}

#[cfg(windows)]
use std::ffi::c_void;

#[cfg(windows)]
pub struct AncestorGuards(pub Vec<*mut c_void>);

#[cfg(windows)]
impl Drop for AncestorGuards {
    fn drop(&mut self) {
        for &h in &self.0 {
            if h != (-1isize as *mut c_void) && !h.is_null() {
                unsafe { win32::CloseHandle(h); }
            }
        }
    }
}

#[cfg(windows)]
#[allow(non_upper_case_globals, non_snake_case)]
pub mod win32 {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    pub const REPLACEFILE_WRITE_THROUGH: u32 = 0x00000001;
    #[allow(dead_code)]
    pub const REPLACEFILE_IGNORE_MERGE_ERRORS: u32 = 0x00000002;
    #[allow(dead_code)]
    pub const REPLACEFILE_IGNORE_ACL_ERRORS: u32 = 0x00000004;

    pub const OWNER_SECURITY_INFORMATION: u32 = 0x00000001;
    pub const DACL_SECURITY_INFORMATION: u32 = 0x00000004;
    #[allow(dead_code)]
    pub const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x80000000;

    pub const TOKEN_QUERY: u32 = 0x0008;
    pub const TokenUser: i32 = 1;
    pub const AclSizeInformation: i32 = 2;
    pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    pub const ACCESS_DENIED_ACE_TYPE: u8 = 1;

    pub const WinWorldSid: i32 = 1;
    pub const WinNetworkSid: i32 = 3;
    pub const WinInteractiveSid: i32 = 4;
    pub const WinAnonymousSid: i32 = 13;
    pub const WinAuthenticatedUserSid: i32 = 17;
    pub const WinLocalSystemSid: i32 = 22;
    pub const WinBuiltinAdministratorsSid: i32 = 26;
    pub const WinBuiltinUsersSid: i32 = 27;

    pub const FILE_WRITE_DATA: u32 = 0x0002;
    pub const FILE_APPEND_DATA: u32 = 0x0004;
    pub const FILE_WRITE_EA: u32 = 0x0010;
    pub const FILE_DELETE_CHILD: u32 = 0x0040;
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    pub const DELETE: u32 = 0x00010000;
    pub const WRITE_DAC: u32 = 0x00040000;
    pub const WRITE_OWNER: u32 = 0x00080000;
    pub const MAXIMUM_ALLOWED: u32 = 0x02000000;
    pub const GENERIC_ALL: u32 = 0x10000000;
    pub const GENERIC_EXECUTE: u32 = 0x20000000;
    pub const GENERIC_WRITE: u32 = 0x40000000;

    pub const DANGEROUS_WRITE_MASK: u32 = FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_DELETE_CHILD
        | FILE_WRITE_ATTRIBUTES
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | MAXIMUM_ALLOWED
        | GENERIC_ALL
        | GENERIC_WRITE;

    pub const GENERIC_READ: u32 = 0x80000000;
    pub const READ_CONTROL: u32 = 0x00020000;
    pub const FILE_SHARE_READ: u32 = 0x00000001;
    pub const FILE_SHARE_WRITE: u32 = 0x00000002;
    pub const FILE_SHARE_DELETE: u32 = 0x00000004;
    pub const OPEN_EXISTING: u32 = 3;
    pub const CREATE_NEW: u32 = 1;
    pub const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
    pub const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
    pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;
    pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;
    pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;
    pub const SE_FILE_OBJECT: i32 = 1;

    #[repr(C)]
    #[derive(Default, Debug)]
    pub struct BY_HANDLE_FILE_INFORMATION {
        pub dwFileAttributes: u32,
        pub ftCreationTime: [u32; 2],
        pub ftLastAccessTime: [u32; 2],
        pub ftLastWriteTime: [u32; 2],
        pub dwVolumeSerialNumber: u32,
        pub nFileSizeHigh: u32,
        pub nFileSizeLow: u32,
        pub nNumberOfLinks: u32,
        pub nFileIndexHigh: u32,
        pub nFileIndexLow: u32,
    }

    #[repr(C)]
    pub struct SID_AND_ATTRIBUTES {
        pub Sid: *mut c_void,
        pub Attributes: u32,
    }

    #[repr(C)]
    pub struct TOKEN_USER {
        pub User: SID_AND_ATTRIBUTES,
    }

    #[repr(C)]
    #[derive(Default, Debug)]
    pub struct ACL_SIZE_INFORMATION {
        pub AceCount: u32,
        pub AclBytesInUse: u32,
        pub AclBytesFree: u32,
    }

    #[repr(C)]
    pub struct ACE_HEADER {
        pub AceType: u8,
        pub AceFlags: u8,
        pub AceSize: u16,
    }

    #[repr(C)]
    pub struct ACCESS_ALLOWED_ACE {
        pub Header: ACE_HEADER,
        pub Mask: u32,
        pub SidStart: u32,
    }

    #[link(name = "advapi32")]
    #[link(name = "kernel32")]
    extern "system" {
        pub fn ReplaceFileW(
            lpReplacedFileName: *const u16,
            lpReplacementFileName: *const u16,
            lpBackupFileName: *const u16,
            dwReplaceFlags: u32,
            lpExclude: *mut c_void,
            lpReserved: *mut c_void,
        ) -> i32;

        pub fn GetLastError() -> u32;

        pub fn GetCurrentProcess() -> *mut c_void;
        pub fn OpenProcessToken(ProcessHandle: *mut c_void, DesiredAccess: u32, TokenHandle: *mut *mut c_void) -> i32;
        pub fn GetTokenInformation(TokenHandle: *mut c_void, TokenInformationClass: i32, TokenInformation: *mut c_void, TokenInformationLength: u32, ReturnLength: *mut u32) -> i32;
        pub fn CreateWellKnownSid(WellKnownSidType: i32, DomainSid: *const c_void, pSid: *mut c_void, cbSid: *mut u32) -> i32;
        pub fn EqualSid(pSid1: *const c_void, pSid2: *const c_void) -> i32;
        pub fn GetAclInformation(pAcl: *const c_void, pAclInformation: *mut c_void, nAclInformationLength: u32, dwAclInformationClass: i32) -> i32;
        pub fn GetAce(pAcl: *const c_void, dwAceIndex: u32, pAce: *mut *mut c_void) -> i32;

        pub fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *mut c_void,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: *mut c_void,
        ) -> *mut c_void;
        pub fn GetFileInformationByHandle(hFile: *mut c_void, lpFileInformation: *mut BY_HANDLE_FILE_INFORMATION) -> i32;
        pub fn CloseHandle(hObject: *mut c_void) -> i32;
        pub fn GetSecurityInfo(
            handle: *mut c_void,
            ObjectType: i32,
            SecurityInfo: u32,
            ppsidOwner: *mut *mut c_void,
            ppsidGroup: *mut *mut c_void,
            ppDacl: *mut *mut c_void,
            ppSacl: *mut *mut c_void,
            ppSecurityDescriptor: *mut *mut c_void,
        ) -> u32;
        pub fn LocalFree(hMem: *mut c_void) -> *mut c_void;

        pub fn GetFileSecurityW(
            lpFileName: *const u16,
            RequestedInformation: u32,
            pSecurityDescriptor: *mut c_void,
            nLength: u32,
            lpnLengthNeeded: *mut u32,
        ) -> i32;

        pub fn GetSecurityDescriptorDacl(
            pSecurityDescriptor: *const c_void,
            lpbDaclPresent: *mut i32,
            pDacl: *mut *mut c_void,
            lpbDaclDefaulted: *mut i32,
        ) -> i32;

        pub fn GetSecurityDescriptorOwner(
            pSecurityDescriptor: *const c_void,
            pOwner: *mut *mut c_void,
            lpbOwnerDefaulted: *mut i32,
        ) -> i32;
    }

    pub fn to_wide_null(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Core inspection logic for Windows security descriptors:
    /// 1. Verifies Owner SID is present and matches the current user SID (or Administrators/SYSTEM).
    /// 2. Verifies DACL is present and not NULL.
    /// 3. Enumerates all ACEs in the DACL: strictly rejects any ACE granting write/delete/modify
    ///    permissions to Everyone (World) or Users.
    pub fn inspect_dacl_and_owner(p_owner: *const c_void, p_dacl: *const c_void, path: &Path, is_target: bool) -> Result<(), String> {
        // If this is a drive root (e.g. "C:\"), it is the OS volume root mount
        if path.parent().is_none() {
            return Ok(());
        }

        if p_owner.is_null() {
            return Err(format!(
                "Security Error: Missing or NULL Owner SID on '{}'. Aborting to fail closed.",
                path.display()
            ));
        }

        // Get current process user's SID
        let mut h_token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h_token) } == 0 {
            return Err(format!(
                "Security Error: Failed to open process token to verify owner on '{}'. Aborting.",
                path.display()
            ));
        }
        let mut len = 0u32;
        unsafe { GetTokenInformation(h_token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
        let mut user_buf = vec![0u8; len as usize];
        if unsafe { GetTokenInformation(h_token, TokenUser, user_buf.as_mut_ptr() as *mut c_void, len, &mut len) } == 0 {
            unsafe { CloseHandle(h_token) };
            return Err(format!(
                "Security Error: Failed to query user SID to verify owner on '{}'. Aborting.",
                path.display()
            ));
        }
        unsafe { CloseHandle(h_token) };
        let current_user_sid = unsafe { (*(user_buf.as_ptr() as *const TOKEN_USER)).User.Sid };

        // Well-known trusted administrative/system SIDs
        let mut admin_sid_buf = vec![0u8; 68];
        let mut cb_admin = 68u32;
        unsafe { CreateWellKnownSid(WinBuiltinAdministratorsSid, std::ptr::null(), admin_sid_buf.as_mut_ptr() as *mut c_void, &mut cb_admin) };

        let mut system_sid_buf = vec![0u8; 68];
        let mut cb_system = 68u32;
        unsafe { CreateWellKnownSid(WinLocalSystemSid, std::ptr::null(), system_sid_buf.as_mut_ptr() as *mut c_void, &mut cb_system) };

        let is_user = unsafe { EqualSid(p_owner, current_user_sid) != 0 };
        let is_admin = unsafe { EqualSid(p_owner, admin_sid_buf.as_ptr() as *const c_void) != 0 };
        let is_system = unsafe { EqualSid(p_owner, system_sid_buf.as_ptr() as *const c_void) != 0 };

        if is_target {
            if !is_user && !is_admin {
                return Err(format!(
                    "Security Error: Target path '{}' is owned by an untrusted principal (SID mismatch). Expected current user or Administrators. Aborting to fail closed.",
                    path.display()
                ));
            }
        } else {
            if !is_user && !is_admin && !is_system {
                return Err(format!(
                    "Security Error: Ancestor directory '{}' is owned by an untrusted principal (SID mismatch). Expected current user, SYSTEM, or Administrators. Aborting to fail closed.",
                    path.display()
                ));
            }
        }

        // DACL validation
        if p_dacl.is_null() {
            return Err(format!(
                "Security Error: Insecure permissions on '{}': NULL DACL detected (grants universal access). Aborting.",
                path.display()
            ));
        }

        let mut acl_size = ACL_SIZE_INFORMATION::default();
        let ok = unsafe {
            GetAclInformation(
                p_dacl,
                &mut acl_size as *mut _ as *mut c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        };
        if ok == 0 {
            return Err(format!(
                "Security Error: Failed to inspect ACL information on '{}'. Aborting.",
                path.display()
            ));
        }

        // For target files (vault / master key): Enforce STRICT ALLOW-LIST.
        // Only active user, BUILTIN\Administrators, and NT AUTHORITY\SYSTEM are permitted.
        // Any other principal, or unknown/complex ACE type, is strictly rejected to fail closed.
        if is_target {
            for i in 0..acl_size.AceCount {
                let mut p_ace = std::ptr::null_mut();
                if unsafe { GetAce(p_dacl, i, &mut p_ace) } == 0 {
                    return Err(format!("Security Error: Failed to retrieve ACE {} on '{}'.", i, path.display()));
                }
                let ace = unsafe { &*(p_ace as *const ACCESS_ALLOWED_ACE) };

                // Unknown or complex ACE types (callback ACEs, object ACEs) fail closed on target
                if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != ACCESS_DENIED_ACE_TYPE {
                    return Err(format!(
                        "Security Error: Insecure permissions on target file '{}': Unsupported or complex ACE type {} (e.g. object/callback ACE) detected. Aborting to fail closed.",
                        path.display(),
                        ace.Header.AceType
                    ));
                }

                if ace.Header.AceType == ACCESS_ALLOWED_ACE_TYPE {
                    let ace_sid = &ace.SidStart as *const u32 as *const c_void;
                    let is_current_user = unsafe { EqualSid(ace_sid, current_user_sid) != 0 };
                    let is_admin_sid = unsafe { EqualSid(ace_sid, admin_sid_buf.as_ptr() as *const c_void) != 0 };
                    let is_system_sid = unsafe { EqualSid(ace_sid, system_sid_buf.as_ptr() as *const c_void) != 0 };

                    if !is_current_user && !is_admin_sid && !is_system_sid {
                        return Err(format!(
                            "Security Error: Insecure permissions on target '{}': ACE grants access to untrusted principal outside strict allow-list. Only active user, Administrators, and SYSTEM are permitted. Aborting to fail closed.",
                            path.display()
                        ));
                    }
                }
            }
        } else {
            // For ancestor directories:
            // 1. Any unsupported or complex ACE type (such as callback ACEs, object ACEs) fails closed.
            // 2. Only active user, BUILTIN\Administrators, and NT AUTHORITY\SYSTEM may hold write permissions (DANGEROUS_WRITE_MASK).
            //    Any ACE granting write/modify/delete permissions to ANY other principal (Everyone, Users, Authenticated Users,
            //    Network, Interactive, Anonymous, or ANY custom group / third-party SID) is strictly rejected to fail closed.
            //    Non-write permissions (read, traverse, execute) for groups like Users or Authenticated Users are permitted.
            for i in 0..acl_size.AceCount {
                let mut p_ace = std::ptr::null_mut();
                if unsafe { GetAce(p_dacl, i, &mut p_ace) } == 0 {
                    return Err(format!("Security Error: Failed to retrieve ACE {} on directory '{}'.", i, path.display()));
                }
                let ace = unsafe { &*(p_ace as *const ACCESS_ALLOWED_ACE) };

                // Reject unsupported or complex ACE types on ancestor directories
                if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != ACCESS_DENIED_ACE_TYPE {
                    return Err(format!(
                        "Security Error: Insecure permissions on directory '{}': Unsupported or complex ACE type {} (e.g. object/callback ACE) detected. Aborting to fail closed.",
                        path.display(),
                        ace.Header.AceType
                    ));
                }

                if ace.Header.AceType == ACCESS_ALLOWED_ACE_TYPE {
                    let mask = ace.Mask;
                    if (mask & DANGEROUS_WRITE_MASK) != 0 {
                        let ace_sid = &ace.SidStart as *const u32 as *const c_void;
                        let is_current_user = unsafe { EqualSid(ace_sid, current_user_sid) != 0 };
                        let is_admin_sid = unsafe { EqualSid(ace_sid, admin_sid_buf.as_ptr() as *const c_void) != 0 };
                        let is_system_sid = unsafe { EqualSid(ace_sid, system_sid_buf.as_ptr() as *const c_void) != 0 };

                        if !is_current_user && !is_admin_sid && !is_system_sid {
                            return Err(format!(
                                "Security Error: Insecure permissions on intermediate directory '{}': Overly permissive ACE grants write/modify/delete access (Mask: 0x{:08x}) to untrusted principal or custom group. Only active user, Administrators, and SYSTEM may have write permissions on vault ancestors. Aborting to fail closed.",
                                path.display(),
                                mask
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Inspects the Windows Security Descriptor on `path` using `GetFileSecurityW`.
    pub fn validate_windows_security_descriptor(path: &Path, is_target: bool) -> Result<(), String> {
        let wide = to_wide_null(path);
        let sec_info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut needed = 0u32;
        unsafe {
            GetFileSecurityW(wide.as_ptr(), sec_info, std::ptr::null_mut(), 0, &mut needed);
        }
        if needed == 0 {
            let err = unsafe { GetLastError() };
            return Err(format!(
                "Security Error: Failed to query Windows security descriptor on '{}' (Win32 error: {}). Aborting.",
                path.display(),
                err
            ));
        }

        let mut buf = vec![0u8; needed as usize];
        let ok = unsafe {
            GetFileSecurityW(wide.as_ptr(), sec_info, buf.as_mut_ptr() as *mut c_void, needed, &mut needed)
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(format!(
                "Security Error: Failed to retrieve Windows security descriptor on '{}' (Win32 error: {}). Aborting.",
                path.display(),
                err
            ));
        }

        let mut dacl_present = 0i32;
        let mut p_dacl = std::ptr::null_mut();
        let mut dacl_defaulted = 0i32;
        let dacl_ok = unsafe {
            GetSecurityDescriptorDacl(
                buf.as_ptr() as *const c_void,
                &mut dacl_present,
                &mut p_dacl,
                &mut dacl_defaulted,
            )
        };
        if dacl_ok == 0 || dacl_present == 0 {
            return Err(format!(
                "Security Error: Insecure permissions on '{}': NULL or missing DACL detected. Aborting to fail closed.",
                path.display()
            ));
        }

        let mut p_owner = std::ptr::null_mut();
        let mut owner_defaulted = 0i32;
        let owner_ok = unsafe {
            GetSecurityDescriptorOwner(
                buf.as_ptr() as *const c_void,
                &mut p_owner,
                &mut owner_defaulted,
            )
        };
        if owner_ok == 0 {
            return Err(format!(
                "Security Error: Failed to query Owner SID on '{}'. Aborting to fail closed.",
                path.display()
            ));
        }

        inspect_dacl_and_owner(p_owner, p_dacl, path, is_target)
    }

    /// Inspects the Windows Security Descriptor on an open file handle using `GetSecurityInfo`.
    pub fn validate_windows_security_descriptor_handle(handle: *mut c_void, path: &Path, is_target: bool) -> Result<(), String> {
        let mut p_owner = std::ptr::null_mut();
        let mut p_dacl = std::ptr::null_mut();
        let mut p_sd = std::ptr::null_mut();

        let ret = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut p_owner,
                std::ptr::null_mut(),
                &mut p_dacl,
                std::ptr::null_mut(),
                &mut p_sd,
            )
        };

        if ret != 0 {
            return Err(format!(
                "Security Error: Failed to inspect security descriptor on open handle for '{}' (Win32 error: {}). Aborting.",
                path.display(),
                ret
            ));
        }

        let res = inspect_dacl_and_owner(p_owner, p_dacl, path, is_target);
        unsafe { LocalFree(p_sd) };
        res
    }
}

/// Validates that `path` and all intermediate ancestor directories meet strict security guarantees on Unix:
/// 1. Relative paths are securely resolved against the validated current working directory.
/// 2. Parent directory traversal (`..`) is strictly rejected.
/// 3. Every existing path component chain must not be a symlink and must be owned by active user or root.
/// 4. No intermediate path component may be group-writable (0o020) or world-writable (0o002) unless it is a root-owned sticky directory (e.g. /tmp with 0o1777).
/// 5. The target itself (if existing) must not be a symlink and must be owned by active user.
/// 6. Private permissions are strictly enforced (0o700 for directories, 0o600 for files) and re-verified.
/// Fails closed upon any filesystem metadata inspection error (except NotFound for target).
pub fn validate_secure_path(path: &Path, is_file: bool) -> Result<(), String> {
    // 0. Reject dangerous parent directory traversal components ("..") across all platforms
    for comp in path.components() {
        if comp == std::path::Component::ParentDir {
            return Err(format!(
                "Security Error: Path '{}' contains parent directory ('..') traversal. Aborting.",
                path.display()
            ));
        }
    }

    // Resolve relative paths against validated current working directory across all platforms
    let resolved_path = if path.is_relative() {
        let cwd = std::env::current_dir().map_err(|e| {
            format!("Security Error: Cannot determine current working directory: {}. Aborting.", e)
        })?;
        cwd.join(path)
    } else {
        path.to_path_buf()
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let active_uid = unsafe { getuid() };

        // 1. Validate every path component in the chain from root down to parent
        if let Some(parent) = resolved_path.parent() {
            let mut ancestors = Vec::new();
            let mut curr = Some(parent);
            while let Some(p) = curr {
                if !p.as_os_str().is_empty() && p != Path::new("/") {
                    ancestors.push(p);
                }
                curr = p.parent();
            }
            ancestors.reverse();

            for ancestor in ancestors {
                match fs::symlink_metadata(ancestor) {
                    Ok(p_meta) => {
                        if p_meta.file_type().is_symlink() {
                            return Err(format!(
                                "Security Error: Path component '{}' is a symbolic link. Symbolic links are strictly prohibited for vault storage.",
                                ancestor.display()
                            ));
                        }

                        if p_meta.uid() != active_uid && p_meta.uid() != 0 {
                            return Err(format!(
                                "Security Error: Path component '{}' is owned by UID {} (expected active user UID {} or root). Aborting.",
                                ancestor.display(),
                                p_meta.uid(),
                                active_uid
                            ));
                        }

                        let mode = p_meta.permissions().mode();
                        if p_meta.uid() == 0 {
                            let is_sticky = (mode & 0o1000) != 0;
                            if !is_sticky && (mode & 0o022) != 0 {
                                return Err(format!(
                                    "Security Error: Root-owned path component '{}' is writable by group/others ({:o}) without sticky bit. Aborting.",
                                    ancestor.display(),
                                    mode & 0o777
                                ));
                            }
                        } else if (mode & 0o022) != 0 {
                            return Err(format!(
                                "Security Error: Path component '{}' has insecure permissions ({:o}, group/world-writable). Aborting.",
                                ancestor.display(),
                                mode & 0o777
                            ));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        // Component does not exist yet (will be created in verified parent)
                        break;
                    }
                    Err(e) => {
                        return Err(format!(
                            "Security Error: Failed to inspect metadata on path component '{}': {}. Aborting.",
                            ancestor.display(),
                            e
                        ));
                    }
                }
            }
        }

        // 2. Target path validation with explicit error handling (fails closed on all errors except NotFound)
        match fs::symlink_metadata(&resolved_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(format!(
                        "Security Error: Target path '{}' is a symbolic link. Symbolic links are strictly prohibited for vault storage.",
                        resolved_path.display()
                    ));
                }

                if meta.uid() != active_uid {
                    return Err(format!(
                        "Security Error: Target path '{}' is owned by UID {} but active user is UID {}. Aborting.",
                        resolved_path.display(),
                        meta.uid(),
                        active_uid
                    ));
                }

                let target_mode = if is_file { 0o600 } else { 0o700 };
                fs::set_permissions(&resolved_path, fs::Permissions::from_mode(target_mode)).map_err(|e| {
                    format!("Security Error: Failed to enforce {:o} permissions on '{}': {}. Aborting.", target_mode, resolved_path.display(), e)
                })?;

                let re_meta = fs::symlink_metadata(&resolved_path).map_err(|e| {
                    format!("Security Error: Failed to re-verify permissions on '{}': {}. Aborting.", resolved_path.display(), e)
                })?;

                if re_meta.permissions().mode() & 0o077 != 0 {
                    return Err(format!(
                        "Security Error: Target path '{}' permissions are insecure ({:o}). Operation aborted.",
                        resolved_path.display(),
                        re_meta.permissions().mode() & 0o777
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Target does not exist yet (first-time creation); verified safe to create
            }
            Err(e) => {
                return Err(format!(
                    "Security Error: Cannot inspect target '{}': {}. Aborting to fail closed.",
                    resolved_path.display(),
                    e
                ));
            }
        }
    }
    #[cfg(windows)]
    {
        // 1. Validate every path component in the chain from root down to parent on Windows using real handles
        // Ancestor directory handles are opened without FILE_SHARE_DELETE and held open to lock the path against TOCTOU races
        let mut ancestor_guards = AncestorGuards(Vec::new());
        if let Some(parent) = resolved_path.parent() {
            let mut ancestors = Vec::new();
            let mut curr = Some(parent);
            while let Some(p) = curr {
                if !p.as_os_str().is_empty() {
                    ancestors.push(p);
                }
                curr = p.parent();
            }
            ancestors.reverse();

            for ancestor in ancestors {
                let wide = win32::to_wide_null(ancestor);
                let h_dir = unsafe {
                    win32::CreateFileW(
                        wide.as_ptr(),
                        win32::GENERIC_READ | win32::READ_CONTROL,
                        win32::FILE_SHARE_READ | win32::FILE_SHARE_WRITE, // Omit FILE_SHARE_DELETE to prevent rename/delete races
                        std::ptr::null_mut(),
                        win32::OPEN_EXISTING,
                        win32::FILE_FLAG_BACKUP_SEMANTICS | win32::FILE_FLAG_OPEN_REPARSE_POINT,
                        std::ptr::null_mut(),
                    )
                };

                if h_dir != (-1isize as *mut c_void) && !h_dir.is_null() {
                    let mut file_info = win32::BY_HANDLE_FILE_INFORMATION::default();
                    let info_ok = unsafe { win32::GetFileInformationByHandle(h_dir, &mut file_info) };
                    if info_ok == 0 {
                        unsafe { win32::CloseHandle(h_dir); }
                        return Err(format!(
                            "Security Error: Failed to query attributes on open handle for '{}'. Aborting.",
                            ancestor.display()
                        ));
                    }

                    if (file_info.dwFileAttributes & win32::FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                        unsafe { win32::CloseHandle(h_dir); }
                        return Err(format!(
                            "Security Error: Path component '{}' is a symbolic link or directory junction (reparse point). Reparse points are strictly prohibited for vault storage.",
                            ancestor.display()
                        ));
                    }

                    if (file_info.dwFileAttributes & win32::FILE_ATTRIBUTE_DIRECTORY) == 0 {
                        unsafe { win32::CloseHandle(h_dir); }
                        return Err(format!(
                            "Security Error: Path component '{}' is not a directory. Aborting.",
                            ancestor.display()
                        ));
                    }

                    let val_res = win32::validate_windows_security_descriptor_handle(h_dir, ancestor, false);
                    if let Err(e) = val_res {
                        unsafe { win32::CloseHandle(h_dir); }
                        return Err(e);
                    }
                    ancestor_guards.0.push(h_dir);
                } else {
                    let err = unsafe { win32::GetLastError() };
                    if err == 2 || err == 3 {
                        // ERROR_FILE_NOT_FOUND (2) or ERROR_PATH_NOT_FOUND (3): component does not exist yet
                        break;
                    }
                    return Err(format!(
                        "Security Error: Cannot open directory handle for path component '{}' (Win32 error: {}). Aborting to fail closed.",
                        ancestor.display(),
                        err
                    ));
                }
            }
        }

        // 2. Validate target path on Windows (if existing) using handle-based inspection while ancestor handles are held
        let wide_target = win32::to_wide_null(&resolved_path);
        let h_target = unsafe {
            win32::CreateFileW(
                wide_target.as_ptr(),
                win32::GENERIC_READ | win32::READ_CONTROL,
                win32::FILE_SHARE_READ,
                std::ptr::null_mut(),
                win32::OPEN_EXISTING,
                win32::FILE_FLAG_BACKUP_SEMANTICS | win32::FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };

        if h_target != (-1isize as *mut c_void) && !h_target.is_null() {
            let mut file_info = win32::BY_HANDLE_FILE_INFORMATION::default();
            let info_ok = unsafe { win32::GetFileInformationByHandle(h_target, &mut file_info) };
            if info_ok == 0 {
                unsafe { win32::CloseHandle(h_target); }
                return Err(format!(
                    "Security Error: Failed to query attributes on open target handle for '{}'. Aborting.",
                    resolved_path.display()
                ));
            }

            if (file_info.dwFileAttributes & win32::FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                unsafe { win32::CloseHandle(h_target); }
                return Err(format!(
                    "Security Error: Target path '{}' is a symbolic link or directory junction (reparse point). Reparse points are strictly prohibited for vault storage.",
                    resolved_path.display()
                ));
            }

            if is_file && (file_info.dwFileAttributes & win32::FILE_ATTRIBUTE_DIRECTORY) != 0 {
                unsafe { win32::CloseHandle(h_target); }
                return Err(format!(
                    "Security Error: Target path '{}' is a directory, expected regular file. Aborting.",
                    resolved_path.display()
                ));
            }

            // Strictly validate Security Descriptor directly on open handle (enforces strict ALLOW-LIST for target files)
            let val_res = win32::validate_windows_security_descriptor_handle(h_target, &resolved_path, is_file);
            unsafe { win32::CloseHandle(h_target); }
            val_res?;
        } else {
            let err = unsafe { win32::GetLastError() };
            if err != 2 && err != 3 {
                return Err(format!(
                    "Security Error: Cannot inspect target '{}' (Win32 error: {}). Aborting to fail closed.",
                    resolved_path.display(),
                    err
                ));
            }
        }
        drop(ancestor_guards);
    }
    let _ = (path, is_file, &resolved_path);
    Ok(())
}

#[cfg(unix)]
fn validate_unix_dir_descriptor(fd: i32, name: &str, active_uid: u32) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::io::FromRawFd;

    let file_ref = std::mem::ManuallyDrop::new(unsafe { fs::File::from_raw_fd(fd) });
    let meta = file_ref.metadata().map_err(|e| {
        format!("Security Error: Failed to stat directory descriptor for '{}': {}", name, e)
    })?;

    if !meta.is_dir() {
        return Err(format!("Security Error: Path component '{}' is not a directory.", name));
    }

    if meta.uid() != active_uid && meta.uid() != 0 {
        return Err(format!(
            "Security Error: Path component '{}' descriptor is owned by UID {} (expected active user UID {} or root).",
            name,
            meta.uid(),
            active_uid
        ));
    }

    let mode = meta.permissions().mode();
    if meta.uid() == 0 {
        let is_sticky = (mode & 0o1000) != 0;
        if !is_sticky && (mode & 0o022) != 0 {
            return Err(format!(
                "Security Error: Root-owned directory '{}' is group/world-writable ({:o}) without sticky bit.",
                name,
                mode & 0o777
            ));
        }
    } else if (mode & 0o022) != 0 {
        return Err(format!(
            "Security Error: Directory component '{}' has insecure permissions ({:o}).",
            name,
            mode & 0o777
        ));
    }

    Ok(())
}

#[cfg(windows)]
/// Anchors every ancestor directory in `resolved_path` by opening each directory handle strictly
/// omitting `FILE_SHARE_DELETE`. This causes the Windows NTFS kernel to reject any concurrent
/// rename, move, unlink, or deletion attempt across the entire ancestor hierarchy with
/// `ERROR_SHARING_VIOLATION` (32). Returns an `AncestorGuards` RAII collection that keeps
/// all ancestor handles open until dropped.
pub fn anchor_ancestor_directories(resolved_path: &Path) -> Result<AncestorGuards, String> {
    let mut ancestor_guards = AncestorGuards(Vec::new());
    if let Some(parent) = resolved_path.parent() {
        let mut ancestors = Vec::new();
        let mut curr = Some(parent);
        while let Some(p) = curr {
            if !p.as_os_str().is_empty() {
                ancestors.push(p);
            }
            curr = p.parent();
        }
        ancestors.reverse();

        for ancestor in ancestors {
            let wide = win32::to_wide_null(ancestor);
            let h_dir = unsafe {
                win32::CreateFileW(
                    wide.as_ptr(),
                    win32::GENERIC_READ | win32::READ_CONTROL,
                    win32::FILE_SHARE_READ | win32::FILE_SHARE_WRITE, // Strictly omit FILE_SHARE_DELETE
                    std::ptr::null_mut(),
                    win32::OPEN_EXISTING,
                    win32::FILE_FLAG_BACKUP_SEMANTICS | win32::FILE_FLAG_OPEN_REPARSE_POINT,
                    std::ptr::null_mut(),
                )
            };

            if h_dir != (-1isize as *mut c_void) && !h_dir.is_null() {
                let mut file_info = win32::BY_HANDLE_FILE_INFORMATION::default();
                let info_ok = unsafe { win32::GetFileInformationByHandle(h_dir, &mut file_info) };
                if info_ok == 0 {
                    unsafe { win32::CloseHandle(h_dir); }
                    return Err(format!(
                        "Security Error: Failed to query attributes on open handle for '{}'. Aborting.",
                        ancestor.display()
                    ));
                }

                if (file_info.dwFileAttributes & win32::FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                    unsafe { win32::CloseHandle(h_dir); }
                    return Err(format!(
                        "Security Error: Path component '{}' is a symbolic link or directory junction (reparse point). Reparse points are strictly prohibited for vault storage.",
                        ancestor.display()
                    ));
                }

                if (file_info.dwFileAttributes & win32::FILE_ATTRIBUTE_DIRECTORY) == 0 {
                    unsafe { win32::CloseHandle(h_dir); }
                    return Err(format!(
                        "Security Error: Path component '{}' is not a directory. Aborting.",
                        ancestor.display()
                    ));
                }

                let val_res = win32::validate_windows_security_descriptor_handle(h_dir, ancestor, false);
                if let Err(e) = val_res {
                    unsafe { win32::CloseHandle(h_dir); }
                    return Err(e);
                }
                ancestor_guards.0.push(h_dir);
            } else {
                let err = unsafe { win32::GetLastError() };
                return Err(format!(
                    "Security Error: Cannot open directory handle for path component '{}' (Win32 error: {}). Aborting to fail closed.",
                    ancestor.display(),
                    err
                ));
            }
        }
    }
    Ok(ancestor_guards)
}

/// Opens a file securely for reading, guaranteeing immunity against symlink and TOCTOU directory swap attacks:
/// - On Unix: walks all ancestor directories descriptor-relatively using `openat` with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`,
///   verifying UID ownership and non-writable permissions on each descriptor, and opens the target file relative to the
///   verified parent directory descriptor using `openat` with `O_NOFOLLOW | O_CLOEXEC`.
/// - On Windows: locks every ancestor directory by opening its handle WITHOUT `FILE_SHARE_DELETE` (so the Windows kernel
///   blocks any concurrent rename, move, unlink, or deletion of intermediate directories), verifies no reparse point,
///   opens the target file handle with `FILE_FLAG_OPEN_REPARSE_POINT` while ancestor handles are held, verifies non-reparse
///   and regular file attributes, validates the Security Descriptor directly on the handle (enforcing the strict target allow-list),
///   and returns the open handle.
pub fn open_secure_file_for_read(path: &Path) -> Result<Option<fs::File>, String> {
    for comp in path.components() {
        if comp == std::path::Component::ParentDir {
            return Err(format!(
                "Security Error: Path '{}' contains parent directory ('..') traversal. Aborting.",
                path.display()
            ));
        }
    }

    let resolved_path = if path.is_relative() {
        let cwd = std::env::current_dir().map_err(|e| {
            format!("Security Error: Cannot determine current working directory: {}. Aborting.", e)
        })?;
        cwd.join(path)
    } else {
        path.to_path_buf()
    };

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::io::FromRawFd;

        let parent = match resolved_path.parent() {
            Some(p) => p,
            None => return Err(format!("Security Error: Path '{}' has no parent directory.", resolved_path.display())),
        };

        let file_name = match resolved_path.file_name() {
            Some(f) => f,
            None => return Err(format!("Security Error: Path '{}' has no file name.", resolved_path.display())),
        };

        let active_uid = unsafe { getuid() };

        let root_c = std::ffi::CString::new("/").map_err(|e| e.to_string())?;
        let root_fd = unsafe {
            open(
                root_c.as_ptr(),
                unix_flags::O_RDONLY | unix_flags::O_DIRECTORY | unix_flags::O_CLOEXEC,
                0,
            )
        };
        if root_fd < 0 {
            return Err(format!("Security Error: Failed to open root directory descriptor: {}.", io::Error::last_os_error()));
        }
        let mut curr_guard = FdGuard(root_fd);

        // Validate root directory descriptor
        validate_unix_dir_descriptor(curr_guard.0, "/", active_uid)?;

        // Traverse ancestors descriptor-relatively using openat
        for comp in parent.components() {
            match comp {
                std::path::Component::RootDir | std::path::Component::CurDir => continue,
                std::path::Component::Normal(c) => {
                    let c_bytes = c.as_bytes();
                    let c_str = std::ffi::CString::new(c_bytes).map_err(|e| e.to_string())?;

                    let next_fd = unsafe {
                        openat(
                            curr_guard.0,
                            c_str.as_ptr(),
                            unix_flags::O_RDONLY | unix_flags::O_DIRECTORY | unix_flags::O_NOFOLLOW | unix_flags::O_CLOEXEC,
                            0,
                        )
                    };

                    if next_fd < 0 {
                        let err = io::Error::last_os_error();
                        if err.kind() == io::ErrorKind::NotFound {
                            return Ok(None);
                        }
                        return Err(format!(
                            "Security Error: Failed to open directory descriptor for component '{}' relative to parent (O_NOFOLLOW): {}. Aborting.",
                            c.to_string_lossy(),
                            err
                        ));
                    }

                    if let Err(e) = validate_unix_dir_descriptor(next_fd, &c.to_string_lossy(), active_uid) {
                        unsafe { close(next_fd); }
                        return Err(e);
                    }

                    curr_guard = FdGuard(next_fd);
                }
                std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                    return Err("Security Error: Invalid path component.".to_string());
                }
            }
        }

        // Open target file strictly relative to verified parent descriptor with openat + O_NOFOLLOW
        let file_cstr = std::ffi::CString::new(file_name.as_bytes()).map_err(|e| e.to_string())?;
        let file_fd = unsafe {
            openat(
                curr_guard.0,
                file_cstr.as_ptr(),
                unix_flags::O_RDONLY | unix_flags::O_NOFOLLOW | unix_flags::O_CLOEXEC,
                0,
            )
        };
        drop(curr_guard);

        if file_fd < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(format!(
                "Security Error: Failed to open target file '{}' relative to parent descriptor (O_NOFOLLOW): {}. Aborting.",
                resolved_path.display(),
                err
            ));
        }

        let file = unsafe { fs::File::from_raw_fd(file_fd) };
        let meta = file.metadata().map_err(|e| {
            format!("Security Error: Cannot stat target file descriptor '{}': {}", resolved_path.display(), e)
        })?;

        if !meta.is_file() {
            return Err(format!(
                "Security Error: Target path '{}' is not a regular file (symlink or special device).",
                resolved_path.display()
            ));
        }

        if meta.uid() != active_uid {
            return Err(format!(
                "Security Error: Target file descriptor '{}' is owned by UID {} but active user is UID {}. Aborting.",
                resolved_path.display(),
                meta.uid(),
                active_uid
            ));
        }

        let mode = meta.permissions().mode();
        if (mode & 0o077) != 0 {
            file.set_permissions(fs::Permissions::from_mode(0o600)).map_err(|e| {
                format!("Security Error: Failed to tighten file permissions on '{}': {}", resolved_path.display(), e)
            })?;
            let re_meta = file.metadata().map_err(|e| {
                format!("Security Error: Failed to re-verify permissions on '{}': {}", resolved_path.display(), e)
            })?;
            if (re_meta.permissions().mode() & 0o077) != 0 {
                return Err(format!("Security Error: File permissions on '{}' remain insecure ({:o}).", resolved_path.display(), re_meta.permissions().mode() & 0o777));
            }
        }

        return Ok(Some(file));
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::FromRawHandle;

        let ancestor_guards = match anchor_ancestor_directories(&resolved_path) {
            Ok(guards) => guards,
            Err(e) => {
                let err = unsafe { win32::GetLastError() };
                if err == 2 || err == 3 {
                    return Ok(None);
                }
                return Err(e);
            }
        };

        // WHILE ancestor handles are actively held (locking path against TOCTOU rename/delete), open target file handle
        let wide_target = win32::to_wide_null(&resolved_path);
        let h_target = unsafe {
            win32::CreateFileW(
                wide_target.as_ptr(),
                win32::GENERIC_READ | win32::READ_CONTROL,
                win32::FILE_SHARE_READ,
                std::ptr::null_mut(),
                win32::OPEN_EXISTING,
                win32::FILE_ATTRIBUTE_NORMAL | win32::FILE_FLAG_BACKUP_SEMANTICS | win32::FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };

        if h_target == (-1isize as *mut c_void) || h_target.is_null() {
            let err = unsafe { win32::GetLastError() };
            if err == 2 || err == 3 {
                return Ok(None);
            }
            return Err(format!(
                "Security Error: Failed to open target handle for '{}' (Win32 error: {}). Aborting.",
                resolved_path.display(),
                err
            ));
        }

        let mut file_info = win32::BY_HANDLE_FILE_INFORMATION::default();
        let info_ok = unsafe { win32::GetFileInformationByHandle(h_target, &mut file_info) };
        if info_ok == 0 {
            unsafe { win32::CloseHandle(h_target); }
            return Err(format!(
                "Security Error: Failed to query attributes on open target handle for '{}'. Aborting.",
                resolved_path.display()
            ));
        }

        if (file_info.dwFileAttributes & win32::FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            unsafe { win32::CloseHandle(h_target); }
            return Err(format!(
                "Security Error: Target path '{}' is a symbolic link or directory junction (reparse point). Reparse points are strictly prohibited.",
                resolved_path.display()
            ));
        }

        if (file_info.dwFileAttributes & win32::FILE_ATTRIBUTE_DIRECTORY) != 0 {
            unsafe { win32::CloseHandle(h_target); }
            return Err(format!(
                "Security Error: Target path '{}' is a directory, not a regular file. Aborting.",
                resolved_path.display()
            ));
        }

        let val_res = win32::validate_windows_security_descriptor_handle(h_target, &resolved_path, true);
        if let Err(e) = val_res {
            unsafe { win32::CloseHandle(h_target); }
            return Err(e);
        }

        drop(ancestor_guards); // Release ancestor locks now that target handle is verified and anchored

        let file = unsafe { fs::File::from_raw_handle(h_target as std::os::windows::io::RawHandle) };
        return Ok(Some(file));
    }

    #[cfg(not(any(unix, windows)))]
    {
        match fs::symlink_metadata(&resolved_path) {
            Ok(m) => {
                if m.file_type().is_symlink() {
                    return Err(format!("Security Error: Path '{}' is a symlink. Aborting.", resolved_path.display()));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("Security Error: Cannot stat '{}': {}", resolved_path.display(), e)),
        }
        let f = fs::File::open(&resolved_path).map_err(|e| format!("Failed to open '{}': {}", resolved_path.display(), e))?;
        Ok(Some(f))
    }
}

/// Exclusively creates a file, guaranteeing immunity against symlink and TOCTOU directory swap attacks:
/// - On Unix: walks all ancestor directories descriptor-relatively using `openat` with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`,
///   and creates the target file relative to the verified parent descriptor using `openat` with `O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC`.
/// - On Windows: locks every ancestor directory by opening its handle WITHOUT `FILE_SHARE_DELETE`,
///   creates the target file handle exclusively with `CREATE_NEW | FILE_FLAG_OPEN_REPARSE_POINT` while ancestor handles are held,
///   verifies attributes and Security Descriptor directly on the handle, and returns the open handle.
pub fn create_secure_file_exclusive(path: &Path, mode: u32) -> Result<fs::File, String> {
    for comp in path.components() {
        if comp == std::path::Component::ParentDir {
            return Err(format!(
                "Security Error: Path '{}' contains parent directory ('..') traversal. Aborting.",
                path.display()
            ));
        }
    }

    let resolved_path = if path.is_relative() {
        let cwd = std::env::current_dir().map_err(|e| {
            format!("Security Error: Cannot determine current working directory: {}. Aborting.", e)
        })?;
        cwd.join(path)
    } else {
        path.to_path_buf()
    };

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::FromRawFd;

        let parent = match resolved_path.parent() {
            Some(p) => p,
            None => return Err(format!("Security Error: Path '{}' has no parent directory.", resolved_path.display())),
        };

        let file_name = match resolved_path.file_name() {
            Some(f) => f,
            None => return Err(format!("Security Error: Path '{}' has no file name.", resolved_path.display())),
        };

        let active_uid = unsafe { getuid() };

        let root_c = std::ffi::CString::new("/").map_err(|e| e.to_string())?;
        let root_fd = unsafe {
            open(
                root_c.as_ptr(),
                unix_flags::O_RDONLY | unix_flags::O_DIRECTORY | unix_flags::O_CLOEXEC,
                0,
            )
        };
        if root_fd < 0 {
            return Err(format!("Security Error: Failed to open root directory descriptor: {}.", io::Error::last_os_error()));
        }
        let mut curr_guard = FdGuard(root_fd);

        // Validate root directory descriptor
        validate_unix_dir_descriptor(curr_guard.0, "/", active_uid)?;

        for comp in parent.components() {
            match comp {
                std::path::Component::RootDir | std::path::Component::CurDir => continue,
                std::path::Component::Normal(c) => {
                    let c_bytes = c.as_bytes();
                    let c_str = std::ffi::CString::new(c_bytes).map_err(|e| e.to_string())?;

                    let next_fd = unsafe {
                        openat(
                            curr_guard.0,
                            c_str.as_ptr(),
                            unix_flags::O_RDONLY | unix_flags::O_DIRECTORY | unix_flags::O_NOFOLLOW | unix_flags::O_CLOEXEC,
                            0,
                        )
                    };

                    if next_fd < 0 {
                        let err = io::Error::last_os_error();
                        return Err(format!(
                            "Security Error: Failed to open directory descriptor for component '{}' relative to parent (O_NOFOLLOW): {}. Aborting.",
                            c.to_string_lossy(),
                            err
                        ));
                    }

                    if let Err(e) = validate_unix_dir_descriptor(next_fd, &c.to_string_lossy(), active_uid) {
                        unsafe { close(next_fd); }
                        return Err(e);
                    }

                    curr_guard = FdGuard(next_fd);
                }
                std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                    return Err("Security Error: Invalid path component.".to_string());
                }
            }
        }

        // Exclusively create target file relative to verified parent descriptor using openat with O_CREAT | O_EXCL | O_NOFOLLOW
        let file_cstr = std::ffi::CString::new(file_name.as_bytes()).map_err(|e| e.to_string())?;
        let file_fd = unsafe {
            openat(
                curr_guard.0,
                file_cstr.as_ptr(),
                unix_flags::O_RDWR | unix_flags::O_CREAT | unix_flags::O_EXCL | unix_flags::O_NOFOLLOW | unix_flags::O_CLOEXEC,
                mode,
            )
        };
        drop(curr_guard);

        if file_fd < 0 {
            let err = io::Error::last_os_error();
            return Err(format!(
                "Security Error: Failed to create target file '{}' exclusively relative to parent descriptor (O_CREAT | O_EXCL | O_NOFOLLOW): {}. Aborting.",
                resolved_path.display(),
                err
            ));
        }

        let file = unsafe { fs::File::from_raw_fd(file_fd) };
        let meta = file.metadata().map_err(|e| {
            format!("Security Error: Cannot stat newly created file descriptor '{}': {}", resolved_path.display(), e)
        })?;

        if !meta.is_file() {
            return Err(format!("Security Error: Newly created target '{}' is not a regular file.", resolved_path.display()));
        }

        if meta.uid() != active_uid {
            return Err(format!("Security Error: Newly created file '{}' is owned by UID {} (expected {}).", resolved_path.display(), meta.uid(), active_uid));
        }

        return Ok(file);
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::FromRawHandle;
        let _ = mode;

        let ancestor_guards = anchor_ancestor_directories(&resolved_path)?;

        // WHILE ancestor handles are actively held, open new target file exclusively
        let wide_target = win32::to_wide_null(&resolved_path);
        let h_target = unsafe {
            win32::CreateFileW(
                wide_target.as_ptr(),
                win32::GENERIC_READ | win32::GENERIC_WRITE | win32::READ_CONTROL,
                0, // Exclusive access: no sharing
                std::ptr::null_mut(),
                win32::CREATE_NEW,
                win32::FILE_ATTRIBUTE_NORMAL | win32::FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };

        if h_target == (-1isize as *mut c_void) || h_target.is_null() {
            let err = unsafe { win32::GetLastError() };
            return Err(format!(
                "Security Error: Failed to create target file exclusively at '{}' (Win32 error: {}). Aborting.",
                resolved_path.display(),
                err
            ));
        }

        let val_res = win32::validate_windows_security_descriptor_handle(h_target, &resolved_path, true);
        if let Err(e) = val_res {
            unsafe { win32::CloseHandle(h_target); }
            let _ = fs::remove_file(&resolved_path);
            return Err(e);
        }

        drop(ancestor_guards); // Release ancestor locks now that target file is created, verified, and anchored

        let file = unsafe { fs::File::from_raw_handle(h_target as std::os::windows::io::RawHandle) };
        return Ok(file);
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = mode;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&resolved_path)
            .map_err(|e| format!("Failed to create '{}' exclusively: {}", resolved_path.display(), e))
    }
}

/// Resolves or creates a secure, private per-user directory for SecretGuard state (never falls back to shared /tmp).
/// Fails closed if 0700 private directory permissions, non-symlink status, parent ownership, or user ownership cannot be established on Unix.
pub fn get_vault_dir() -> Result<PathBuf, String> {
    if let Ok(dir_str) = env::var("SECRETGUARD_DIR") {
        let p = PathBuf::from(dir_str);
        // Pre-validate existing parent components before creation to eliminate TOCTOU races
        validate_secure_path(&p, false)?;
        fs::create_dir_all(&p).map_err(|e| format!("Failed to create SECRETGUARD_DIR at '{}': {}", p.display(), e))?;
        // Post-validate created directory to enforce 0700 mode
        validate_secure_path(&p, false)?;
        return Ok(p);
    }

    let base_dir = env::var("USERPROFILE")
        .or_else(|_| env::var("HOME"))
        .map_err(|_| "Environment Error: Neither HOME nor USERPROFILE is set. SecretGuard cannot securely locate the private user directory. Refusing to use a shared directory.".to_string())?;

    let dir = Path::new(&base_dir).join(".secretguard");
    // Pre-validate existing parent components before creation
    validate_secure_path(&dir, false)?;
    fs::create_dir_all(&dir).map_err(|e| {
        format!("Failed to create secure user directory at '{}': {}", dir.display(), e)
    })?;
    validate_secure_path(&dir, false)?;
    Ok(dir)
}

pub fn get_vault_path() -> Result<PathBuf, String> {
    if let Ok(p) = env::var("SECRETGUARD_VAULT_PATH") {
        let path = PathBuf::from(p);
        validate_secure_path(&path, true)?;
        return Ok(path);
    }
    let dir = get_vault_dir()?;
    let path = dir.join("vault.enc");
    validate_secure_path(&path, true)?;
    Ok(path)
}

pub fn get_master_key_path() -> Result<PathBuf, String> {
    if let Ok(p) = env::var("SECRETGUARD_MASTER_KEY_PATH") {
        let path = PathBuf::from(p);
        validate_secure_path(&path, true)?;
        return Ok(path);
    }
    let dir = get_vault_dir()?;
    let path = dir.join(".master.key");
    validate_secure_path(&path, true)?;
    Ok(path)
}

/// Cross-platform atomic file replacement:
/// - On Unix: atomic rename followed by explicit parent directory fsync to guarantee metadata journal commit.
/// - On Windows: race-free bounded retry loop (5 attempts) distinguishing first-time creation from in-place ReplaceFileW.
pub fn atomic_replace_file(tmp_path: &Path, target_path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        fs::rename(tmp_path, target_path).map_err(|e| {
            let _ = fs::remove_file(tmp_path);
            format!("Failed to atomically replace vault file {}: {}", target_path.display(), e)
        })?;

        // Propagate parent directory sync errors to guarantee journal commitment
        if let Some(parent) = target_path.parent() {
            let dir = fs::File::open(parent).map_err(|e| {
                format!("Failed to open parent directory '{}' for fsync: {}", parent.display(), e)
            })?;
            dir.sync_all().map_err(|e| {
                format!("Failed to fsync parent directory '{}' after vault replacement: {}", parent.display(), e)
            })?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        // Bounded retry loop (5 attempts) eliminating any TOCTOU race between target existing or being concurrently created
        for attempt in 0..5 {
            if fs::symlink_metadata(target_path).is_ok() {
                let replaced_w = win32::to_wide_null(target_path);
                let replacement_w = win32::to_wide_null(tmp_path);

                let flags = win32::REPLACEFILE_WRITE_THROUGH | win32::REPLACEFILE_IGNORE_MERGE_ERRORS;
                let success = unsafe {
                    win32::ReplaceFileW(
                        replaced_w.as_ptr(),
                        replacement_w.as_ptr(),
                        std::ptr::null(), // atomic in-place swap without backup file
                        flags,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };

                if success != 0 {
                    return Ok(());
                }

                let err = unsafe { win32::GetLastError() };
                // ERROR_FILE_NOT_FOUND (2): target was removed in that microsecond; retry as initial rename
                if err == 2 && attempt < 4 {
                    std::thread::yield_now();
                    continue;
                }

                if attempt < 4 {
                    std::thread::sleep(std::time::Duration::from_millis(5 * (attempt + 1) as u64));
                    continue;
                }

                let _ = fs::remove_file(tmp_path);
                return Err(format!(
                    "Windows ReplaceFileW failed to atomically replace '{}' with temporary vault '{}' (Win32 error: {}).",
                    target_path.display(),
                    tmp_path.display(),
                    err
                ));
            } else {
                // Target does not exist yet (first-time vault creation)
                match fs::rename(tmp_path, target_path) {
                    Ok(()) => return Ok(()),
                    Err(e) if (e.kind() == io::ErrorKind::AlreadyExists || e.kind() == io::ErrorKind::PermissionDenied) && attempt < 4 => {
                        // Concurrent process created target in this window; loop to ReplaceFileW
                        std::thread::yield_now();
                        continue;
                    }
                    Err(e) => {
                        if attempt < 4 {
                            std::thread::sleep(std::time::Duration::from_millis(5 * (attempt + 1) as u64));
                            continue;
                        }
                        let _ = fs::remove_file(tmp_path);
                        return Err(format!("Windows initial vault creation failed for '{}': {}", target_path.display(), e));
                    }
                }
            }
        }
        let _ = fs::remove_file(tmp_path);
        Err(format!("Windows atomic vault replacement failed after 5 retry attempts for '{}'", target_path.display()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        fs::rename(tmp_path, target_path).map_err(|e| {
            let _ = fs::remove_file(tmp_path);
            format!("Failed to rename {} to {}: {}", tmp_path.display(), target_path.display(), e)
        })
    }
}

/// Strips trailing CR (\r) and LF (\n) line terminators while preserving
/// leading and internal whitespace in secrets and passwords.
pub fn strip_line_terminator(s: &mut String) {
    if s.ends_with("\r\n") {
        s.truncate(s.len() - 2);
    } else if s.ends_with('\n') || s.ends_with('\r') {
        s.truncate(s.len() - 1);
    }
}

/// Parses and validates raw terminal password bytes into a valid UTF-8 string,
/// preserving international multi-byte UTF-8 sequences and stripping line terminators.
pub fn parse_password_bytes(bytes: &[u8]) -> io::Result<String> {
    let mut input = String::from_utf8(bytes.to_vec()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Password input contains invalid UTF-8 bytes: {}", e),
        )
    })?;
    strip_line_terminator(&mut input);
    Ok(input)
}

/// Retrieves or generates a genuine 256-bit cryptographically secure random master key via CSPRNG (OsRng)
/// with atomic, descriptor-relative/anchored 0600 file creation.
///
/// Returns Err if the master key path is a symlink (including dangling symlinks),
/// if permissions are insecure and cannot be tightened, or if the key length is corrupted.
pub fn get_or_generate_master_key() -> Result<[u8; 32], String> {
    let path = get_master_key_path()?;

    // Bounded retry loop (max 3 attempts) to eliminate recursion and prevent stack overflow
    for _attempt in 0..3 {
        if let Some(mut file) = open_secure_file_for_read(&path)? {
            use std::io::Read;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(|e| {
                format!(
                    "Permission denied or I/O error reading master key descriptor at '{}': {}. Aborting to protect vault integrity.",
                    path.display(),
                    e
                )
            })?;

            if bytes.len() != 32 {
                return Err(format!(
                    "Master key file at '{}' is corrupted (expected 32 bytes, found {} bytes). \
                     Aborting operation to prevent permanent vault data loss. Please restore your master key from backup.",
                    path.display(),
                    bytes.len()
                ));
            }

            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }

        // Master key does not exist yet: generate a new master key
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                format!(
                    "Failed to create master key directory '{}': {}",
                    parent.display(),
                    err
                )
            })?;
        }

        match create_secure_file_exclusive(&path, 0o600) {
            Ok(mut file) => {
                if let Err(err) = file.write_all(&key).and_then(|_| file.sync_all()) {
                    drop(file);
                    let _ = fs::remove_file(&path);
                    return Err(format!(
                        "Failed to persist master key to '{}': {}. Vault operations aborted.",
                        path.display(),
                        err
                    ));
                }
                return Ok(key);
            }
            Err(_err) => {
                // Concurrent process might have created it; loop to next attempt to read and validate it
                continue;
            }
        }
    }

    Err(format!(
        "Failed to safely access or create master key at '{}' after multiple attempts.",
        path.display()
    ))
}

/// RFC 5869 HKDF-SHA256 (Extract and Expand) using official audited `hkdf` crate
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).expect("Valid length for HKDF-SHA256 expansion");
    okm
}

pub fn derive_vault_key(passphrase: Option<&str>) -> Result<[u8; 32], String> {
    let master = get_or_generate_master_key()?;
    let salt = match passphrase {
        Some(pass) => pass.as_bytes(),
        None => b"secretguard_vault_rfc5869_salt_v3",
    };
    let info = b"SECRETGUARD_RFC5869_HKDF_AES256GCM_KEY";
    let derived = hkdf_sha256(salt, &master, info, 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&derived[..32]);
    Ok(key)
}

pub fn encrypt_vault_payload(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption error: {:?}", e))?;

    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(combined)
}

pub fn decrypt_vault_payload(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if data.len() < 12 {
        return Err("Encrypted vault data is corrupted or too short".to_string());
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed: Incorrect key, password, or corrupted vault".to_string())
}

pub fn load_vault(passphrase: Option<&str>) -> Result<VaultStore, String> {
    let path = get_vault_path()?;
    let mut file = match open_secure_file_for_read(&path)? {
        Some(f) => f,
        None => return Ok(VaultStore::default()),
    };

    use std::io::Read;
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|e| {
        format!("Failed to read vault file from handle at '{}': {}", path.display(), e)
    })?;

    let key = derive_vault_key(passphrase)?;
    let decrypted = decrypt_vault_payload(&data, &key)?;
    let store: VaultStore = serde_json::from_slice(&decrypted)
        .map_err(|e| format!("Failed to parse decrypted vault data: {}", e))?;
    Ok(store)
}

pub fn save_vault(store: &VaultStore, passphrase: Option<&str>) -> Result<(), String> {
    let path = get_vault_path()?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|e| format!("Failed to create vault directory '{}': {}", parent.display(), e))?;

    let json_bytes =
        serde_json::to_vec(store).map_err(|e| format!("Failed to serialize vault: {}", e))?;
    let key = derive_vault_key(passphrase)?;
    let encrypted = encrypt_vault_payload(&json_bytes, &key)?;

    // Unpredictable unique temporary file to eliminate race conditions and symlink replacement vulnerabilities
    let pid = process::id();
    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let tmp_filename = format!(".vault.{}.{:x}.tmp", pid, u64::from_le_bytes(nonce));
    let tmp_path = parent.join(tmp_filename);

    let mut file = create_secure_file_exclusive(&tmp_path, 0o600)?;
    let write_res = file.write_all(&encrypted).and_then(|_| file.sync_all());
    if let Err(e) = write_res {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("Failed to write and sync encrypted vault data to {}: {}", tmp_path.display(), e));
    }
    drop(file);

    atomic_replace_file(&tmp_path, &path)?;

    Ok(())
}

#[cfg(unix)]
struct SttyEchoGuard;

#[cfg(unix)]
impl Drop for SttyEchoGuard {
    fn drop(&mut self) {
        let _ = Command::new("stty").arg("echo").status();
    }
}

#[cfg(unix)]
struct SignalDispositionGuard {
    old_sigint: usize,
    old_sigterm: usize,
}

#[cfg(unix)]
impl Drop for SignalDispositionGuard {
    fn drop(&mut self) {
        unsafe {
            signal(2, self.old_sigint);
            signal(15, self.old_sigterm);
        }
    }
}

/// Reads a password or secret from the terminal with terminal echo disabled (zero external dependencies).
///
/// # Thread-Safety & Multithreading Architecture
/// - **Global Input Serialization**: Concurrent calls to `read_password_hidden` across threads are
///   strictly serialized via an internal process-wide mutex (`TERMINAL_INPUT_LOCK`). This eliminates races
///   on the terminal echo state, global interruption flags, and signal handler installations.
/// - **POSIX Signal Masking (`pthread_sigmask`)**: During terminal setup (before `stty -echo`), `SIGINT`
///   and `SIGTERM` are masked on the calling thread via `pthread_sigmask(SIG_BLOCK, ...)`, with an RAII guard
///   ensuring restoration on all exit paths. Signals are unmasked only after handlers and echo guards are armed.
/// - **Library Multithreading Contract**: In POSIX, signal dispositions (`signal()`) and process-directed
///   signals (`kill(pid, sig)`) affect the entire process, while signal masks are per-thread. When embedding
///   SecretGuard in multithreaded applications:
///   1. For interactive CLI prompts, terminal interaction should be managed on a dedicated thread (or worker
///      threads should mask `SIGINT`/`SIGTERM` so signals target the main/interactive thread).
///   2. For automated, background, or multi-threaded service workloads, developers should use SecretGuard's
///      programmatic APIs ([`load_vault_with_key`], [`save_vault_with_key`]), which operate entirely in-memory
///      with zero terminal or signal interactions.
///
/// Fails closed if terminal echo cannot be disabled. On Unix, terminal echo is restored both explicitly,
/// via an RAII drop guard for stack unwinding, and via catchable signal handlers (`SIGINT` / `SIGTERM`).
///
/// Note on termination: Uncatchable OS-level signals (such as SIGKILL/SIGSTOP) or release panic=abort
/// cannot execute userspace unwinding destructors. In such unexpected crash conditions, users can reset
/// their terminal with the standard `reset` or `stty sane` command.
pub fn read_password_hidden(prompt: &str) -> io::Result<String> {
    // Acquire process-wide terminal input lock to serialize concurrent calls across threads.
    // This eliminates races on terminal echo state, global signal interruption flags, and signal handlers.
    let _input_lock = TERMINAL_INPUT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    #[cfg(unix)]
    {
        use unix_signal_constants::{SIG_BLOCK, SIG_SETMASK};

        eprint!("{}", prompt);
        let _ = io::stderr().flush();

        const SIGINT: i32 = 2;
        const SIGTERM: i32 = 15;
        const SIG_ERR: usize = !0usize;

        // 1. Block SIGINT and SIGTERM during terminal configuration to eliminate the race window
        // where a signal could arrive while terminal echo is disabled but before signal handlers are armed.
        // Uses POSIX-compliant pthread_sigmask for robust multi-threaded signal masking.
        let mut block_mask = unsafe { std::mem::zeroed::<sigset_t>() };
        let mut orig_mask = unsafe { std::mem::zeroed::<sigset_t>() };
        if unsafe { sigemptyset(&mut block_mask) } != 0
            || unsafe { sigaddset(&mut block_mask, SIGINT) } != 0
            || unsafe { sigaddset(&mut block_mask, SIGTERM) } != 0
        {
            return Err(io::Error::last_os_error());
        }

        let mask_res = unsafe { pthread_sigmask(SIG_BLOCK, &block_mask, &mut orig_mask) };
        if mask_res != 0 {
            return Err(io::Error::from_raw_os_error(mask_res));
        }

        // RAII signal mask guard ensures the original signal mask is restored on ANY exit path
        struct SigmaskGuard(sigset_t);
        impl Drop for SigmaskGuard {
            fn drop(&mut self) {
                unsafe { pthread_sigmask(SIG_SETMASK, &self.0, std::ptr::null_mut()); }
            }
        }
        let mask_guard = SigmaskGuard(orig_mask);

        // 2. Disable echo and fail closed if stty fails
        let status = Command::new("stty")
            .arg("-echo")
            .status()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to invoke stty to disable echo: {}", e)))?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Cannot disable terminal echo (stty returned non-zero). Failing closed to prevent secret leakage in terminal.",
            ));
        }

        // Reset signal flags before input
        TERMINAL_INTERRUPTED.store(false, Ordering::SeqCst);
        RECEIVED_SIGNAL.store(0, Ordering::SeqCst);

        // 3. Install async-signal-safe flag handlers for SIGINT (Ctrl+C) and SIGTERM using integer signal handler types
        let old_sigint = unsafe { signal(SIGINT, sig_flag_handler as usize) };
        if old_sigint == SIG_ERR {
            let _ = Command::new("stty").arg("echo").status();
            return Err(io::Error::last_os_error());
        }

        let old_sigterm = unsafe { signal(SIGTERM, sig_flag_handler as usize) };
        if old_sigterm == SIG_ERR {
            unsafe { signal(SIGINT, old_sigint); }
            let _ = Command::new("stty").arg("echo").status();
            return Err(io::Error::last_os_error());
        }

        if unsafe { siginterrupt(SIGINT, 1) } != 0 {
            unsafe {
                signal(SIGINT, old_sigint);
                signal(SIGTERM, old_sigterm);
            }
            let _ = Command::new("stty").arg("echo").status();
            return Err(io::Error::last_os_error());
        }

        if unsafe { siginterrupt(SIGTERM, 1) } != 0 {
            unsafe {
                signal(SIGINT, old_sigint);
                signal(SIGTERM, old_sigterm);
            }
            let _ = Command::new("stty").arg("echo").status();
            return Err(io::Error::last_os_error());
        }

        // RAII signal disposition guard guarantees previous signal handlers are restored
        // on ANY exit path (success, error return, or panic unwinding)
        let _sig_guard = SignalDispositionGuard {
            old_sigint,
            old_sigterm,
        };

        // RAII guard guarantees stty echo is restored even on panic or error
        let _guard = SttyEchoGuard;

        // 4. Now that echo suppression and signal handlers are fully armed, unblock signals
        drop(mask_guard);

        // Deterministic test-synchronization hook:
        // Notifies parent test harness ONLY AFTER terminal echo is successfully suppressed,
        // signal handlers are actively installed and armed, and signals are unblocked.
        if std::env::var("SG_SIGNAL_TEST_ARMED").is_ok() {
            eprintln!("SG_ARMED");
            let _ = io::stderr().flush();
        }

        // Check if a signal arrived while blocked during setup (held pending by kernel)
        if TERMINAL_INTERRUPTED.load(Ordering::SeqCst) {
            let sig = RECEIVED_SIGNAL.load(Ordering::SeqCst);
            let exit_code = if sig == SIGTERM { 143 } else if sig == SIGINT { 130 } else { 128 + sig };
            let _ = Command::new("stty").arg("echo").status();
            // Explicitly restore original signal dispositions before process exit
            // (std::process::exit terminates immediately without unwinding RAII drop guards)
            unsafe {
                signal(SIGINT, old_sigint);
                signal(SIGTERM, old_sigterm);
            }
            // Independently verify that dispositions match original handlers:
            let cur_sigint = unsafe { signal(SIGINT, old_sigint) };
            let cur_sigterm = unsafe { signal(SIGTERM, old_sigterm) };
            if cur_sigint != old_sigint || cur_sigterm != old_sigterm {
                eprintln!("SG_DISPOSITION_RESTORE_MISMATCH");
                std::process::exit(99);
            }
            eprintln!();
            std::process::exit(exit_code);
        }

        let mut raw_bytes = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            if TERMINAL_INTERRUPTED.load(Ordering::SeqCst) {
                break;
            }
            let n = unsafe { read(0, byte.as_mut_ptr(), 1) };
            if n == 0 {
                // EOF reached on stdin
                break;
            } else if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted || TERMINAL_INTERRUPTED.load(Ordering::SeqCst) {
                    // Interrupted system call (EINTR) from delivered signal
                    break;
                }
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Terminal read error: {}", err),
                ));
            }
            if byte[0] == b'\n' || byte[0] == b'\r' {
                break;
            }
            raw_bytes.push(byte[0]);
        }

        // Explicitly restore echo in normal userspace context (guaranteed async-signal-safe architecture)
        let _ = Command::new("stty").arg("echo").status();

        if TERMINAL_INTERRUPTED.load(Ordering::SeqCst) {
            let sig = RECEIVED_SIGNAL.load(Ordering::SeqCst);
            let exit_code = if sig == SIGTERM {
                143 // 128 + 15
            } else if sig == SIGINT {
                130 // 128 + 2
            } else {
                128 + sig
            };
            // Explicitly restore original signal dispositions before process exit
            // (std::process::exit terminates immediately without unwinding RAII drop guards)
            unsafe {
                signal(SIGINT, old_sigint);
                signal(SIGTERM, old_sigterm);
            }
            // Independently verify that dispositions match original handlers:
            let cur_sigint = unsafe { signal(SIGINT, old_sigint) };
            let cur_sigterm = unsafe { signal(SIGTERM, old_sigterm) };
            if cur_sigint != old_sigint || cur_sigterm != old_sigterm {
                eprintln!("SG_DISPOSITION_RESTORE_MISMATCH");
                std::process::exit(99);
            }
            eprintln!();
            std::process::exit(exit_code);
        }

        eprintln!();
        let mut input = String::from_utf8(raw_bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Password input contains invalid UTF-8 bytes: {}", e),
            )
        })?;
        strip_line_terminator(&mut input);
        Ok(input)
    }
    #[cfg(not(unix))]
    {
        eprint!("{}", prompt);
        let _ = io::stderr().flush();
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "$p = Read-Host -AsSecureString; if ($p) { [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p)) }",
            ])
            .output()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to invoke PowerShell for hidden input: {}", e)))?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PowerShell secure input failed. Failing closed to prevent secret leakage in terminal.",
            ));
        }

        let mut s = String::from_utf8(output.stdout)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid UTF-8 from secure input: {}", e)))?;
        eprintln!();
        strip_line_terminator(&mut s);
        Ok(s)
    }
}

/// Replaces occurrences of `needle` in `haystack` at the raw byte level,
/// without modifying any surrounding non-UTF-8 or binary bytes.
pub fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return haystack.to_vec();
    }
    let mut result = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i <= haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            result.extend_from_slice(replacement);
            i += needle.len();
        } else {
            result.push(haystack[i]);
            i += 1;
        }
    }
    if i < haystack.len() {
        result.extend_from_slice(&haystack[i..]);
    }
    result
}

/// Stream sanitizer that maintains a bounded tail holdback buffer (4096 bytes) and stateful candidate
/// retention to guarantee that:
/// 1. Standard Cloud API Keys (AWS, GitHub, OpenAI, etc., 20-128 bytes) and Extended JWTs (up to 4096 bytes)
///    are detected even when split across arbitrary chunk boundaries.
/// 2. Multi-line PEM Private Key blocks (RSA up to 4096-bit, EC, OpenSSH) are statefully retained up to
///    16KB until their closing boundary (`-----END ...`) is established, preventing premature emission.
/// 3. Partial credentials are NEVER emitted prematurely before succeeding chunks arrive.
/// 4. Clean binary streams are preserved byte-for-byte.
/// 5. Binary streams containing embedded credentials preserve all surrounding non-secret invalid UTF-8 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnclosedPem {
    pub start_idx: usize,
    pub pem_type: Vec<u8>,
}

pub struct StreamSanitizer {
    buffer: Vec<u8>,
}

impl StreamSanitizer {
    /// Maximum supported credential length across sliding window chunk boundaries (4096 bytes / 4 KB).
    pub const WINDOW_SIZE: usize = 4096;
    /// Maximum holdback ceiling for stateful multi-line candidates such as PEM private key blocks (16384 bytes / 16 KB).
    pub const MAX_STATEFUL_HOLD_LIMIT: usize = 16384;

    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
        }
    }

    pub fn is_private_key_type(pem_type: &[u8]) -> bool {
        let lower = pem_type.to_ascii_lowercase();
        lower.windows(3).any(|w| w == b"key") || lower.windows(7).any(|w| w == b"private")
    }

    /// Sanitizes completed PEM private key blocks directly in the buffer (redacting header, key payload, and footer)
    /// and scans for any active unclosed PEM block.
    pub fn sanitize_pems_in_buffer(buffer: &mut Vec<u8>) -> Option<UnclosedPem> {
        let mut search_pos = 0;
        while search_pos < buffer.len() {
            let rel_start = match buffer[search_pos..].windows(11).position(|w| w == b"-----BEGIN ") {
                Some(pos) => pos,
                None => break,
            };
            let start = search_pos + rel_start;
            let header_rest = &buffer[start + 11..];
            let rel_header_end = match header_rest.windows(5).position(|w| w == b"-----") {
                Some(pos) => pos,
                None => {
                    // Header line is incomplete; hold back starting from `start`
                    return Some(UnclosedPem {
                        start_idx: start,
                        pem_type: Vec::new(),
                    });
                }
            };
            let pem_type = &header_rest[..rel_header_end];
            let content_start = start + 11 + rel_header_end + 5;

            let mut end_marker = Vec::with_capacity(9 + pem_type.len() + 5);
            end_marker.extend_from_slice(b"-----END ");
            end_marker.extend_from_slice(pem_type);
            end_marker.extend_from_slice(b"-----");

            if content_start <= buffer.len() {
                if let Some(rel_end) = buffer[content_start..]
                    .windows(end_marker.len())
                    .position(|w| w == end_marker.as_slice())
                {
                    let mut block_end = content_start + rel_end + end_marker.len();
                    if block_end < buffer.len() && buffer[block_end] == b'\r' {
                        block_end += 1;
                    }
                    if block_end < buffer.len() && buffer[block_end] == b'\n' {
                        block_end += 1;
                    }

                    if Self::is_private_key_type(pem_type) {
                        let replacement = b"[REDACTED]\n";
                        buffer.splice(start..block_end, replacement.iter().copied());
                        search_pos = start + replacement.len();
                    } else {
                        search_pos = block_end;
                    }
                    continue;
                }
            }

            // Unclosed PEM block found
            return Some(UnclosedPem {
                start_idx: start,
                pem_type: pem_type.to_vec(),
            });
        }
        None
    }

    /// Scans the buffer from left to right to identify any active, unclosed PEM block.
    ///
    /// Guarantees:
    /// 1. Prior completed PEM blocks or earlier `-----END ` markers appearing before a new `-----BEGIN `
    ///    cannot cause false-positive completion of subsequent unclosed blocks.
    /// 2. Matches the exact PEM type (e.g. `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `OPENSSH PRIVATE KEY`)
    ///    between `-----BEGIN <TYPE>-----` and `-----END <TYPE>-----`.
    /// 3. Incomplete headers where the `-----BEGIN ...` line itself has not fully arrived are recognized and held.
    /// 4. Multiple PEM blocks in the same stream are tracked independently.
    pub fn find_unclosed_pem(buffer: &[u8]) -> Option<UnclosedPem> {
        let mut search_pos = 0;
        while search_pos < buffer.len() {
            let rel_start = match buffer[search_pos..].windows(11).position(|w| w == b"-----BEGIN ") {
                Some(pos) => pos,
                None => break,
            };
            let start = search_pos + rel_start;
            let header_rest = &buffer[start + 11..];
            let rel_header_end = match header_rest.windows(5).position(|w| w == b"-----") {
                Some(pos) => pos,
                None => {
                    // Header line is incomplete; hold back starting from `start`
                    return Some(UnclosedPem {
                        start_idx: start,
                        pem_type: Vec::new(),
                    });
                }
            };
            let pem_type = &header_rest[..rel_header_end];
            let content_start = start + 11 + rel_header_end + 5;

            let mut end_marker = Vec::with_capacity(9 + pem_type.len() + 5);
            end_marker.extend_from_slice(b"-----END ");
            end_marker.extend_from_slice(pem_type);
            end_marker.extend_from_slice(b"-----");

            if content_start <= buffer.len() {
                if let Some(rel_end) = buffer[content_start..]
                    .windows(end_marker.len())
                    .position(|w| w == end_marker.as_slice())
                {
                    // This PEM block is completed! Move search_pos beyond this block.
                    let block_end = content_start + rel_end + end_marker.len();
                    search_pos = block_end;
                    continue;
                }
            }

            // Unclosed PEM block found
            return Some(UnclosedPem {
                start_idx: start,
                pem_type: pem_type.to_vec(),
            });
        }
        None
    }

    /// Internal helper to sanitize a slice of bytes while preserving binary fidelity.
    pub fn sanitize_bytes_internal(bytes: &[u8], engine: &SecretGuardEngine) -> (Vec<u8>, bool) {
        let lossy = String::from_utf8_lossy(bytes);
        let res = engine.scan_and_sanitize(&lossy);

        if !res.has_secret {
            return (bytes.to_vec(), false);
        }

        // If the original buffer is valid UTF-8, emit the standard sanitized text
        if std::str::from_utf8(bytes).is_ok() {
            return (res.sanitized_text.into_bytes(), true);
        }

        // Buffer contains binary / invalid UTF-8 bytes:
        // Perform surgical byte-level replacement for each detected secret,
        // preserving all surrounding invalid UTF-8 bytes byte-for-byte!
        let mut sanitized = bytes.to_vec();
        for (secret, replacement) in &res.redacted_pairs {
            sanitized = replace_bytes(&sanitized, secret.as_bytes(), replacement.as_bytes());
        }
        (sanitized, true)
    }

    pub fn sanitize_chunk(&mut self, chunk: &[u8], engine: &SecretGuardEngine, out: &mut impl Write) -> io::Result<()> {
        self.buffer.extend_from_slice(chunk);

        // Stateful candidate retention: If buffer contains an unclosed multi-line PEM block header
        // (e.g. -----BEGIN RSA PRIVATE KEY-----), hold back candidate until its matching closing boundary
        // (-----END <TYPE>-----) is received, preventing premature emission.
        // Any completed PEM private key blocks in buffer are sanitized in-place immediately.
        if let Some(unclosed) = Self::sanitize_pems_in_buffer(&mut self.buffer) {
            let start = unclosed.start_idx;
            // If candidate has reached or exceeded MAX_STATEFUL_HOLD_LIMIT (16KB), fail closed:
            // Redact the entire candidate in place so no partial key data can ever escape!
            if (self.buffer.len() - start) >= Self::MAX_STATEFUL_HOLD_LIMIT {
                let mut redacted = self.buffer[..start].to_vec();
                redacted.extend_from_slice(b"[REDACTED_PRIVATE_KEY_BLOCK]\n");
                self.buffer = redacted;
            } else {
                // Retain the unclosed candidate in buffer until matching -----END arrives.
                // If there is safe data before the candidate that exceeds WINDOW_SIZE, drain only the safe prefix.
                if start > Self::WINDOW_SIZE {
                    let (safe_prefix, _) = Self::sanitize_bytes_internal(&self.buffer[..start], engine);
                    out.write_all(&safe_prefix)?;
                    self.buffer = self.buffer[start..].to_vec();
                }
                return out.flush();
            }
        }

        // If buffer is larger than WINDOW_SIZE, process and emit the prefix
        // while holding back the tail WINDOW_SIZE bytes to prevent premature partial emission
        if self.buffer.len() > Self::WINDOW_SIZE {
            let safe_drain_point = self.buffer.len() - Self::WINDOW_SIZE;

            let (sanitized_bytes, has_secret) = Self::sanitize_bytes_internal(&self.buffer, engine);

            if has_secret {
                if sanitized_bytes.len() > Self::WINDOW_SIZE {
                    let drain = sanitized_bytes.len() - Self::WINDOW_SIZE;
                    out.write_all(&sanitized_bytes[..drain])?;
                    self.buffer = sanitized_bytes[drain..].to_vec();
                } else {
                    self.buffer = sanitized_bytes;
                }
            } else {
                // No secret detected: safely write out prefix
                out.write_all(&self.buffer[..safe_drain_point])?;
                self.buffer = self.buffer[safe_drain_point..].to_vec();
            }
        }

        out.flush()
    }

    pub fn flush_final(&mut self, engine: &SecretGuardEngine, out: &mut impl Write) -> io::Result<()> {
        if !self.buffer.is_empty() {
            if let Some(unclosed) = Self::sanitize_pems_in_buffer(&mut self.buffer) {
                let mut redacted = self.buffer[..unclosed.start_idx].to_vec();
                redacted.extend_from_slice(b"[REDACTED_PRIVATE_KEY_BLOCK]\n");
                self.buffer = redacted;
            }
            let (sanitized_bytes, _) = Self::sanitize_bytes_internal(&self.buffer, engine);
            out.write_all(&sanitized_bytes)?;
            self.buffer.clear();
            out.flush()?;
        }
        Ok(())
    }
}

/// Sanitizes a stream buffer while preserving binary stream fidelity and guaranteeing
/// that credentials embedded inside binary chunks cannot escape redaction.
pub fn sanitize_stream_buffer(buf: &[u8], engine: &SecretGuardEngine, out: &mut impl Write) -> io::Result<()> {
    let mut sanitizer = StreamSanitizer::new();
    sanitizer.sanitize_chunk(buf, engine, out)?;
    sanitizer.flush_final(engine, out)
}

pub fn run_vault_cli(args: &[String], engine: &SecretGuardEngine) {
    if args.is_empty() {
        eprintln!(
            r#"SecretGuard Encrypted Zero-Knowledge Memory Vault (v0.3.13)

USAGE:
    secretguard vault <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    set <NAME> [VALUE]         Encrypts and saves secret to local AES-256-GCM vault.
    get <NAME>                 Decrypts and prints secret value to stdout.
    list                       Lists stored secret identifiers (names only, values protected).
    delete <NAME>              Removes a secret from the vault.
    run <KEYS...> -- <CMD...>  Injects vault secrets into child process in-memory only.
    import-env [PATH]          Imports secrets from .env file into vault and creates .env.example.
"#
        );
        process::exit(2);
    }

    match args[0].as_str() {
        "set" => {
            if args.len() < 2 {
                eprintln!("Usage: secretguard vault set <KEY_NAME> [VALUE]");
                eprintln!("\nSafe Usage:");
                eprintln!("  secretguard vault set <KEY_NAME>          (prompts interactively with hidden input, preventing shell & ps leaks)");
                eprintln!("  cat secret.txt | secretguard vault set <KEY_NAME>  (reads secret securely from piped stdin)");
                process::exit(2);
            }
            let key_name = &args[1];

            // Finding 1 & 3: Protect secrets from leaking through command-line arguments and terminal echo
            let secret_val = if args.len() >= 3 {
                eprintln!("⚠️  SECURITY WARNING: Passing secrets as CLI arguments exposes them in process listings ('ps aux')");
                eprintln!("   and shell history files. Prefer 'secretguard vault set {}' (interactive/stdin).\n", key_name);
                args[2].clone()
            } else {
                use std::io::IsTerminal;
                if io::stdin().is_terminal() {
                    // Disable terminal echo (fail-closed if echo cannot be disabled)
                    let prompt = format!("Enter secret value for '{}' (input hidden): ", key_name);
                    match read_password_hidden(&prompt) {
                        Ok(val) => val,
                        Err(e) => {
                            eprintln!("❌ Security failure reading hidden secret: {}", e);
                            eprintln!("🛑 Aborting: SecretGuard refuses to read secrets with terminal echo enabled.");
                            process::exit(1);
                        }
                    }
                } else {
                    // Piped stdin
                    let mut buffer = String::new();
                    if let Err(e) = io::stdin().read_line(&mut buffer) {
                        eprintln!("❌ Failed to read secret from stdin: {}", e);
                        process::exit(1);
                    }
                    strip_line_terminator(&mut buffer);
                    buffer
                }
            };

            if secret_val.is_empty() {
                eprintln!("❌ Secret value cannot be empty.");
                process::exit(1);
            }

            // Finding 4: Never overwrite or default on a corrupted vault! Fail loudly to prevent data loss.
            let mut store = match load_vault(None) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("❌ FATAL: Cannot open vault: {}", e);
                    eprintln!("🛑 Aborting operation to prevent overwriting or destroying existing vault data.");
                    process::exit(1);
                }
            };

            store.secrets.insert(key_name.to_string(), secret_val);
            if let Err(e) = save_vault(&store, None) {
                eprintln!("❌ Failed to save secret: {}", e);
                process::exit(1);
            }
            println!("🔒 Successfully encrypted & stored '{}' in SecretGuard Vault (AES-256-GCM)!", key_name);
        }
        "get" => {
            if args.len() < 2 {
                eprintln!("Usage: secretguard vault get <KEY_NAME>");
                process::exit(2);
            }
            let key_name = &args[1];
            let store = match load_vault(None) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("❌ {}", e);
                    process::exit(1);
                }
            };

            if let Some(val) = store.secrets.get(key_name) {
                print!("{}", val);
            } else {
                eprintln!("❌ Secret '{}' not found in vault.", key_name);
                process::exit(1);
            }
        }
        "list" => {
            let store = match load_vault(None) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("❌ {}", e);
                    process::exit(1);
                }
            };

            println!("🔐 SecretGuard Encrypted Vault: ~/.secretguard/vault.enc\n");
            if store.secrets.is_empty() {
                println!("(Vault is currently empty. Use 'secretguard vault set <KEY>' to add secrets)");
            } else {
                println!("{:<25} {:<15}", "SECRET NAME", "ALGORITHM");
                println!("──────────────────────────────────────────");
                for key in store.secrets.keys() {
                    println!("{:<25} {:<15}", key, "AES-256-GCM");
                }
                println!("\nTotal Secrets Stored: {}", store.secrets.len());
            }
        }
        "delete" | "rm" => {
            if args.len() < 2 {
                eprintln!("Usage: secretguard vault delete <KEY_NAME>");
                process::exit(2);
            }
            let key_name = &args[1];

            // Finding 4: Never overwrite corrupted vault
            let mut store = match load_vault(None) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("❌ FATAL: Cannot open vault: {}", e);
                    eprintln!("🛑 Aborting operation to prevent data loss.");
                    process::exit(1);
                }
            };

            if store.secrets.remove(key_name).is_some() {
                if let Err(e) = save_vault(&store, None) {
                    eprintln!("❌ Failed to save vault after deletion: {}", e);
                    process::exit(1);
                }
                println!("🗑️  Removed '{}' from vault.", key_name);
            } else {
                eprintln!("❌ Secret '{}' not found.", key_name);
                process::exit(1);
            }
        }
        "run" => {
            let split_pos = args.iter().position(|a| a == "--");
            if split_pos.is_none() || split_pos.unwrap() == args.len() - 1 {
                eprintln!("Usage: secretguard vault run <KEY1> [KEY2...] -- <COMMAND> [ARGS...]");
                process::exit(2);
            }
            let pos = split_pos.unwrap();
            let key_names = &args[1..pos];
            let cmd_parts = &args[pos + 1..];

            let store = match load_vault(None) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("❌ {}", e);
                    process::exit(1);
                }
            };

            let mut env_injects = HashMap::new();
            for key in key_names {
                if let Some(val) = store.secrets.get(key) {
                    env_injects.insert(key.clone(), val.clone());
                } else {
                    eprintln!("⚠️  Warning: Vault key '{}' not found, running without it.", key);
                }
            }

            let child_cmd = &cmd_parts[0];
            let child_args = &cmd_parts[1..];

            println!("🔒 SecretGuard Vault: Injected {} secret(s) into memory for '{}'", env_injects.len(), child_cmd);

            let mut child = Command::new(child_cmd)
                .args(child_args)
                .envs(&env_injects)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|e| {
                    eprintln!("❌ Failed to execute command '{}': {}", child_cmd, e);
                    process::exit(1);
                });

            // Asynchronously sanitize child stderr using chunk/delimiter streaming with bounded overlap window
            // guaranteeing that credentials split across chunk boundaries are detected and redacted
            let stderr_opt = child.stderr.take();
            let stderr_thread = std::thread::spawn(move || {
                if let Some(stderr) = stderr_opt {
                    let mut reader = io::BufReader::new(stderr);
                    let stderr_handle = io::stderr();
                    let mut handle = stderr_handle.lock();
                    let local_engine = SecretGuardEngine::new();
                    let mut sanitizer = StreamSanitizer::new();
                    let mut buf = Vec::new();
                    while let Ok(n) = reader.read_until(b'\n', &mut buf) {
                        if n == 0 {
                            break;
                        }
                        let _ = sanitizer.sanitize_chunk(&buf, &local_engine, &mut handle);
                        buf.clear();
                    }
                    let _ = sanitizer.flush_final(&local_engine, &mut handle);
                }
            });

            if let Some(stdout) = child.stdout.take() {
                let mut reader = io::BufReader::new(stdout);
                let stdout_handle = io::stdout();
                let mut handle = stdout_handle.lock();
                let mut sanitizer = StreamSanitizer::new();
                let mut buf = Vec::new();
                while let Ok(n) = reader.read_until(b'\n', &mut buf) {
                    if n == 0 {
                        break;
                    }
                    let _ = sanitizer.sanitize_chunk(&buf, engine, &mut handle);
                    buf.clear();
                }
                let _ = sanitizer.flush_final(engine, &mut handle);
            }

            let _ = stderr_thread.join();
            let status = child.wait().expect("Child process was not running");

            // Finding 8: Accurate process exit status handling for Unix signals and Windows errors
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(code) = status.code() {
                    process::exit(code);
                } else if let Some(sig) = status.signal() {
                    process::exit(128 + sig);
                } else {
                    process::exit(1);
                }
            }
            #[cfg(not(unix))]
            {
                process::exit(status.code().unwrap_or(1));
            }
        }
        "import-env" => {
            let target_env = if args.len() >= 2 { &args[1] } else { ".env" };
            let env_path = Path::new(target_env);
            if !env_path.exists() {
                eprintln!("❌ File not found: {}", env_path.display());
                process::exit(1);
            }

            println!("📥 Importing secrets from '{}' into encrypted vault...", env_path.display());

            let file = match File::open(env_path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("❌ Failed to open '{}': {}", env_path.display(), e);
                    process::exit(1);
                }
            };
            let reader = io::BufReader::new(file);

            // Finding 4: Never overwrite or default on a corrupted vault
            let mut store = match load_vault(None) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("❌ FATAL: Cannot open vault: {}", e);
                    eprintln!("🛑 Aborting import to protect existing vault contents.");
                    process::exit(1);
                }
            };

            let mut imported = 0;
            let mut example_lines = Vec::new();

            // Finding 9: Robust .env parser handling export, quotes, inline comments, and syntax
            for line in reader.lines().flatten() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    example_lines.push(line);
                    continue;
                }

                // Strip leading 'export ' if present (common in bash env scripts)
                let clean_line = if trimmed.starts_with("export ") {
                    trimmed.strip_prefix("export ").unwrap_or(trimmed).trim()
                } else {
                    trimmed
                };

                if let Some((k, mut v)) = clean_line.split_once('=') {
                    let key = k.trim().to_string();

                    // Validate key identifier format
                    if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || key.is_empty() {
                        example_lines.push(line);
                        continue;
                    }

                    v = v.trim();

                    // Strip inline comment only if outside of quotes
                    let val = if (v.starts_with('"') && v.ends_with('"') && v.len() >= 2)
                        || (v.starts_with('\'') && v.ends_with('\'') && v.len() >= 2)
                    {
                        v[1..v.len() - 1].to_string()
                    } else if let Some((before_comment, _)) = v.split_once(" #") {
                        before_comment.trim().trim_matches('"').trim_matches('\'').to_string()
                    } else {
                        v.trim_matches('"').trim_matches('\'').to_string()
                    };

                    if !val.is_empty() {
                        store.secrets.insert(key.clone(), val);
                        imported += 1;
                        example_lines.push(format!("{}=YOUR_{}_HERE", key, key));
                    }
                }
            }

            if let Err(e) = save_vault(&store, None) {
                eprintln!("❌ Failed to save vault: {}", e);
                process::exit(1);
            }
            let example_path = env_path.with_file_name(".env.example");
            match File::create(&example_path) {
                Ok(mut out) => {
                    for l in example_lines {
                        let _ = writeln!(out, "{}", l);
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  Warning: Failed to create template file '{}': {}", example_path.display(), e);
                }
            }

            println!("✨ Successfully imported {} secret(s) into encrypted vault!", imported);
            println!("📄 Created clean template: {}", example_path.display());
            println!("🔒 Your secrets are now safe from git commits and shell leaks.");
        }
        _ => {
            eprintln!("Unknown vault subcommand: '{}'", args[0]);
            process::exit(2);
        }
    }
}
