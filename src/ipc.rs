//! Authenticated Local IPC Protocol & Service for SecretGuard
//!
//! Provides a secure, zero-trust inter-process communication protocol connecting:
//! - IDE extensions (VS Code, Cursor, Windsurf)
//! - Autonomous AI agents (Claude Code, Aider, Copilot, Cline)
//! - MCP servers and gateway daemons
//! - Local Security Broker (`src/broker.rs`)
//!
//! Security Properties:
//! - Authenticated sessions via ephemeral CSPRNG bearer tokens saved at 0o600
//! - Automatic caller identity verification (`IdentityContext`)
//! - Strict session registry with TTL expiry and peer validation
//! - Real loopback socket IPC transport
//! - All operations logged to tamper-evident audit ledger

use crate::broker::SecurityBroker;
use crate::identity::{IdentityContext, RequesterType};
use crate::policy::{AuthorizationDecision, OperationRequest, OperationType};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::Duration;

/// Maximum allowed IPC JSON request line size (64 KiB) to prevent memory exhaustion DoS
const MAX_IPC_REQUEST_BYTES: usize = 64 * 1024;
/// Per-connection IPC read/write timeout in seconds to prevent slow-client blocking DoS
const IPC_IO_TIMEOUT_SECS: u64 = 5;
/// Fixed worker pool thread count shared across every IPC listener
const IPC_WORKER_POOL_SIZE: usize = 16;
/// Fixed bounded queue capacity for pending accepted IPC connections
const IPC_QUEUE_CAPACITY: usize = 16;

/// IPC Message payload exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    /// Initial client handshake authenticating against the broker
    Authenticate {
        token: String,
        client_name: String,
        pid: u32,
    },
    /// Response to handshake
    AuthenticateResponse {
        authenticated: bool,
        session_id: String,
        message: String,
    },
    /// Request authorization evaluation for an operation
    AuthorizeRequest {
        session_id: String,
        credential_name: String,
        operation: String,
        target_resource: String,
    },
    /// Authorization decision returned by the broker
    AuthorizeResponse {
        decision: String,
        allowed: bool,
        audit_sequence: u64,
        details: Option<String>,
    },
    /// Request delegated execution (broker executes call, scrubs secrets, returns result)
    DelegatedCallRequest {
        session_id: String,
        credential_name: String,
        operation: String,
        target_resource: String,
    },
    /// Delegated execution response with masked/scrubbed secrets
    DelegatedCallResponse {
        status_code: u16,
        body: Vec<u8>,
        scrubbed_count: usize,
        audit_sequence: u64,
    },
    /// Error message
    Error { code: i32, message: String },
}

/// Active authenticated session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedSession {
    pub session_id: String,
    pub client_name: String,
    pub pid: u32,
    pub requester_type: RequesterType,
    pub executable_path: Option<std::path::PathBuf>,
    pub binary_hash: Option<String>,
    pub established_at: u64,
    pub last_active_at: u64,
}

/// IPC Server managing authenticated sessions and IPC transport
pub struct IpcServer {
    pub broker: SecurityBroker,
    pub expected_token: String,
    pub sessions: Arc<RwLock<HashMap<String, AuthenticatedSession>>>,
}

impl Default for IpcServer {
    fn default() -> Self {
        Self::new()
    }
}

impl IpcServer {
    pub fn try_new() -> Result<Self, String> {
        let expected_token = Self::get_or_create_token()
            .map_err(|e| format!("Security Fail-Closed: Cannot derive IPC token: {}", e))?;

        let broker = SecurityBroker::try_new()
            .map_err(|e| format!("Security Fail-Closed: Cannot initialize broker: {}", e))?;

        Ok(Self {
            broker,
            expected_token,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|e| {
            eprintln!("CRITICAL IPC FAILURE: {}", e);
            panic!("{}", e);
        })
    }

    /// Derives or creates local IPC authentication token stored securely in .secretguard/ipc.token (0o600)
    pub fn get_or_create_token() -> Result<String, std::io::Error> {
        let dir = crate::vault::get_vault_dir().map_err(std::io::Error::other)?;
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            }
        }
        crate::vault::validate_secure_path(&dir, false)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;

        let token_path = dir.join("ipc.token");

        // On Unix, reject an existing token file if its permissions were ever overly permissive,
        // because another local user could already have read the token before tightening.
        #[cfg(unix)]
        if let Ok(meta) = fs::symlink_metadata(&token_path) {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if meta.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Security Error: IPC token path is an untrusted symlink!",
                ));
            }
            if !meta.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Security Error: IPC token path is not a regular file!",
                ));
            }
            let active_uid = unsafe { libc::getuid() };
            if meta.uid() != active_uid {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Security Error: IPC token file is not owned by the active user!",
                ));
            }
            if (meta.permissions().mode() & 0o077) != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "Security Error: Existing IPC token '{}' has insecure permissions ({:o}); refusing potentially exposed token.",
                        token_path.display(),
                        meta.permissions().mode() & 0o777
                    ),
                ));
            }
        }

        if let Some(file) = crate::vault::open_secure_file_for_read(&token_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?
        {
            let mut content = String::new();
            file.take(256).read_to_string(&mut content)?;
            let trimmed = content.trim();
            if trimmed.len() >= 32 {
                return Ok(trimmed.to_string());
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Security Error: Existing IPC token is malformed or too short.",
            ));
        }

        // Generate 32-byte secure CSPRNG token
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let token = format!("sg_ipc_{}", hex_str);

        let mut file = crate::vault::create_secure_file_exclusive(&token_path, 0o600)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
        file.write_all(token.as_bytes())?;
        file.sync_all()?;

        Ok(token)
    }

    /// Validates an active session ID against session registry and TTL (3600s)
    pub fn validate_session(&self, session_id: &str) -> Result<AuthenticatedSession, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut registry = self.sessions.write().unwrap();
        if let Some(session) = registry.get_mut(session_id) {
            // Check session TTL (1 hour)
            if now.saturating_sub(session.last_active_at) > 3600 {
                registry.remove(session_id);
                return Err(
                    "Authentication Session Expired (TTL 3600s). Re-authenticate.".to_string(),
                );
            }
            session.last_active_at = now;
            Ok(session.clone())
        } else {
            Err("Authentication Required: Session expired or invalid (Session ID not found in broker registry).".to_string())
        }
    }

    /// Processes an incoming IPC message and returns the response
    pub fn handle_message(&self, msg: &IpcMessage) -> IpcMessage {
        self.handle_message_with_peer(msg, None)
    }

    /// Processes an incoming IPC message with kernel-verified peer PID validation
    pub fn handle_message_with_peer(&self, msg: &IpcMessage, peer_pid: Option<u32>) -> IpcMessage {
        match msg {
            IpcMessage::Authenticate {
                token,
                client_name: _client_name,
                pid,
            } => {
                if token != &self.expected_token {
                    return IpcMessage::AuthenticateResponse {
                        authenticated: false,
                        session_id: String::new(),
                        message: "Invalid IPC authentication token.".to_string(),
                    };
                }

                // Verify that client-claimed PID matches OS kernel peer PID to block spoofing
                let effective_pid = match peer_pid {
                    Some(os_pid) => {
                        if *pid != 0 && *pid != os_pid {
                            return IpcMessage::AuthenticateResponse {
                                authenticated: false,
                                session_id: String::new(),
                                message: format!(
                                    "Security Violation: PID spoofing detected! Claimed PID {} does not match kernel peer PID {}.",
                                    pid, os_pid
                                ),
                            };
                        }
                        os_pid
                    }
                    None => {
                        // Fail closed: Reject authentication when OS peer identity cannot be verified by kernel
                        return IpcMessage::AuthenticateResponse {
                            authenticated: false,
                            session_id: String::new(),
                            message: "Security Violation: Peer process identity unverified by OS kernel. Authentication rejected (Fail-Closed).".to_string(),
                        };
                    }
                };

                // Verify client PID through the OS kernel to prevent identity spoofing
                let verified_ident = match IdentityContext::from_pid(effective_pid) {
                    Ok(ident) => ident,
                    Err(e) => {
                        return IpcMessage::AuthenticateResponse {
                            authenticated: false,
                            session_id: String::new(),
                            message: format!(
                                "Security Violation: Kernel process verification failed for PID {} ({}).",
                                effective_pid, e
                            ),
                        };
                    }
                };

                let mut nonce = [0u8; 16];
                OsRng.fill_bytes(&mut nonce);
                let hex_nonce: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();
                let session_id = format!("sess_{}", hex_nonce);

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                let session = AuthenticatedSession {
                    session_id: session_id.clone(),
                    client_name: verified_ident.executable_name.clone(),
                    pid: effective_pid,
                    requester_type: verified_ident.requester_type,
                    executable_path: verified_ident.executable_path.clone(),
                    binary_hash: verified_ident.binary_hash.clone(),
                    established_at: now,
                    last_active_at: now,
                };

                self.sessions
                    .write()
                    .unwrap()
                    .insert(session_id.clone(), session);

                IpcMessage::AuthenticateResponse {
                    authenticated: true,
                    session_id,
                    message: format!(
                        "Authenticated as '{}' (PID {}, Trust Tier: {:?})",
                        verified_ident.executable_name, effective_pid, verified_ident.trust_tier
                    ),
                }
            }
            IpcMessage::AuthorizeRequest {
                session_id,
                credential_name,
                operation,
                target_resource,
            } => {
                let active_session = match self.validate_session(session_id) {
                    Ok(s) => s,
                    Err(e) => {
                        return IpcMessage::Error {
                            code: -32001,
                            message: e,
                        }
                    }
                };

                let op_type = parse_op_type(operation);
                let ident = session_to_identity(&active_session);
                let req = OperationRequest::new(ident, credential_name, op_type, target_resource);

                let decision = self.broker.authorize(&req);
                let allowed = matches!(
                    decision,
                    AuthorizationDecision::AllowDelegated | AuthorizationDecision::AllowRaw
                );
                let seq = self
                    .broker
                    .audit_ledger
                    .lock()
                    .ok()
                    .and_then(|l| l.records.last().map(|r| r.sequence_number))
                    .unwrap_or(0);

                let (dec_str, details) = match decision {
                    AuthorizationDecision::AllowDelegated => (
                        "AllowDelegated".to_string(),
                        Some("Delegated execution permitted via broker.".to_string()),
                    ),
                    AuthorizationDecision::AllowRaw => (
                        "AllowRaw".to_string(),
                        Some("Raw credential access permitted.".to_string()),
                    ),
                    AuthorizationDecision::RequireHumanApproval { prompt, .. } => {
                        ("RequireHumanApproval".to_string(), Some(prompt))
                    }
                    AuthorizationDecision::Deny { reason } => ("Deny".to_string(), Some(reason)),
                };

                IpcMessage::AuthorizeResponse {
                    decision: dec_str,
                    allowed,
                    audit_sequence: seq,
                    details,
                }
            }
            IpcMessage::DelegatedCallRequest {
                session_id,
                credential_name,
                operation,
                target_resource,
            } => {
                let active_session = match self.validate_session(session_id) {
                    Ok(s) => s,
                    Err(e) => {
                        return IpcMessage::Error {
                            code: -32001,
                            message: e,
                        }
                    }
                };

                let op_type = parse_op_type(operation);
                let ident = session_to_identity(&active_session);
                let req = OperationRequest::new(ident, credential_name, op_type, target_resource);

                match self.broker.execute_delegated_call(&req, None) {
                    Ok(resp) => IpcMessage::DelegatedCallResponse {
                        status_code: resp.status_code,
                        body: resp.body,
                        scrubbed_count: resp.scrubbed_tokens_count,
                        audit_sequence: resp.audit_sequence,
                    },
                    Err(e) => IpcMessage::Error {
                        code: -32003,
                        message: format!("Delegated execution failed: {}", e),
                    },
                }
            }
            _ => IpcMessage::Error {
                code: -32601,
                message: "Unsupported IPC message type.".to_string(),
            },
        }
    }

    /// Starts the authenticated IPC listener on a local loopback port in the background
    /// using a fixed-size bounded worker pool and bounded queue.
    pub fn start_background(self: Arc<Self>) -> Result<u16, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let server = Arc::clone(&self);

        std::thread::Builder::new()
            .name("secretguard-ipc-listener".to_string())
            .spawn(move || {
                run_bounded_ipc_pool(&server, listener.incoming().flatten(), process_tcp_stream);
            })?;

        Ok(port)
    }

    /// Runs local loopback TCP IPC transport listener with genuine OS peer verification
    /// and a fixed-size bounded worker pool.
    pub fn run_listener(&self, port: u16) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))?;
        println!(
            "🛡️  SecretGuard Authenticated IPC Service listening on 127.0.0.1:{}",
            port
        );

        run_bounded_ipc_pool(self, listener.incoming().flatten(), process_tcp_stream);
        Ok(())
    }

    #[cfg(unix)]
    /// Runs local Unix domain socket IPC transport listener with kernel-verified peer credentials
    /// and a fixed-size bounded worker pool.
    pub fn run_unix_socket_listener(&self, socket_path: &Path) -> Result<(), std::io::Error> {
        use std::os::unix::net::UnixListener;
        if socket_path.exists() {
            let _ = std::fs::remove_file(socket_path);
        }
        let listener = UnixListener::bind(socket_path)?;
        println!(
            "🛡️  SecretGuard Authenticated Unix Socket listening on {}",
            socket_path.display()
        );

        run_bounded_ipc_pool(self, listener.incoming().flatten(), |server, stream| {
            let timeout = Some(Duration::from_secs(IPC_IO_TIMEOUT_SECS));
            let _ = stream.set_read_timeout(timeout);
            let _ = stream.set_write_timeout(timeout);
            let peer_pid = get_unix_domain_peer_pid(&stream);
            handle_ipc_stream(server, stream, peer_pid);
        });
        Ok(())
    }
}

/// Processes an accepted loopback TCP stream with read/write timeouts and OS peer PID verification.
fn process_tcp_stream(server: &IpcServer, stream: TcpStream) {
    let timeout = Some(Duration::from_secs(IPC_IO_TIMEOUT_SECS));
    let _ = stream.set_read_timeout(timeout);
    let _ = stream.set_write_timeout(timeout);

    let peer_pid = match (stream.local_addr(), stream.peer_addr()) {
        (Ok(local), Ok(peer)) => {
            #[cfg(windows)]
            {
                get_tcp_peer_pid_tuple(local.port(), peer.port())
            }
            #[cfg(unix)]
            {
                get_unix_tcp_peer_pid(local.port(), peer.port())
            }
        }
        _ => None,
    };

    handle_ipc_stream(server, stream, peer_pid);
}

/// Shared bounded worker-pool dispatcher for all IPC listener transports.
/// Guarantees fixed worker thread count, bounded queue capacity, leak-free RAII connection
/// accounting, and safe non-blocking rejection when capacity is exceeded.
fn run_bounded_ipc_pool<S, I, F>(server: &IpcServer, incoming: I, handler: F)
where
    S: Read + Write + Send,
    I: Iterator<Item = S>,
    F: Fn(&IpcServer, S) + Sync,
{
    let (tx, rx) = mpsc::sync_channel::<S>(IPC_QUEUE_CAPACITY);
    let rx = Arc::new(Mutex::new(rx));
    let active_connections = Arc::new(AtomicUsize::new(0));
    let handler_ref = &handler;

    std::thread::scope(|scope| {
        for worker_id in 0..IPC_WORKER_POOL_SIZE {
            let rx_clone = Arc::clone(&rx);
            let active_clone = Arc::clone(&active_connections);
            let _ = std::thread::Builder::new()
                .name(format!("secretguard-ipc-worker-{}", worker_id))
                .spawn_scoped(scope, move || {
                    struct ConnGuard(Arc<AtomicUsize>);
                    impl Drop for ConnGuard {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::AcqRel);
                        }
                    }

                    loop {
                        let stream = {
                            let guard = match rx_clone.lock() {
                                Ok(g) => g,
                                Err(_) => break,
                            };
                            match guard.recv() {
                                Ok(s) => s,
                                Err(_) => break,
                            }
                        };

                        active_clone.fetch_add(1, Ordering::AcqRel);
                        let _conn_guard = ConnGuard(Arc::clone(&active_clone));
                        handler_ref(server, stream);
                    }
                });
        }

        for stream in incoming {
            if let Err(
                mpsc::TrySendError::Full(mut rejected)
                | mpsc::TrySendError::Disconnected(mut rejected),
            ) = tx.try_send(stream)
            {
                let err_msg = IpcMessage::Error {
                    code: -32000,
                    message: "Server busy: IPC worker pool capacity exceeded.".to_string(),
                };
                if let Ok(json) = serde_json::to_string(&err_msg) {
                    let _ = writeln!(rejected, "{}", json);
                    let _ = rejected.flush();
                }
            }
        }
        drop(tx);
    });
}

/// Reads a single newline-delimited IPC JSON request bounded to `max_bytes`.
fn read_bounded_ipc_line<R: Read>(reader: R, max_bytes: usize) -> std::io::Result<Option<String>> {
    let mut limited = BufReader::new(reader.take((max_bytes + 1) as u64));
    let mut line = String::new();
    let bytes_read = limited.read_line(&mut line)?;
    if bytes_read == 0 {
        return Ok(None);
    }
    if line.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "IPC request exceeds maximum allowed size of {} bytes",
                max_bytes
            ),
        ));
    }
    Ok(Some(line))
}

/// Handles a single IPC client stream with bounded request size and explicit error responses.
fn handle_ipc_stream<S: Read + Write>(server: &IpcServer, mut stream: S, peer_pid: Option<u32>) {
    match read_bounded_ipc_line(&mut stream, MAX_IPC_REQUEST_BYTES) {
        Ok(Some(line)) => {
            let resp_msg = match serde_json::from_str::<IpcMessage>(line.trim()) {
                Ok(req_msg) => server.handle_message_with_peer(&req_msg, peer_pid),
                Err(_) => IpcMessage::Error {
                    code: -32700,
                    message: "Invalid IPC JSON request.".to_string(),
                },
            };
            let resp_json = serde_json::to_string(&resp_msg).unwrap_or_default();
            let _ = writeln!(stream, "{}", resp_json);
            let _ = stream.flush();
        }
        Ok(None) => {}
        Err(e) => {
            let resp_msg = IpcMessage::Error {
                code: -32600,
                message: format!("IPC request rejected: {}", e),
            };
            let resp_json = serde_json::to_string(&resp_msg).unwrap_or_default();
            let _ = writeln!(stream, "{}", resp_json);
            let _ = stream.flush();
        }
    }
}

#[cfg(windows)]
fn get_tcp_peer_pid_tuple(server_port: u16, client_port: u16) -> Option<u32> {
    #[repr(C)]
    struct MIB_TCPROW_OWNER_PID {
        state: u32,
        local_addr: u32,
        local_port: u32,
        remote_addr: u32,
        remote_port: u32,
        owning_pid: u32,
    }

    #[repr(C)]
    struct MIB_TCPTABLE_OWNER_PID {
        num_entries: u32,
        table: [MIB_TCPROW_OWNER_PID; 1],
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedTcpTable(
            pTcpTable: *mut std::ffi::c_void,
            pdwSize: *mut u32,
            bOrder: i32,
            ulAf: u32,
            tableClass: u32,
            reserved: u32,
        ) -> u32;
    }

    const AF_INET: u32 = 2;
    const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    const MIB_TCP_STATE_ESTAB: u32 = 5;

    let mut size: u32 = 0;
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    if size == 0 {
        return None;
    }

    let mut buf: Vec<u8> = vec![0; size as usize];
    let ret = unsafe {
        GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if ret != 0 {
        return None;
    }

    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let entries = table.num_entries as usize;
    let ptr = buf.as_ptr() as usize + std::mem::size_of::<u32>();
    let rows = unsafe { std::slice::from_raw_parts(ptr as *const MIB_TCPROW_OWNER_PID, entries) };

    for row in rows {
        if row.state == MIB_TCP_STATE_ESTAB {
            let row_local_port = u16::from_be(row.local_port as u16);
            let row_remote_port = u16::from_be(row.remote_port as u16);
            // Verify complete 4-tuple on loopback connection:
            // 127.0.0.1 in network byte order is 0x0100007f (in little-endian memory)
            let is_loopback = (row.local_addr == 0x0100007f || row.local_addr == 0x7f000001)
                && (row.remote_addr == 0x0100007f || row.remote_addr == 0x7f000001);
            if is_loopback && row_local_port == client_port && row_remote_port == server_port {
                return Some(row.owning_pid);
            }
        }
    }
    None
}

#[cfg(unix)]
fn get_unix_tcp_peer_pid(server_port: u16, client_port: u16) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        find_linux_tcp_peer_pid(server_port, client_port)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (server_port, client_port);
        None
    }
}

#[cfg(all(unix, target_os = "linux"))]
fn find_linux_tcp_peer_pid(server_port: u16, client_port: u16) -> Option<u32> {
    let tcp_file = std::fs::read_to_string("/proc/net/tcp").ok()?;
    let client_hex = format!("{:04X}", client_port);
    let server_hex = format!("{:04X}", server_port);
    // Verify complete 4-tuple on Linux loopback
    let expected_client_endpoint = format!("0100007F:{}", client_hex);
    let expected_server_endpoint = format!("0100007F:{}", server_hex);

    let mut target_inode = None;
    for line in tcp_file.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 10 {
            let local_part = parts[1];
            let rem_part = parts[2];
            let state = parts[3];
            // State 01 is TCP_ESTABLISHED
            if state == "01"
                && local_part.eq_ignore_ascii_case(&expected_client_endpoint)
                && rem_part.eq_ignore_ascii_case(&expected_server_endpoint)
            {
                target_inode = parts[9].parse::<u64>().ok();
                break;
            }
        }
    }

    let inode = target_inode?;
    let inode_str = format!("socket:[{}]", inode);

    // Search /proc/*/fd/* for matching socket inode
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        if let Ok(file_name) = entry.file_name().into_string() {
            if let Ok(pid) = file_name.parse::<u32>() {
                let fd_dir = entry.path().join("fd");
                if let Ok(fds) = std::fs::read_dir(fd_dir) {
                    for fd_entry in fds.flatten() {
                        if let Ok(target) = std::fs::read_link(fd_entry.path()) {
                            if target.to_string_lossy() == inode_str {
                                return Some(pid);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(unix)]
fn get_unix_domain_peer_pid(stream: &std::os::unix::net::UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    #[cfg(target_os = "linux")]
    unsafe {
        let mut ucred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let res = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if res == 0 && ucred.pid > 0 {
            Some(ucred.pid as u32)
        } else {
            None
        }
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    unsafe {
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        let res = libc::getsockopt(
            fd,
            0,
            libc::LOCAL_PEEREPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if res == 0 && pid > 0 {
            return Some(pid as u32);
        }
        None
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    None
}

/// Client helper: sends an authenticated IPC message across loopback socket
pub fn send_ipc_request(port: u16, msg: &IpcMessage) -> Result<IpcMessage, String> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .map_err(|e| format!("Failed to connect to SecretGuard IPC service: {}", e))?;

    let json_req = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    writeln!(stream, "{}", json_req).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("Failed to read IPC response: {}", e))?;

    serde_json::from_str::<IpcMessage>(line.trim())
        .map_err(|e| format!("Invalid IPC response: {}", e))
}

fn session_to_identity(session: &AuthenticatedSession) -> IdentityContext {
    IdentityContext {
        pid: session.pid,
        ppid: None,
        executable_name: session.client_name.clone(),
        executable_path: session.executable_path.clone(),
        binary_hash: session.binary_hash.clone(),
        lineage: vec![session.client_name.clone()],
        requester_type: session.requester_type,
        trust_tier: match session.requester_type {
            RequesterType::HumanInteractive => crate::identity::TrustTier::Tier3Privileged,
            RequesterType::ApprovedIde => crate::identity::TrustTier::Tier2StandardAgent,
            RequesterType::AutonomousAgent => crate::identity::TrustTier::Tier2StandardAgent,
            RequesterType::McpServer => crate::identity::TrustTier::Tier1Restricted,
            RequesterType::BuildOrScript => crate::identity::TrustTier::Tier1Restricted,
            RequesterType::UnknownProcess => crate::identity::TrustTier::Tier0Blocked,
        },
        trust_score: match session.requester_type {
            RequesterType::HumanInteractive => 90,
            RequesterType::ApprovedIde => 75,
            RequesterType::AutonomousAgent => 65,
            RequesterType::McpServer => 45,
            RequesterType::BuildOrScript => 35,
            RequesterType::UnknownProcess => 10,
        },
        is_interactive_tty: session.requester_type == RequesterType::HumanInteractive,
        working_dir: std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
        git_repo: crate::identity::detect_current_git_repo(
            &std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
        ),
    }
}

fn parse_op_type(op: &str) -> OperationType {
    match op.to_uppercase().as_str() {
        "GET" | "HTTPGET" => OperationType::HttpGet,
        "POST" | "HTTPPOST" => OperationType::HttpPost,
        "PUT" | "HTTPPUT" => OperationType::HttpPut,
        "DELETE" | "HTTPDELETE" => OperationType::HttpDelete,
        "FETCH" | "GIT:FETCH" => OperationType::GitFetch,
        "PUSH" | "GIT:PUSH" => OperationType::GitPush,
        "RAW" | "RAW:READ" => OperationType::RawCredentialAccess,
        other => OperationType::McpToolCall(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_authentication_handshake_and_session_registration() {
        let _lock = crate::vault::TERMINAL_INPUT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp_dir = std::env::temp_dir().join(format!("sg_ipc_unit_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        std::env::set_var("SECRETGUARD_DIR", &temp_dir);

        let server = IpcServer::new();
        let correct_token = server.expected_token.clone();
        let current_pid = std::process::id();

        // 1. Wrong token fails
        let fail_msg = IpcMessage::Authenticate {
            token: "invalid_token".to_string(),
            client_name: "test_agent".to_string(),
            pid: current_pid,
        };
        let res = server.handle_message(&fail_msg);
        match res {
            IpcMessage::AuthenticateResponse { authenticated, .. } => assert!(!authenticated),
            _ => panic!("Expected AuthenticateResponse"),
        }

        // 2. Spoofed non-existent PID fails closed
        let spoof_msg = IpcMessage::Authenticate {
            token: correct_token.clone(),
            client_name: "spoofed_agent".to_string(),
            pid: 9999999,
        };
        let spoof_res = server.handle_message_with_peer(&spoof_msg, Some(9999999));
        match spoof_res {
            IpcMessage::AuthenticateResponse {
                authenticated,
                message,
                ..
            } => {
                assert!(!authenticated);
                assert!(message.contains("Kernel process verification failed"));
            }
            _ => panic!("Expected AuthenticateResponse"),
        }

        // 2b. Missing OS peer verification (None) fails closed
        let unverified_res = server.handle_message(&spoof_msg);
        match unverified_res {
            IpcMessage::AuthenticateResponse {
                authenticated,
                message,
                ..
            } => {
                assert!(!authenticated);
                assert!(message.contains("Peer process identity unverified"));
            }
            _ => panic!("Expected AuthenticateResponse"),
        }

        // 3. Correct token and valid verified PID succeeds and registers session
        let ok_msg = IpcMessage::Authenticate {
            token: correct_token,
            client_name: "claude-code".to_string(),
            pid: current_pid,
        };
        let res = server.handle_message_with_peer(&ok_msg, Some(current_pid));
        let session_id = match res {
            IpcMessage::AuthenticateResponse {
                authenticated,
                session_id,
                ..
            } => {
                assert!(authenticated);
                assert!(session_id.starts_with("sess_"));
                session_id
            }
            _ => panic!("Expected AuthenticateResponse"),
        };

        // 4. Authenticated session permits authorize call on caller's repository
        let caller_repo = crate::identity::IdentityContext::from_pid(current_pid)
            .ok()
            .and_then(|id| id.git_repo)
            .unwrap_or_else(|| "org/repo".to_string());
        let target_url = format!("https://api.github.com/repos/{}/pulls", caller_repo);
        let auth_op = IpcMessage::AuthorizeRequest {
            session_id: session_id.clone(),
            credential_name: "GITHUB_TOKEN".to_string(),
            operation: "GET".to_string(),
            target_resource: target_url,
        };
        let op_res = server.handle_message(&auth_op);
        match op_res {
            IpcMessage::AuthorizeResponse { allowed, .. } => assert!(allowed),
            _ => panic!("Expected AuthorizeResponse"),
        }

        // 5. Fake session ID fails closed
        let fake_op = IpcMessage::AuthorizeRequest {
            session_id: "sess_fake_unregistered_id".to_string(),
            credential_name: "GITHUB_TOKEN".to_string(),
            operation: "GET".to_string(),
            target_resource: "https://api.github.com".to_string(),
        };
        let fake_res = server.handle_message(&fake_op);
        match fake_res {
            IpcMessage::Error { code, .. } => assert_eq!(code, -32001),
            _ => panic!("Expected Error code -32001 for fake session"),
        }

        std::env::remove_var("SECRETGUARD_DIR");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_ipc_bounded_request_line_rejects_oversized_payload() {
        let valid = b"{\"hello\":1}\n";
        let ok = read_bounded_ipc_line(&valid[..], 64).expect("Valid line should succeed");
        assert_eq!(ok.as_deref(), Some("{\"hello\":1}\n"));

        let oversized = [b'A'; 128];
        let err = read_bounded_ipc_line(&oversized[..], 64)
            .expect_err("Oversized line without newline must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_ipc_listener_pool_concurrent_slow_client_and_oversized_rejection() {
        let _lock = crate::vault::TERMINAL_INPUT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp_dir = std::env::temp_dir().join(format!("sg_ipc_pool_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o700));
        }
        std::env::set_var("SECRETGUARD_DIR", &temp_dir);

        let server = Arc::new(IpcServer::new());
        let port = Arc::clone(&server)
            .start_background()
            .expect("Background IPC pool should bind");

        // 1. Open slow clients that never send a newline (would stall a synchronous listener)
        let mut slow_clients = Vec::new();
        for _ in 0..3 {
            let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
            let _ = s.write_all(b"{\"partial\":");
            slow_clients.push(s);
        }

        // 2. A fast client sending an oversized payload must still be served concurrently and rejected
        let mut fast_client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let _ = fast_client.set_read_timeout(Some(Duration::from_secs(3)));
        let big = vec![b'X'; MAX_IPC_REQUEST_BYTES + 1];
        let _ = fast_client.write_all(&big);
        let _ = fast_client.flush();

        let mut resp_line = String::new();
        let mut reader = BufReader::new(fast_client);
        let _ = reader.read_line(&mut resp_line);
        assert!(
            resp_line.contains("-32600") && resp_line.contains("exceeds maximum allowed size"),
            "Expected oversized rejection error, got: {}",
            resp_line
        );

        drop(slow_clients);
        std::env::remove_var("SECRETGUARD_DIR");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
