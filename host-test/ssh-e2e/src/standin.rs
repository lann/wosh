//! An in-process sshd stand-in for the M7 gate: enough of SSH server
//! semantics (host key, password auth, exec) to drive the composed
//! client's inner-ssh path (x/crypto/ssh compiled to wasm) without a
//! real sshd. Synthetic test credentials only (testuser/testpass);
//! this is a defensive test harness, not production auth.

use std::process::Stdio;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use base64::Engine as _;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Handle, Msg, Server as _, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::TcpListener;

const TEST_USER: &str = "testuser";
const TEST_PASSWORD: &str = "testpass";

/// Handle to the running stand-in and its observable state.
pub struct Standin {
    pub port: u16,
    /// base64 (standard, padded) SHA-256 over the RFC 4253 wire-format
    /// public-key blob — the same fingerprint format the client
    /// engine computes (Go's `key.Marshal()` + sha256 + base64
    /// StdEncoding). NOT russh's own `SHA256:<b64-nopad>` string.
    pub host_key_fp: String,
    /// Incremented only on `auth_password` attempts (never `auth_none`
    /// probes) — the M7 gate asserts this stays 0 when the client
    /// correctly refuses to send credentials to an unpinned host key.
    pub password_attempts: Arc<AtomicU32>,
    /// PIDs parsed from `detached, pid = <N>` on an exec'd child's
    /// stderr (mosh-server daemonizes; nothing else reaps these).
    pub spawned_pids: Arc<Mutex<Vec<u32>>>,
}

/// Compute the fingerprint format documented on [`Standin::host_key_fp`].
fn wire_fingerprint(key: &PrivateKey) -> Result<String> {
    let blob = key
        .public_key()
        .to_bytes()
        .context("encoding host public key to RFC 4253 wire bytes")?;
    let digest = Sha256::digest(&blob);
    Ok(base64::engine::general_purpose::STANDARD.encode(digest))
}

#[derive(Clone)]
struct StandinServer {
    password_attempts: Arc<AtomicU32>,
    spawned_pids: Arc<Mutex<Vec<u32>>>,
}

impl server::Server for StandinServer {
    type Handler = ClientHandler;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> ClientHandler {
        ClientHandler {
            password_attempts: self.password_attempts.clone(),
            spawned_pids: self.spawned_pids.clone(),
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as server::Handler>::Error) {
        log::debug!("[standin] session error: {error:?}");
    }
}

struct ClientHandler {
    password_attempts: Arc<AtomicU32>,
    spawned_pids: Arc<Mutex<Vec<u32>>>,
}

impl server::Handler for ClientHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        // x/crypto/ssh always probes "none" first; it must not count
        // as a password attempt. Steer the client at password auth.
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
            partial_success: false,
        })
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.password_attempts.fetch_add(1, Ordering::SeqCst);
        if user == TEST_USER && password == TEST_PASSWORD {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).to_string();
        // Ack the exec request itself; the command's actual output and
        // exit status stream over the channel independently, from the
        // spawned task below (this matches how a real sshd's exec
        // channel behaves: SSH_MSG_CHANNEL_SUCCESS just confirms the
        // request was understood, not that the command has finished).
        session.channel_success(channel)?;

        let handle = session.handle();
        let spawned_pids = self.spawned_pids.clone();
        tokio::spawn(async move {
            if let Err(e) = run_exec(command, channel, handle, spawned_pids).await {
                log::warn!("[standin] exec task failed: {e:?}");
            }
        });
        Ok(())
    }
}

/// Run `sh -c <command>`, streaming stdout as channel data and stderr
/// as extended data (type 1), scanning stderr for mosh-server's
/// `detached, pid = <N>` daemonization marker so the harness can reap
/// it at teardown.
async fn run_exec(
    command: String,
    channel: ChannelId,
    handle: Handle,
    spawned_pids: Arc<Mutex<Vec<u32>>>,
) -> Result<()> {
    let mut child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&command)
        .env("LC_ALL", "C.UTF-8")
        .env("TERM", "xterm-256color")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning `sh -c {command}`"))?;

    let mut stdout = child.stdout.take().context("child stdout")?;
    let stderr = child.stderr.take().context("child stderr")?;

    let handle_out = handle.clone();
    let stdout_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if handle_out.data(channel, buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let handle_err = handle.clone();
    let stderr_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    if let Some(pid) = parse_detached_pid(&line) {
                        spawned_pids.lock().unwrap().push(pid);
                    }
                    if handle_err
                        .extended_data(channel, 1, line.as_bytes().to_vec())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let status = child.wait().await.context("waiting for exec'd child")?;
    let _ = stdout_task.await;
    let _ = stderr_task.await;

    let code = status.code().unwrap_or(1) as u32;
    let _ = handle.exit_status_request(channel, code).await;
    let _ = handle.eof(channel).await;
    let _ = handle.close(channel).await;
    Ok(())
}

/// Parse `detached, pid = <N>` (mosh-server's daemonization line) out
/// of a stderr line, wherever it appears in the text.
fn parse_detached_pid(line: &str) -> Option<u32> {
    let ix = line.find("detached, pid = ")?;
    let tail = &line[ix + "detached, pid = ".len()..];
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Start the stand-in, bound on an ephemeral loopback port.
pub async fn start() -> Result<Standin> {
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .context("generating ed25519 host key")?;
    let host_key_fp = wire_fingerprint(&host_key)?;

    let config = Arc::new(server::Config {
        auth_rejection_time: std::time::Duration::from_millis(0),
        auth_rejection_time_initial: Some(std::time::Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    });

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("binding standin listener")?;
    let port = listener.local_addr()?.port();

    let password_attempts = Arc::new(AtomicU32::new(0));
    let spawned_pids = Arc::new(Mutex::new(Vec::new()));

    let password_attempts_task = password_attempts.clone();
    let spawned_pids_task = spawned_pids.clone();
    tokio::spawn(async move {
        // `server` and `listener` must both outlive the accept loop
        // (run_on_socket's future borrows the listener), so everything
        // lives inside this single task rather than being split up.
        let mut server = StandinServer {
            password_attempts: password_attempts_task,
            spawned_pids: spawned_pids_task,
        };
        if let Err(e) = server.run_on_socket(config, &listener).await {
            log::debug!("[standin] server loop ended: {e:?}");
        }
    });

    Ok(Standin {
        port,
        host_key_fp,
        password_attempts,
        spawned_pids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confidence check on the stand-in itself: dial it with a real
    /// russh client, authenticate, exec a command that both prints
    /// output and emits the `detached, pid = ...` marker mosh-server
    /// uses, and assert data + exit status + pid parsing all work.
    #[tokio::test]
    async fn standin_exec_round_trip() {
        let standin = start().await.expect("start standin");

        struct ClientHandler;
        impl russh::client::Handler for ClientHandler {
            type Error = russh::Error;
            async fn check_server_key(
                &mut self,
                _server_public_key: &russh::keys::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        let config = Arc::new(russh::client::Config::default());
        let mut session = russh::client::connect(
            config,
            ("127.0.0.1", standin.port),
            ClientHandler,
        )
        .await
        .expect("connect to standin");

        assert!(
            session
                .authenticate_password(TEST_USER, TEST_PASSWORD)
                .await
                .expect("auth request")
                .success(),
            "password auth should succeed with correct test credentials"
        );

        let mut channel = session.channel_open_session().await.expect("open channel");
        channel
            .exec(
                true,
                "printf 'hello\\n' 1>&1; printf 'detached, pid = 4194303\\n' 1>&2; exit 0",
            )
            .await
            .expect("exec");

        let mut stdout_data = Vec::new();
        let mut stderr_data = Vec::new();
        let mut exit_status = None;
        loop {
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                russh::ChannelMsg::Data { ref data } => stdout_data.extend_from_slice(data),
                russh::ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    stderr_data.extend_from_slice(data)
                }
                russh::ChannelMsg::ExitStatus { exit_status: code } => {
                    exit_status = Some(code);
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }

        assert_eq!(String::from_utf8_lossy(&stdout_data), "hello\n");
        assert!(String::from_utf8_lossy(&stderr_data).contains("detached, pid = 4194303"));
        assert_eq!(exit_status, Some(0));
        assert_eq!(
            standin.spawned_pids.lock().unwrap().as_slice(),
            &[4194303]
        );
    }
}
