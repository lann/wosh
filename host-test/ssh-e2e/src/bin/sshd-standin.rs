//! The sshd stand-in as its own process, for harnesses that live
//! outside this crate (the M7 browser leg drives the page from node).
//! Prints the facts the harness needs on stdout, one per line:
//!
//!   standin: port=<p> fp=<base64 sha256>
//!   password-attempts: <n>        (on every change)
//!
//! SIGTERM/SIGINT reap the mosh-servers the exec channel detached
//! (mosh-server daemonizes; nothing else ever reaps these).

use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use ssh_e2e::standin;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    env_logger::init();
    let standin = standin::start().await?;
    println!("standin: port={} fp={}", standin.port, standin.host_key_fp);

    let attempts = standin.password_attempts.clone();
    tokio::spawn(async move {
        let mut last = 0u32;
        loop {
            let now = attempts.load(Ordering::SeqCst);
            if now != last {
                last = now;
                println!("password-attempts: {now}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = term.recv() => {},
        _ = tokio::signal::ctrl_c() => {},
    }
    for pid in standin.spawned_pids.lock().unwrap().drain(..) {
        println!("reaping spawned pid {pid}");
        let _ = std::process::Command::new("kill")
            .arg(pid.to_string())
            .stderr(std::process::Stdio::null())
            .status();
    }
    Ok(())
}
