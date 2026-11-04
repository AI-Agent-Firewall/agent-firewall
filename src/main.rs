use agent_firewall_core::reload::PolicyManager;
use anyhow::{Result, bail};
use std::sync::mpsc;

fn main() {
    if let Err(error) = run() {
        eprintln!("policy subsystem failed: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let path = args.next().unwrap_or_else(|| "configs/policy.yaml".into());
    if args.next().is_some() {
        bail!("usage: agent-firewall-core [policy-path]");
    }
    let (stop_tx, stop_rx) = mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = stop_tx.send(());
    })?;
    let manager = PolicyManager::start(path)?;
    let active = manager.reader().snapshot();
    eprintln!(
        "policy active: id={} last_updated={} rules={} sinks={}; Ctrl-C to stop",
        active.policy_id(),
        active.last_updated(),
        active.rules().len(),
        active.sinks().len()
    );
    stop_rx.recv()?;
    drop(manager);
    Ok(())
}
