//! `passbox phone`: enrolling the iPhone that approves when Touch ID goes unanswered.

use crate::broker::{self, ENROLL_SECS, PhoneWrap, SERVE, Timing};
use crate::store::Store;
use crate::{headless, tailnet};
use anyhow::{Context, Result, bail};
use std::time::{Duration, Instant};

/* The Mac opens a window and shows a code. The phone dials in over the tailnet with the code and
the public half of a key it made in its own Secure Enclave, and a fingerprint here wraps the store
key to it. One approval on the phone then proves the pairing, and a pairing that fails the proof
is removed, so the phone is never trusted on the strength of a file. */
pub(crate) fn phone_add(store: &Store) -> Result<()> {
    if headless() || !store.has_se_wrap() {
        bail!("a phone approves alongside Touch ID, and this store is not bound to this Mac");
    }
    let address = tailnet::address()
        .context("Tailscale is not up on this Mac, and the phone reaches the broker over it")?;
    let this_mac = tailnet::whois(address).unwrap_or_else(|| address.to_string());

    let code = broker::phone_open(store)?;
    eprintln!("On the iPhone, open passbox and enter:");
    eprintln!("  Mac   {this_mac}");
    eprintln!("  Code  {code}");
    eprintln!("Then touch the sensor here when this Mac asks to let the phone approve reads.");
    eprintln!("If the phone cannot connect, expose the broker once with:\n  {SERVE}");

    let until = Instant::now() + Duration::from_secs(ENROLL_SECS);
    let phone = loop {
        if let Some(phone) = PhoneWrap::load(store) {
            break phone;
        }
        if Instant::now() >= until {
            bail!("no phone enrolled within {ENROLL_SECS}s, run `passbox phone add` again");
        }
        std::thread::sleep(Duration::from_millis(250));
    };

    eprintln!(
        "enrolled {}, approve the test request on it now",
        phone.node
    );
    if let Err(e) = broker::phone_test(store) {
        std::fs::remove_file(store.phone_wrap_path())?;
        return Err(e.context("the phone did not prove it can approve, so it was removed"));
    }
    let after = Timing::read(store)?.after.as_secs();
    eprintln!(
        "{} can approve. It is asked once Touch ID has gone unanswered for {after}s, and at \
         once when the lid is closed",
        phone.node
    );
    Ok(())
}

pub(crate) fn phone_ls(store: &Store) {
    match PhoneWrap::load(store) {
        Some(phone) => println!("{}", phone.node),
        None => eprintln!("no phone is enrolled on this Mac"),
    }
}

/// Deleting the wrap is the whole removal: the phone's key then has nothing here to open
pub(crate) fn phone_rm(store: &Store) -> Result<()> {
    let Some(phone) = PhoneWrap::load(store) else {
        bail!("no phone is enrolled on this Mac");
    };
    std::fs::remove_file(store.phone_wrap_path())?;
    let caller = broker::own_ancestry();
    broker::append_audit(store, &phone.node, "<phone>", "removed", &caller, "")?;
    eprintln!("removed {}, it can no longer approve", phone.node);
    Ok(())
}
