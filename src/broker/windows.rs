//! Approval windows: a plugin call or an SSH login that a recent prompt already covers.

use crate::{plugin, ssh};
use std::collections::HashMap;

/// The SHA256 fingerprints of the signing key and of the host key it signs logins to
pub(super) type SshWindowKey = (String, String);

/// One key opened for one host key. It holds the private key as a token holds its values, so a
/// signature under it needs no prompt and no store key, which is what a locked screen needs
pub(super) struct SshWindow {
    pub(super) opened: u64,
    /// The `[ssh.windows]` name it was opened under, which sets its length on every call
    pub(super) host: String,
    /// The secret the key is stored under, for the audit
    pub(super) name: String,
    pub(super) private: Box<ssh_key::PrivateKey>,
}

/* A signing window covers a later login with the same key to the same host key while the approved
section still lists the name it opened under. Pinned to the host key, so another server that
claims the name in known_hosts gets a prompt. Split out so it can be tested without a prompt */
pub(super) fn ssh_window_open<'a>(
    windows: &'a HashMap<SshWindowKey, SshWindow>,
    policy: &ssh::Windows,
    approved: Option<&str>,
    key: &SshWindowKey,
    now: u64,
) -> Option<&'a SshWindow> {
    if approved != Some(policy.hash.as_str()) {
        return None;
    }

    let window = windows.get(key)?;
    let secs = policy.hosts.get(&window.host)?;
    (now < window.opened.saturating_add(*secs)).then_some(window)
}

pub(super) fn fingerprint(key: &ssh_key::PublicKey) -> String {
    key.fingerprint(ssh_key::HashAlg::Sha256).to_string()
}

/// Caller scope, tool, and the exact call from `Tool::call`
pub(super) type WindowKey = (String, String, String);

/// Each distinct call is its own window, so this caps what one scope can hold
const MAX_WINDOWS_PER_SCOPE: usize = 256;

/// One call opened for one caller scope, with a fed plugin's secret held as a token holds its values
pub(super) struct Window {
    pub(super) opened: u64,
    pub(super) secret: Option<String>,
}

/* A window covers a later call of the same tool with the same arguments from the same scope while
the approved section still lists it. The length is read from the section on each call, so a
shortened window ends sooner. Split out so scope and expiry can be tested without a prompt */
pub(super) fn window_open<'a>(
    windows: &'a HashMap<WindowKey, Window>,
    policy: &plugin::Windows,
    approved: Option<&str>,
    scope: &str,
    tool: &str,
    call: &str,
    now: u64,
) -> Option<&'a Window> {
    if approved != Some(policy.hash.as_str()) {
        return None;
    }
    let secs = policy.tools.get(tool)?;
    windows
        .get(&(scope.to_string(), tool.to_string(), call.to_string()))
        .filter(|w| now < w.opened.saturating_add(*secs))
}

/// A full scope drops its oldest window first
pub(super) fn open_window(
    windows: &mut HashMap<WindowKey, Window>,
    key: WindowKey,
    window: Window,
) {
    let full = windows.keys().filter(|k| k.0 == key.0).count() >= MAX_WINDOWS_PER_SCOPE;
    if full && !windows.contains_key(&key) {
        let oldest = windows
            .iter()
            .filter(|(k, _)| k.0 == key.0)
            .min_by_key(|(_, w)| w.opened)
            .map(|(k, _)| k.clone());
        if let Some(oldest) = oldest {
            windows.remove(&oldest);
        }
    }
    windows.insert(key, window);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::private::Ed25519Keypair;

    #[test]
    fn a_signing_window_covers_its_host_key_until_it_lapses_or_the_section_changes() {
        let policy = ssh::parse_windows("[ssh.windows]\nlegion = \"1h\"\n").unwrap();
        let pair = Ed25519Keypair::from_seed(&[3; 32]);
        let private = ssh_key::PrivateKey::new(pair.into(), "").unwrap();
        let mut windows = HashMap::new();
        let key = ("key".to_string(), "SHA256:legion".to_string());
        windows.insert(
            key.clone(),
            SshWindow {
                opened: 1_000,
                host: "legion".into(),
                name: "ssh/legion".into(),
                private: Box::new(private),
            },
        );
        let hash = Some(policy.hash.as_str());
        let open = |k: &SshWindowKey, approved, now| {
            ssh_window_open(&windows, &policy, approved, k, now).is_some()
        };
        assert!(open(&key, hash, 1_000 + 3_599));
        assert!(!open(&key, hash, 1_000 + 3_600));
        // Another host key that claims the name has no window of its own
        assert!(!open(&("key".into(), "SHA256:evil".into()), hash, 1_001));
        assert!(!open(&key, None, 1_001));
        assert!(!open(&key, Some("an older section"), 1_001));

        let dropped = ssh::parse_windows("[ssh.windows]\nm1 = \"1h\"\n").unwrap();
        assert!(ssh_window_open(&windows, &dropped, Some(&dropped.hash), &key, 1_001).is_none());
        let shorter = ssh::parse_windows("[ssh.windows]\nlegion = \"10m\"\n").unwrap();
        assert!(ssh_window_open(&windows, &shorter, Some(&shorter.hash), &key, 1_599).is_some());
        assert!(ssh_window_open(&windows, &shorter, Some(&shorter.hash), &key, 1_600).is_none());
    }

    fn policy(tool: &str, secs: u64) -> plugin::Windows {
        plugin::Windows {
            tools: [(tool.to_string(), secs)].into(),
            hash: "approved".into(),
        }
    }

    fn opened(scope: &str, tool: &str, at: u64) -> HashMap<WindowKey, Window> {
        HashMap::from([(
            (scope.to_string(), tool.to_string(), "call".to_string()),
            Window {
                opened: at,
                secret: None,
            },
        )])
    }

    #[test]
    fn a_window_covers_its_tool_until_it_ends() {
        let windows = opened("local", "things3.logbook", 1_000);
        let full = policy("things3.logbook", 60);
        let open = |policy: &plugin::Windows, tool: &str, now| {
            window_open(
                &windows,
                policy,
                Some("approved"),
                "local",
                tool,
                "call",
                now,
            )
            .is_some()
        };
        assert!(open(&full, "things3.logbook", 1_000));
        assert!(open(&full, "things3.logbook", 1_059));
        assert!(!open(&full, "things3.logbook", 1_060), "an ended window");
        assert!(!open(&full, "things3.today", 1_001), "another tool");

        // A section shortened after the window opened ends it sooner
        assert!(!open(
            &policy("things3.logbook", 10),
            "things3.logbook",
            1_020
        ));
    }

    #[test]
    fn a_window_covers_only_the_exact_call_that_opened_it() {
        let windows = opened("local", "imap.search", 1_000);
        let policy = policy("imap.search", 3_600);
        let open = |call: &str| {
            window_open(
                &windows,
                &policy,
                Some("approved"),
                "local",
                "imap.search",
                call,
                1_001,
            )
            .is_some()
        };
        assert!(open("call"));
        assert!(!open("another call"));
    }

    #[test]
    fn a_window_covers_only_the_scope_that_opened_it() {
        let a = "server (someone@example.com, 100.64.0.7)";
        let b = "laptop (someone@example.com, 100.64.0.8)";
        let policy = policy("imap.search", 3_600);
        let open = |windows: &HashMap<WindowKey, Window>, scope: &str| {
            window_open(
                windows,
                &policy,
                Some("approved"),
                scope,
                "imap.search",
                "call",
                1_001,
            )
            .is_some()
        };

        let by_host = opened(a, "imap.search", 1_000);
        assert!(open(&by_host, a));
        assert!(!open(&by_host, b), "another tailnet host");
        assert!(!open(&by_host, "local"), "a local call");

        let by_local = opened("local", "imap.search", 1_000);
        assert!(open(&by_local, "local"));
        assert!(!open(&by_local, a), "a tailnet host");
    }

    #[test]
    fn a_full_scope_drops_its_oldest_window_and_leaves_other_scopes() {
        let key =
            |scope: &str, n: usize| (scope.to_string(), "imap.read".to_string(), n.to_string());
        let window = |opened| Window {
            opened,
            secret: None,
        };
        let mut windows = HashMap::new();
        open_window(&mut windows, key("other", 0), window(1));
        for n in 0..MAX_WINDOWS_PER_SCOPE {
            open_window(
                &mut windows,
                key("local", n),
                window(1_000 + u64::try_from(n).unwrap()),
            );
        }
        assert_eq!(windows.len(), MAX_WINDOWS_PER_SCOPE + 1);

        // Reopening a call already held replaces it and drops nothing
        open_window(&mut windows, key("local", 5), window(5_000));
        assert_eq!(windows.len(), MAX_WINDOWS_PER_SCOPE + 1);

        open_window(&mut windows, key("local", 999), window(9_000));
        assert_eq!(windows.len(), MAX_WINDOWS_PER_SCOPE + 1);
        assert!(!windows.contains_key(&key("local", 0)), "the oldest went");
        assert!(windows.contains_key(&key("local", 1)));
        assert!(windows.contains_key(&key("local", 999)));
        assert!(
            windows.contains_key(&key("other", 0)),
            "another scope keeps its window"
        );
    }

    #[test]
    fn no_window_applies_from_a_section_that_was_not_approved() {
        let windows = opened("local", "imap.search", 1_000);
        let policy = policy("imap.search", 3_600);
        for approved in [None, Some("an older section")] {
            let found = window_open(
                &windows,
                &policy,
                approved,
                "local",
                "imap.search",
                "call",
                1_001,
            );
            assert!(found.is_none(), "{approved:?}");
        }
        let emptied = plugin::Windows {
            tools: std::collections::BTreeMap::default(),
            hash: "approved".into(),
        };
        let found = window_open(
            &windows,
            &emptied,
            Some("approved"),
            "local",
            "imap.search",
            "call",
            1_001,
        );
        assert!(found.is_none());
    }
}
