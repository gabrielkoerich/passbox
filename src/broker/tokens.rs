//! Tokens: what one approval opens, for whom, until when, and the children minted from it.

use super::Request;
use super::audit::append_audit_to;
use super::server::Shared;
use crate::store::{self, Store};
use anyhow::{Result, anyhow, bail};
use std::collections::HashMap;

// A child mints with no prompt, so a holder could otherwise fill the broker's memory with them
const MAX_CHILDREN: usize = 64;

/* Exact names only. A token is worth minting because it is narrower than the store key, and a
namespace is not: it hands over everything under it now, and a caller that asks for one has not
said what it actually reads. The refusal lists them so naming them is a copy, not a chore. */
pub(super) fn reject_namespaces(asked: &[String], known: &[String]) -> Result<()> {
    for pattern in asked {
        if known.iter().any(|n| n == pattern) {
            continue;
        }
        let under = store::select(known, Some(pattern));
        if under.is_empty() {
            bail!("no secret named {pattern}");
        }
        bail!(
            "{pattern} is a namespace holding {} secrets, ask for the ones this needs:\n  {}",
            under.len(),
            under.join("\n  ")
        );
    }
    Ok(())
}

/* Split out so the scoping rules can be tested without a store, a socket or a finger:
an unknown token opens nothing, a known one opens only what it was granted, and neither
opens anything once it has lapsed. */
fn token_lookup(
    tokens: &HashMap<String, TokenGrant>,
    token: &str,
    name: &str,
    now: u64,
) -> Option<String> {
    let grant = tokens.get(token)?;
    (now < grant.expires)
        .then(|| grant.values.get(name).cloned())
        .flatten()
}

/// What one token opens: the values it was granted, when it stops working, and the approval behind it
pub(super) struct TokenGrant {
    pub(super) values: HashMap<String, String>,
    // The secret file each value came from, so a read after an update or delete is not served stale
    pub(super) stamps: HashMap<String, (String, u64)>,
    pub(super) expires: u64,
    // Shared by a grant and every child of it, so each read traces back to the one fingerprint
    pub(super) grant: String,
}

/* A child narrows its parent by name and never outlives it, so minting one needs no prompt. An
unset ttl takes the parent's expiry, since workers restart and re-read all day. Anything wider
than the parent is None, and the caller falls back to a grant that prompts */
fn delegate(
    tokens: &HashMap<String, TokenGrant>,
    parent: &str,
    names: &[String],
    ttl: u64,
    now: u64,
) -> Option<Result<TokenGrant>> {
    let parent = tokens.get(parent).filter(|p| now < p.expires)?;
    let expires = if ttl == 0 {
        parent.expires
    } else {
        now.saturating_add(ttl)
    };
    if names.is_empty() || expires > parent.expires {
        return None;
    }

    let mut values = HashMap::new();
    let mut stamps = HashMap::new();
    for name in names {
        values.insert(name.clone(), parent.values.get(name)?.clone());
        if let Some(stamp) = parent.stamps.get(name) {
            stamps.insert(name.clone(), stamp.clone());
        }
    }
    // The count takes in the root grant itself, which is live while any child is
    let live = tokens
        .values()
        .filter(|g| g.grant == parent.grant && now < g.expires)
        .count();
    if live > MAX_CHILDREN {
        return Some(Err(anyhow!(
            "this grant already has {MAX_CHILDREN} live child tokens, wait for one to lapse"
        )));
    }

    Some(Ok(TokenGrant {
        values,
        stamps,
        expires,
        grant: parent.grant.clone(),
    }))
}

/// Two ids long, since a token is a bearer credential and an id alone is only a file name
pub(super) fn new_token() -> String {
    format!("{}{}", store::new_id(), store::new_id())
}

/// Mints a child under the token lock alone, so it never waits behind a prompt
pub(super) fn mint_child(
    shared: &Shared,
    request: &Request,
    caller: &str,
) -> Option<Result<String>> {
    let now = store::now();
    let mut tokens = shared.tokens.lock().expect("tokens");
    tokens.retain(|_, g| now < g.expires);
    let child = match delegate(&tokens, &request.token, &request.names, request.ttl, now)? {
        Ok(child) => child,
        Err(e) => return Some(Err(e)),
    };
    let token = new_token();
    let mut granted: Vec<String> = child.values.keys().cloned().collect();
    granted.sort();
    let grant = child.grant.clone();
    tokens.insert(token.clone(), child);
    drop(tokens);

    for name in &granted {
        let to = match shared.store.recipient() {
            Ok(to) => to,
            Err(e) => return Some(Err(e)),
        };
        if let Err(e) = append_audit_to(
            &shared.store,
            &to,
            &request.agent,
            name,
            "delegated",
            caller,
            &grant,
            "",
        ) {
            return Some(Err(e));
        }
    }
    Some(Ok(format!("{token}\n{}", granted.join("\n"))))
}

/* Tokens, held past the store key's life. The key opens everything and so is dropped quickly,
a token covers only the secrets it was granted, to whoever holds it. They sit behind their own
lock, so a token read is answered while a prompt holds the broker. */
pub(super) type Tokens = std::sync::Arc<std::sync::Mutex<HashMap<String, TokenGrant>>>;

/// A token answers only for what it was granted, and only until it expires. The grant id comes too
pub(super) fn token_value(
    tokens: &Tokens,
    store: &Store,
    token: &str,
    name: &str,
) -> Option<(String, String)> {
    let now = store::now();
    let mut tokens = tokens.lock().expect("tokens");
    tokens.retain(|_, g| now < g.expires);
    // A secret changed or deleted since the grant is no longer the one approved, so the read falls through to a prompt
    for grant in tokens.values_mut() {
        if let Some((id, stamp)) = grant.stamps.get(name)
            && !store.is_current(id, *stamp)
        {
            grant.values.remove(name);
            grant.stamps.remove(name);
        }
    }
    let value = token_lookup(&tokens, token, name, now)?;
    Some((value, tokens[token].grant.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant_of(pairs: &[(&str, &str)], expires: u64) -> TokenGrant {
        TokenGrant {
            values: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            stamps: HashMap::new(),
            expires,
            grant: "root".into(),
        }
    }

    #[test]
    fn a_namespace_is_refused_and_its_names_listed() {
        let known: Vec<String> = ["acme/pk", "acme/addr", "personal/github"]
            .iter()
            .copied()
            .map(String::from)
            .collect();
        let err = reject_namespaces(&["acme".to_string()], &known)
            .unwrap_err()
            .to_string();
        assert!(err.contains("namespace holding 2"), "{err}");
        assert!(
            err.contains("acme/pk") && err.contains("acme/addr"),
            "{err}"
        );
    }

    #[test]
    fn exact_names_are_accepted() {
        let known: Vec<String> = ["acme/pk", "personal/github"]
            .iter()
            .copied()
            .map(String::from)
            .collect();
        assert!(reject_namespaces(&["acme/pk".to_string()], &known).is_ok());
        assert!(
            reject_namespaces(
                &["acme/pk".to_string(), "personal/github".to_string()],
                &known
            )
            .is_ok()
        );
    }

    /// A flat store is the case a namespace rule would miss, so the rule is not about slashes
    #[test]
    fn a_name_that_is_not_there_is_refused() {
        let known = vec!["token".to_string(), "other".to_string()];
        let err = reject_namespaces(&["nope".to_string()], &known)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no secret named nope"), "{err}");
        assert!(reject_namespaces(&["token".to_string()], &known).is_ok());
    }

    #[test]
    fn a_token_opens_only_what_it_was_granted() {
        let mut tokens = HashMap::new();
        tokens.insert("tok".to_string(), grant_of(&[("acme/pk", "value")], 2_000));
        assert_eq!(
            token_lookup(&tokens, "tok", "acme/pk", 1_000).as_deref(),
            Some("value")
        );
        assert!(token_lookup(&tokens, "tok", "personal/github", 1_000).is_none());
    }

    #[test]
    fn an_unknown_token_opens_nothing() {
        let mut tokens = HashMap::new();
        tokens.insert("tok".to_string(), grant_of(&[("acme/pk", "v")], 2_000));
        assert!(token_lookup(&tokens, "guessed", "acme/pk", 1_000).is_none());
    }

    #[test]
    fn a_lapsed_token_opens_nothing() {
        let mut tokens = HashMap::new();
        tokens.insert("tok".to_string(), grant_of(&[("acme/pk", "v")], 2_000));
        assert!(token_lookup(&tokens, "tok", "acme/pk", 2_000).is_none());
        assert!(token_lookup(&tokens, "tok", "acme/pk", 9_999).is_none());
    }

    #[test]
    fn a_child_opens_a_subset_of_its_parent_and_never_outlives_it() {
        let mut tokens = HashMap::new();
        let parent = grant_of(&[("w/a", "1"), ("w/b", "2")], 2_000);
        tokens.insert("parent".to_string(), parent);
        let names = |n: &[&str]| n.iter().copied().map(String::from).collect::<Vec<_>>();
        let mint = |tokens: &HashMap<String, TokenGrant>, from: &str, n: &[&str], ttl, now| {
            delegate(tokens, from, &names(n), ttl, now).map(|r| r.unwrap())
        };

        let child = mint(&tokens, "parent", &["w/a"], 0, 1_000).unwrap();
        assert_eq!(child.expires, 2_000);
        assert_eq!(child.grant, "root");
        assert_eq!(child.values.keys().collect::<Vec<_>>(), ["w/a"]);
        assert_eq!(
            mint(&tokens, "parent", &["w/a"], 500, 1_000)
                .unwrap()
                .expires,
            1_500
        );
        assert_eq!(
            mint(&tokens, "parent", &["w/a"], 1_000, 1_000)
                .unwrap()
                .expires,
            2_000
        );
        let twice = mint(&tokens, "parent", &["w/a", "w/a"], 0, 1_000).unwrap();
        assert_eq!(twice.values.len(), 1);

        // A name the parent lacks, a later expiry, a lapsed parent or no parent at all prompts
        assert!(mint(&tokens, "parent", &["w/a", "w/c"], 0, 1_000).is_none());
        assert!(mint(&tokens, "parent", &["w/a"], 1_001, 1_000).is_none());
        assert!(mint(&tokens, "parent", &["w/a"], u64::MAX, 1_000).is_none());
        assert!(mint(&tokens, "parent", &["w/a"], 0, 2_000).is_none());
        assert!(mint(&tokens, "guessed", &["w/a"], 0, 1_000).is_none());
        assert!(mint(&tokens, "", &["w/a"], 0, 1_000).is_none());
        assert!(mint(&tokens, "parent", &[], 0, 1_000).is_none());

        // A child of a child still ends with the first parent
        tokens.insert("child".to_string(), child);
        let grandchild = mint(&tokens, "child", &["w/a"], 0, 1_500).unwrap();
        assert_eq!(grandchild.expires, 2_000);
        assert!(mint(&tokens, "child", &["w/a"], 600, 1_500).is_none());
        assert!(mint(&tokens, "child", &["w/b"], 0, 1_500).is_none());
    }

    #[test]
    fn a_grant_mints_at_most_its_cap_of_live_children() {
        let mut tokens = HashMap::new();
        tokens.insert("root".to_string(), grant_of(&[("w/a", "1")], 2_000));
        let names = vec!["w/a".to_string()];
        for i in 0..MAX_CHILDREN {
            let child = delegate(&tokens, "root", &names, 0, 1_000)
                .unwrap()
                .unwrap();
            tokens.insert(format!("c{i}"), child);
        }

        // A child minting its own child counts against the same root
        let err = delegate(&tokens, "c0", &names, 0, 1_000)
            .unwrap()
            .err()
            .unwrap();
        assert!(err.to_string().contains("64 live child tokens"), "{err}");
        assert!(
            delegate(&tokens, "root", &names, 0, 1_000)
                .unwrap()
                .is_err()
        );

        // A lapsed child frees its place
        tokens.get_mut("c1").unwrap().expires = 1_000;
        assert!(delegate(&tokens, "root", &names, 0, 1_000).unwrap().is_ok());

        // Another grant has its own count
        let mut other = grant_of(&[("w/a", "1")], 2_000);
        other.grant = "other".into();
        tokens.insert("other".to_string(), other);
        assert!(
            delegate(&tokens, "other", &names, 0, 1_000)
                .unwrap()
                .is_ok()
        );
    }
}
