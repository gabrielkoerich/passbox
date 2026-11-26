//! One age file per secret. The filename is a random id, the name lives inside the ciphertext.

use crate::crypto;
#[cfg(feature = "host")]
use crate::{se, yubikey};
use age::{scrypt, x25519};
use anyhow::{Context, Result, anyhow, bail};
use hmac::{Hmac, Mac};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const KEEP_VERSIONS: usize = 5;
pub(crate) const TOMB_TTL_SECS: u64 = 90 * 24 * 60 * 60;

#[derive(Serialize, Deserialize)]
pub(crate) struct Secret {
    pub name: String,
    pub value: String,
    pub created: u64,
    pub updated: u64,
    /// The value is the whole text, such as a certificate, never read as `key: value` fields
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub blob: bool,
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/* What never syncs and git never tracks, in rclone filter syntax so `sync_via_rclone` excludes
the same list. A
leading `/` anchors the pattern at the store root, without one it matches a file name anywhere.
Matching ignores case, as macOS and iCloud Drive do. */
pub(crate) const MACHINE_LOCAL: &[&str] = &[
    // Live endpoints, and the public keys this machine rebuilds whenever the store key opens
    "/broker.sock",
    "/ssh-agent.sock",
    "/ssh-keys.pub",
    // A client's broker address, which on another Mac would send its reads to this one's host
    "/host",
    // A USB path on one Mac means nothing on another
    "/remote",
    "/config.toml",
    "/names",
    "/plugins/**",
    // The repo is this machine's history, and the remote is a mirror rather than a clone
    "/.git/**",
    "/.gitignore",
    "/store/.versions/**",
    // A file that did not open when this Mac sealed its store, kept aside rather than lost
    "/store/.quarantine/**",
    // A write's temporary file, left only by a crash
    "*.tmp",
    // What git tracked that belongs to one machine, set aside and never used
    "/.from-git/**",
    // A copy cut off before its rename, never a real file
    "*.partial",
    // A grant that travelled would let a machine you have not touched inherit an approval
    "/grants-*.age",
    "/windows-*.json",
    // A phone enrolls with one Mac, and its wrap names the node that dials that Mac
    "/wraps/phone-*.json",
    // What this Mac knows of the store key and its signing, which a copy must never change
    "/recipient.pin",
    "/signed",
    // This Mac began its first seal, so one cut off resumes rather than refusing what it missed
    "/sealing",
];

/// Whether a path relative to the store is one of `MACHINE_LOCAL`, ignoring case as macOS does
pub(crate) fn machine_local(relative: &str) -> bool {
    MACHINE_LOCAL.iter().any(|p| path_matches(p, relative)) || set_aside_by_2_4_2(relative)
}

/// 2.4.2 renamed a git-tracked file in place, as `config.toml.from-git-<time>-<n>`
fn set_aside_by_2_4_2(relative: &str) -> bool {
    relative
        .rsplit('/')
        .next()
        .is_some_and(|name| name.to_lowercase().contains(".from-git-"))
}

pub(crate) fn path_matches(pattern: &str, relative: &str) -> bool {
    let (pattern, relative) = (pattern.to_lowercase(), relative.to_lowercase());
    let (pattern, text) = match pattern.strip_prefix('/') {
        Some(rooted) => (rooted, relative.as_str()),
        None => (
            pattern.as_str(),
            relative.rsplit('/').next().unwrap_or(&relative),
        ),
    };
    if let Some(dir) = pattern.strip_suffix("/**") {
        return text == dir || text.starts_with(&format!("{dir}/"));
    }
    match pattern.split_once('*') {
        Some((head, tail)) => {
            text.len() >= head.len() + tail.len()
                && text.starts_with(head)
                && text.ends_with(tail)
                && !text[head.len()..text.len() - tail.len()].contains('/')
        }
        None => text == pattern,
    }
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/* A name, or everything under a namespace. The trailing slash is what stops `acme` dragging
in `acmecorp`. Lives here rather than in `import` because the client build has no `import`. */
#[cfg(feature = "host")]
pub(crate) fn select(all: &[String], prefix: Option<&str>) -> Vec<String> {
    let Some(prefix) = prefix else {
        return all.to_vec();
    };
    let namespace = format!("{}/", prefix.trim_end_matches('/'));
    all.iter()
        .filter(|name| *name == prefix || name.starts_with(&namespace))
        .cloned()
        .collect()
}

pub(crate) fn new_id() -> String {
    let bytes: [u8; 16] = rand::random();
    hex::encode(bytes)
}

#[derive(Clone)]
pub(crate) struct Store {
    pub dir: PathBuf,
}

impl Store {
    pub(crate) fn open() -> Result<Self> {
        let dir = match std::env::var_os("PASSBOX_DIR") {
            Some(d) => PathBuf::from(d),
            None => home()?.join(".passbox"),
        };
        Ok(Store { dir })
    }

    pub(crate) fn secrets_dir(&self) -> PathBuf {
        self.dir.join("store")
    }
    pub(crate) fn versions_dir(&self) -> PathBuf {
        self.secrets_dir().join(".versions")
    }
    pub(crate) fn wraps_dir(&self) -> PathBuf {
        self.dir.join("wraps")
    }
    fn recipient_path(&self) -> PathBuf {
        self.wraps_dir().join("recipient")
    }
    /// The recipient this Mac last saw the store key make. Machine local, so no synced copy changes it
    fn pin_path(&self) -> PathBuf {
        self.dir.join("recipient.pin")
    }
    /// Present once this Mac has sealed its files, after which an unsealed one is refused. It holds
    /// when, so a version kept before then is known to be this Mac's own
    fn signed_path(&self) -> PathBuf {
        self.dir.join("signed")
    }

    fn sealing_path(&self) -> PathBuf {
        self.dir.join("sealing")
    }

    fn sealed(&self) -> bool {
        self.signed_path().exists()
    }

    fn sealed_at(&self) -> u64 {
        fs::read_to_string(self.signed_path())
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    fn mark_sealed(&self) -> Result<()> {
        write_private(&self.signed_path(), now().to_string().as_bytes())
    }

    /// A Mac joining a store adopts nothing unsealed from the copy it was given, which may have had
    /// its sealed files taken out and its own planted
    #[cfg(feature = "host")]
    pub(crate) fn join(&self) -> Result<()> {
        if self.sealed() {
            return Ok(());
        }
        self.mark_sealed()
    }

    /// The store's public key as this copy names it, for a person to compare across Macs
    #[cfg(feature = "host")]
    pub(crate) fn fingerprint(&self) -> Result<String> {
        let raw = fs::read_to_string(self.recipient_path())
            .with_context(|| format!("no store at {}", self.dir.display()))?;
        Ok(raw.trim().to_string())
    }

    /* An earlier version written back as the current one, sealed. One kept before this Mac sealed its
    files is its own. An unsealed one kept after was a file this Mac refused, moved aside by a write,
    so restoring it would seal what a copy planted */
    pub(crate) fn restore_version(
        &self,
        id: &str,
        version: &Path,
        key: &x25519::Identity,
    ) -> Result<()> {
        let (secret, sealed) = open(version, id, key)?;
        let kept: u64 = version
            .file_stem()
            .and_then(|s| s.to_str()?.parse().ok())
            .unwrap_or(u64::MAX);
        if !sealed && self.sealed() && kept >= self.sealed_at() {
            bail!(
                "this version was unsealed when it was kept, after this Mac sealed its files, so \
                 passbox did not write it here"
            );
        }
        self.put(id, &secret, key)
    }
    fn recovery_path(&self) -> PathBuf {
        self.wraps_dir().join("recovery.age")
    }
    /// Opened by the token rather than by a passphrase, so the file is inert on its own
    #[cfg(feature = "host")]
    pub(crate) fn yubikey_wrap_path(&self) -> PathBuf {
        self.wraps_dir().join("yubikey.age")
    }
    #[cfg(feature = "host")]
    pub(crate) fn has_yubikey_wrap(&self) -> bool {
        self.yubikey_wrap_path().exists()
    }

    /// One wrap per machine, because a Secure Enclave key cannot leave the Mac that made it
    pub(crate) fn se_wrap_path(&self) -> PathBuf {
        self.wraps_dir().join(format!("se-{}.json", hostname()))
    }
    /// One per machine as well: a phone enrolls with one Mac, and the file names the node it dials from
    #[cfg(feature = "host")]
    pub(crate) fn phone_wrap_path(&self) -> PathBuf {
        self.wraps_dir().join(format!("phone-{}.json", hostname()))
    }
    pub(crate) fn socket_path(&self) -> PathBuf {
        self.dir.join("broker.sock")
    }
    /// Where `SSH_AUTH_SOCK` points
    #[cfg(feature = "host")]
    pub(crate) fn ssh_agent_path(&self) -> PathBuf {
        self.dir.join("ssh-agent.sock")
    }
    /// The public half of every SSH key in the store, so listing them needs no prompt
    #[cfg(feature = "host")]
    pub(crate) fn ssh_keys_path(&self) -> PathBuf {
        self.dir.join("ssh-keys.pub")
    }
    /// The approved `[ssh.windows]` section, signed under the store key as the plugin record is
    #[cfg(feature = "host")]
    pub(crate) fn ssh_approval_path(&self) -> PathBuf {
        self.dir.join(format!("windows-ssh-{}.json", hostname()))
    }
    /// Installed plugins, one directory each. Local and machine specific, so sync skips it
    #[cfg(feature = "host")]
    pub(crate) fn plugins_dir(&self) -> PathBuf {
        self.dir.join("plugins")
    }
    /// Per machine, so two Macs never append to the same file through a syncer
    pub(crate) fn audit_path(&self) -> PathBuf {
        self.dir.join(format!("audit-{}.log", hostname()))
    }
    pub(crate) fn is_initialised(&self) -> bool {
        self.recipient_path().exists()
    }
    pub(crate) fn has_se_wrap(&self) -> bool {
        self.se_wrap_path().exists()
    }

    /// Generate the store key and write no wrap. The recipient stays in the clear so writing a
    /// secret never needs an unlock. The caller decides which wraps to add.
    pub(crate) fn init(&self) -> Result<x25519::Identity> {
        if self.is_initialised() {
            bail!("{} is already initialised", self.dir.display());
        }
        private_dir(&self.dir)?;
        private_dir(&self.secrets_dir())?;
        private_dir(&self.versions_dir())?;
        private_dir(&self.wraps_dir())?;

        let key = x25519::Identity::generate();
        let public = key.to_public().to_string();
        write_private(&self.recipient_path(), public.as_bytes())?;
        write_private(&self.pin_path(), public.as_bytes())?;
        self.mark_sealed()?;
        Ok(key)
    }

    #[cfg(feature = "host")]
    pub(crate) fn has_recovery_wrap(&self) -> bool {
        self.recovery_path().exists()
    }

    /// A wrap that opens the store away from this Mac. Sync is worth nothing without one.
    #[cfg(feature = "host")]
    pub(crate) fn has_portable_wrap(&self) -> bool {
        self.has_recovery_wrap() || self.has_yubikey_wrap()
    }

    /* The passphrase wrap is the only thing that opens the store away from this Mac, which makes
    it both what syncing needs and the one file worth attacking in a synced copy. It is written
    when the user asks for sync, never before.

    The age crate calibrates scrypt to about a second of work on this machine, which is the
    right default and the wrong thing to pay sixty times over in a test suite. `log_n` lowers it,
    and only a debug build will read the environment variable that asks for that. */
    pub(crate) fn create_recovery_wrap_with_factor(
        &self,
        key: &x25519::Identity,
        passphrase: SecretString,
        log_n: Option<u8>,
    ) -> Result<()> {
        let mut recipient = scrypt::Recipient::new(passphrase);
        if let Some(log_n) = log_n {
            recipient.set_work_factor(log_n);
        }
        let mut text = secrecy::ExposeSecret::expose_secret(&key.to_string()).to_string();
        let wrapped = crypto::encrypt(text.as_bytes(), &[Box::new(recipient)])?;
        text.zeroize();
        write_private(&self.recovery_path(), &wrapped)
    }

    /// Recipients are public, so they sit in the clear beside the wrap they opened
    #[cfg(feature = "host")]
    pub(crate) fn yubikey_recipients_path(&self) -> PathBuf {
        self.wraps_dir().join("yubikey.recipients")
    }

    #[cfg(feature = "host")]
    pub(crate) fn yubikey_recipients(&self) -> Vec<String> {
        fs::read_to_string(self.yubikey_recipients_path()).map_or_default(|raw| {
            raw.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        })
    }

    #[cfg(feature = "host")]
    fn yubikey_seal_path(&self) -> PathBuf {
        self.wraps_dir().join("yubikey.seal")
    }

    /* wraps/yubikey.recipients syncs, and adding a token wraps the store key to every line in it, so a
    copy that added a line of its own would get the key. The seal, keyed from the store key, shows
    the list is one this store wrote. A list with no seal predates it, and a person checks it */
    #[cfg(feature = "host")]
    pub(crate) fn yubikey_list(&self, key: &x25519::Identity) -> Result<(Vec<String>, bool)> {
        let all = self.yubikey_recipients();
        let Ok(seal) = fs::read_to_string(self.yubikey_seal_path()) else {
            return Ok((all, false));
        };
        let holds = hex::decode(seal.trim())
            .is_ok_and(|seal| list_mac(key, &all).is_ok_and(|mac| mac.verify_slice(&seal).is_ok()));
        if !holds {
            bail!(
                "wraps/yubikey.recipients changed outside passbox, so no key was wrapped. It lists: {}",
                all.join(", ")
            );
        }
        Ok((all, true))
    }

    /// age takes any number of recipients, so every token shares one wrap, written with its list
    /// and the list's seal
    #[cfg(feature = "host")]
    pub(crate) fn wrap_to_yubikeys(&self, key: &x25519::Identity, all: &[String]) -> Result<()> {
        let mut to = Vec::new();
        for text in all {
            to.push(yubikey::recipient(text)?);
        }

        let mut plain = secrecy::ExposeSecret::expose_secret(&key.to_string()).to_string();
        let wrapped = crypto::encrypt(plain.as_bytes(), &to);
        plain.zeroize();
        write_private(&self.yubikey_wrap_path(), &wrapped?)?;
        write_private(&self.yubikey_recipients_path(), all.join("\n").as_bytes())?;
        let seal = hex::encode(list_mac(key, all)?.finalize().into_bytes());
        write_private(&self.yubikey_seal_path(), seal.as_bytes())
    }

    /// The token prompts for a touch itself, so passbox raises nothing here
    #[cfg(feature = "host")]
    pub(crate) fn unlock_with_yubikey(&self) -> Result<x25519::Identity> {
        let wrapped = fs::read(self.yubikey_wrap_path()).context("no YubiKey wrap")?;
        let raw = crypto::decrypt(&wrapped, &[yubikey::identity()?])
            .context("the YubiKey refused, or it is not the one this was wrapped to")?;
        self.trusted(key_from_bytes(&raw)?)
    }

    /// The store's public key, refused when it differs from what the store key made on this Mac
    pub(crate) fn recipient(&self) -> Result<x25519::Recipient> {
        let raw = fs::read_to_string(self.recipient_path())
            .with_context(|| format!("no store at {}, run `passbox init`", self.dir.display()))?;
        // Once this Mac has pinned the store's key, a swapped wraps/recipient changes nothing here
        let pinned = fs::read_to_string(self.pin_path()).unwrap_or_default();
        let text = if pinned.trim().is_empty() {
            raw.trim()
        } else {
            pinned.trim()
        };
        x25519::Recipient::from_str(text).map_err(|e| anyhow!("bad recipient file: {e}"))
    }

    /* wraps/recipient and the wraps sync, so a copy could swap either. The pin, which never syncs,
    names the store's key: a key that differs is refused, a swapped recipient is put back, and the
    first unlock on this Mac signs the files already here */
    fn trusted(&self, key: x25519::Identity) -> Result<x25519::Identity> {
        let public = key.to_public().to_string();
        let on_disk = fs::read_to_string(self.recipient_path()).unwrap_or_default();
        match fs::read_to_string(self.pin_path()) {
            // A wrap is a key sealed to a public key, so a synced copy can plant one that opens to a
            // key of its own choosing. Only the pinned key is the store's
            Ok(pin) if pin.trim() != public => bail!(
                "the key this wrap opened is not the store key this Mac knows, a synced copy may \
                 have replaced the wrap, so nothing was opened"
            ),
            Ok(_) => {
                if on_disk.trim() != public {
                    eprintln!(
                        "wraps/recipient did not match the store key, so passbox put it back"
                    );
                    write_private(&self.recipient_path(), public.as_bytes())?;
                }
            }
            // The first unlock after an upgrade pins the key only when the recipient agrees
            Err(_) if on_disk.trim() != public => bail!(
                "wraps/recipient and the store key disagree, and this Mac has no record of which is \
                 right. Restore wraps/recipient, or the wrap you unlocked with, from a backup you trust"
            ),
            Err(_) => write_private(&self.pin_path(), public.as_bytes())?,
        }
        if !self.sealed() {
            self.seal_all(&key)?;
        }
        Ok(key)
    }

    /* Once per Mac, as it upgrades, in place so a tombstone and the versions stay as they are. The
    files are trusted and sealed only on the store's first upgrade, when none is sealed. A sealed
    file means another Mac upgraded, so nothing unsealed is trusted. A file that does not open is
    moved to store/.quarantine, which never syncs, so it neither holds the upgrade back nor locks
    the store. The client build reads what a Mac sealed, and never adopts. Before it writes, the
    first seal lists every file it will seal with a hash of its bytes, so one cut off resumes on
    exactly those, and a file a sync brought in between is not adopted */
    fn seal_all(&self, key: &x25519::Identity) -> Result<()> {
        let (files, any_sealed) = self.by_seal(key)?;
        let listed = fs::read_to_string(self.sealing_path()).ok();
        if cfg!(feature = "host") && (!any_sealed || listed.is_some()) {
            let listed = if let Some(text) = listed {
                text
            } else {
                let text: String = files
                    .iter()
                    .map(|(id, _)| self.secret_path(id))
                    .chain(self.tombed()?.iter().map(|id| self.tomb_path(id)))
                    .filter_map(|path| file_line(&path))
                    .collect();
                write_private(&self.sealing_path(), text.as_bytes())?;
                text
            };
            let keep = |path: &Path| file_line(path).is_some_and(|line| listed.contains(&line));
            self.seal_files(&files, key, keep)?;
        }
        self.mark_sealed()?;
        let _ = fs::remove_file(self.sealing_path());
        Ok(())
    }

    /// The unsealed secrets, and whether any file carries this store's seal. A file that does not
    /// open is moved to the quarantine, not lost
    pub(crate) fn by_seal(&self, key: &x25519::Identity) -> Result<(Vec<(String, Secret)>, bool)> {
        let mut files = Vec::new();
        let mut any_sealed = false;
        for id in self.ids_with_files()? {
            let path = self.secret_path(&id);
            match open(&path, &id, key) {
                Ok((secret, false)) => files.push((id, secret)),
                Ok((_, true)) => any_sealed = true,
                Err(e) => {
                    let aside = self.secrets_dir().join(".quarantine");
                    private_dir(&aside)?;
                    fs::rename(&path, aside.join(format!("{id}.age")))?;
                    eprintln!("moved {} aside, it does not open: {e:#}", path.display());
                }
            }
        }
        Ok((files, any_sealed))
    }

    /// Adopts the unsealed secrets and tombstones `keep` passes as this store's own
    pub(crate) fn seal_files(
        &self,
        files: &[(String, Secret)],
        key: &x25519::Identity,
        keep: impl Fn(&Path) -> bool,
    ) -> Result<()> {
        for (id, secret) in files {
            let path = self.secret_path(id);
            if keep(&path) {
                write_sealed(&path, id, secret, key)?;
            }
        }
        for id in self.tombed()? {
            if self.sealed_tomb(&id, key).is_none() && keep(&self.tomb_path(&id)) {
                let stamp = fs::read_to_string(self.tomb_path(&id))
                    .ok()
                    .and_then(|s| s.split_whitespace().next()?.parse().ok())
                    .unwrap_or_else(now);
                self.write_tomb(&id, stamp, key)?;
            }
        }
        Ok(())
    }

    pub(crate) fn unlock_with_passphrase(
        &self,
        passphrase: SecretString,
    ) -> Result<x25519::Identity> {
        let wrapped = fs::read(self.recovery_path()).context("no recovery wrap")?;
        let raw = crypto::decrypt(&wrapped, &[Box::new(scrypt::Identity::new(passphrase))])
            .context("wrong passphrase")?;
        self.trusted(key_from_bytes(&raw)?)
    }

    /// Bind the store key to this Mac's Secure Enclave. Neither step raises a prompt.
    #[cfg(feature = "host")]
    pub(crate) fn create_se_wrap(&self, key: &x25519::Identity) -> Result<()> {
        let mut text = secrecy::ExposeSecret::expose_secret(&key.to_string()).to_string();
        let wrap = se::wrap(text.as_bytes())?;
        text.zeroize();
        write_private(&self.se_wrap_path(), &serde_json::to_vec(&wrap)?)
    }

    #[cfg(feature = "host")]
    fn se_wrap(&self) -> Result<se::SeWrap> {
        let raw =
            fs::read(self.se_wrap_path()).context("no Secure Enclave wrap on this machine")?;
        Ok(serde_json::from_slice(&raw)?)
    }

    /// Raise a Touch ID prompt worded by `reason`, then open the store key.
    #[cfg(feature = "host")]
    pub(crate) fn unlock_with_se(&self, reason: &str) -> Result<x25519::Identity> {
        let plain = se::unwrap(&self.se_wrap()?, reason)?;
        self.trusted(key_from_bytes(&plain)?)
    }

    /// The same prompt, left on screen while the caller also waits for a phone. `done` runs on
    /// another thread with the key or the refusal
    #[cfg(feature = "host")]
    pub(crate) fn unlock_with_se_in_background(
        &self,
        reason: &str,
        done: impl FnOnce(Result<x25519::Identity>) + Send + 'static,
    ) -> Result<se::Prompt> {
        let store = self.clone();
        se::unwrap_in_background(&self.se_wrap()?, reason, move |plain| {
            done(plain.and_then(|plain| store.trusted(key_from_bytes(&plain)?)));
        })
    }

    /// The store key as a phone handed it back, refused unless it is this store's
    #[cfg(feature = "host")]
    pub(crate) fn key_from_phone(&self, raw: &[u8]) -> Result<x25519::Identity> {
        let key = key_from_bytes(raw)
            .map_err(|_| anyhow!("the phone opened a different key, not this store's"))?;
        if key.to_public().to_string() != self.recipient()?.to_string() {
            bail!("the phone opened a different key, not this store's");
        }
        self.trusted(key)
    }

    /// Ids with a secret file and no tombstone.
    pub(crate) fn ids(&self) -> Result<Vec<String>> {
        let mut out = self.ids_with_files()?;
        out.retain(|id| !self.tomb_path(id).exists());
        Ok(out)
    }

    /// Every id that still has a file, tombstoned or not. A delete that arrived through a
    /// sync leaves the file in place, so undeleting it is a matter of dropping the tombstone.
    pub(crate) fn ids_with_files(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let dir = self.secrets_dir();
        if !dir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("age") {
                continue;
            }
            if let Some(id) = path.file_stem().and_then(|s| s.to_str()) {
                out.push(id.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    fn tombed(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let dir = self.secrets_dir();
        if !dir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("tomb")
                && let Some(id) = path.file_stem().and_then(|s| s.to_str())
            {
                out.push(id.to_string());
            }
        }
        Ok(out)
    }

    pub(crate) fn untomb(&self, id: &str) -> Result<()> {
        let tomb = self.tomb_path(id);
        if tomb.exists() {
            fs::remove_file(tomb)?;
        }
        Ok(())
    }

    pub(crate) fn secret_path(&self, id: &str) -> PathBuf {
        self.secrets_dir().join(format!("{id}.age"))
    }
    pub(crate) fn tomb_path(&self, id: &str) -> PathBuf {
        self.secrets_dir().join(format!("{id}.tomb"))
    }

    pub(crate) fn load(&self, id: &str, key: &x25519::Identity) -> Result<Secret> {
        let (secret, signed) = open(&self.secret_path(id), id, key)?;
        // Once this Mac has sealed its files, an unsealed one was not written by passbox here
        if !signed && self.sealed() {
            bail!("it is not sealed by this store's key for this file");
        }
        Ok(secret)
    }

    /// Every secret that opens and is signed. A file that is not is skipped and named, so one
    /// planted or broken file cannot hide the rest
    pub(crate) fn secrets(&self, key: &x25519::Identity) -> Result<Vec<(String, Secret)>> {
        let mut out = Vec::new();
        for id in self.ids()? {
            match self.load(&id, key) {
                Ok(secret) => out.push((id, secret)),
                Err(e) => self.skipped(&id, &e),
            }
        }
        Ok(out)
    }

    fn skipped(&self, id: &str, e: &anyhow::Error) {
        eprintln!("skipped {}: {e:#}", self.secret_path(id).display());
    }

    /// A hash of the secret file's bytes, which changes whenever the entry is rewritten
    #[cfg(feature = "host")]
    pub(crate) fn stamp(&self, id: &str) -> Result<u64> {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        fs::read(self.secret_path(id))?.hash(&mut hasher);
        Ok(hasher.finish())
    }

    /// True while the id has a file, no tombstone and the bytes it had when stamped
    #[cfg(feature = "host")]
    pub(crate) fn is_current(&self, id: &str, stamp: u64) -> bool {
        !self.tomb_path(id).exists() && self.stamp(id).is_ok_and(|now| now == stamp)
    }

    pub(crate) fn find(
        &self,
        name: &str,
        key: &x25519::Identity,
    ) -> Result<Option<(String, Secret)>> {
        for id in self.ids()? {
            match self.load(&id, key) {
                Ok(secret) if secret.name == name => return Ok(Some((id, secret))),
                Ok(_) => {}
                Err(e) => self.skipped(&id, &e),
            }
        }
        Ok(None)
    }

    /* A host to ask instead of a local broker. One line, `machine:port`, which a client writes
    once. A machine with no Enclave has nothing to unlock and no sensor to ask, so asking a
    machine that has both is the only thing it can usefully do. */
    pub(crate) fn host_path(&self) -> PathBuf {
        self.dir.join("host")
    }

    /// Whether git tracks a path in the store, in any case, since the Mac's disk ignores case. A
    /// machine local file it tracks came from a pull, and a git that will not run counts as tracking
    pub(crate) fn git_tracks(&self, relative: &str) -> bool {
        if !self.dir.join(".git").exists() {
            return false;
        }
        std::process::Command::new("git")
            .arg("-C")
            .arg(&self.dir)
            .args(["ls-files", "--error-unmatch", "--"])
            .arg(format!(":(icase){relative}"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_or(true, |s| s.success())
    }

    pub(crate) fn host(&self) -> Option<String> {
        if let Ok(from_env) = std::env::var("PASSBOX_HOST")
            && !from_env.is_empty()
        {
            return Some(from_env);
        }
        // A host file git checked out names a broker someone else chose, which would answer every read
        if self.git_tracks("host") {
            eprintln!("ignored the host file, it came from git");
            return None;
        }
        let text = fs::read_to_string(self.host_path()).ok()?;
        let line = text.lines().next()?.trim().to_string();
        (!line.is_empty()).then_some(line)
    }

    /// Versions before 0.13.43 kept every name in the clear here, so remove what they left
    pub(crate) fn remove_name_index(&self) -> Result<()> {
        match fs::remove_file(self.dir.join("names")) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }

    /// Each name from an entry that opens and is sealed, so checking the seal decrypts every value,
    /// which the wiping allocator clears when it is freed
    pub(crate) fn names(&self, key: &x25519::Identity) -> Result<Vec<String>> {
        let mut out: Vec<String> = self
            .secrets(key)?
            .into_iter()
            .map(|(_, secret)| secret.name.clone())
            .collect();
        out.sort();
        Ok(out)
    }

    /// Encrypt and write, keeping the previous file as a version.
    pub(crate) fn put(&self, id: &str, secret: &Secret, key: &x25519::Identity) -> Result<()> {
        private_dir(&self.secrets_dir())?;
        self.keep_version(id)?;
        write_sealed(&self.secret_path(id), id, secret, key)?;
        let tomb = self.tomb_path(id);
        if tomb.exists() {
            fs::remove_file(tomb)?;
        }
        Ok(())
    }

    /// Move the current file into `.versions`, trimming to the newest `KEEP_VERSIONS`.
    pub(crate) fn keep_version(&self, id: &str) -> Result<()> {
        let current = self.secret_path(id);
        if !current.exists() {
            return Ok(());
        }
        let dir = self.versions_dir().join(id);
        private_dir(&dir)?;
        let mut stamp = now();
        while dir.join(format!("{stamp}.age")).exists() {
            stamp += 1;
        }
        fs::rename(&current, dir.join(format!("{stamp}.age")))?;

        let mut kept = self.versions(id)?;
        while kept.len() > KEEP_VERSIONS {
            let (_, oldest) = kept.remove(0);
            fs::remove_file(oldest)?;
        }
        Ok(())
    }

    /// Versions for an id, oldest first.
    pub(crate) fn versions(&self, id: &str) -> Result<Vec<(u64, PathBuf)>> {
        let dir = self.versions_dir().join(id);
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            let stamp = path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u64>().ok());
            if let Some(stamp) = stamp {
                out.push((stamp, path));
            }
        }
        out.sort_by_key(|(stamp, _)| *stamp);
        Ok(out)
    }

    /// Version the current file, then leave a tombstone so the delete survives a sync. It holds when,
    /// sealed with the id, so a tombstone a copy forged never prunes a secret's history
    pub(crate) fn delete(&self, id: &str, key: &x25519::Identity) -> Result<()> {
        self.keep_version(id)?;
        self.write_tomb(id, now(), key)
    }

    fn write_tomb(&self, id: &str, stamp: u64, key: &x25519::Identity) -> Result<()> {
        let seal = hex::encode(tomb_mac(key, id, stamp)?.finalize().into_bytes());
        write_private(&self.tomb_path(id), format!("{stamp} {seal}").as_bytes())
    }

    /// The time a tombstone holds, when its seal shows this store wrote it
    fn sealed_tomb(&self, id: &str, key: &x25519::Identity) -> Option<u64> {
        let text = fs::read_to_string(self.tomb_path(id)).ok()?;
        let (stamp, seal) = text.trim().split_once(' ')?;
        let stamp: u64 = stamp.parse().ok()?;
        let seal = hex::decode(seal).ok()?;
        tomb_mac(key, id, stamp).ok()?.verify_slice(&seal).ok()?;
        Some(stamp)
    }

    /// Drop tombstones older than the TTL, along with the versions they guard.
    /// Only a tombstone this store sealed prunes, so a forged one can hide a secret until `restore`
    /// but never delete its history
    pub(crate) fn prune_tombs(&self, key: &x25519::Identity) -> Result<usize> {
        let dir = self.secrets_dir();
        if !dir.exists() {
            return Ok(0);
        }
        let mut pruned = 0;
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("tomb") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Some(stamp) = self.sealed_tomb(id, key) else {
                continue;
            };
            // The name was added back, so an old tombstone a copy put back prunes nothing
            if self.secret_path(id).exists() {
                continue;
            }
            if now().saturating_sub(stamp) < TOMB_TTL_SECS {
                continue;
            }
            let versions = self.versions_dir().join(id);
            if versions.exists() {
                fs::remove_dir_all(versions)?;
            }
            fs::remove_file(&path)?;
            pruned += 1;
        }
        Ok(pruned)
    }
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))
}

pub(crate) fn hostname() -> String {
    std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn key_from_bytes(raw: &[u8]) -> Result<x25519::Identity> {
    let text = std::str::from_utf8(raw).context("the wrap is not a key")?;
    x25519::Identity::from_str(text.trim()).map_err(|e| anyhow!("bad store key: {e}"))
}

pub(crate) fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// One encrypted secret file, wherever it sits, such as an earlier version. Versions never sync,
/// so one from before signing is still read
pub(crate) fn load_path(path: &Path, key: &x25519::Identity) -> Result<Secret> {
    open(path, &id_of(path), key).map(|(secret, _)| secret)
}

/// A live file is `store/<id>.age`, a version `store/.versions/<id>/<stamp>.age`
fn id_of(path: &Path) -> String {
    let parent = path.parent().and_then(Path::file_name);
    let name = if parent.is_some_and(|p| p == "store") {
        path.file_stem()
    } else {
        parent
    };
    name.map_or_else(String::new, |n| n.to_string_lossy().to_string())
}

/// What a secret file holds: the secret, and the seal only the store key can make
#[derive(Deserialize)]
struct Sealed {
    #[serde(flatten)]
    secret: Secret,
    #[serde(default)]
    seal: Option<String>,
}

#[derive(Serialize)]
struct SealedRef<'a> {
    #[serde(flatten)]
    secret: &'a Secret,
    seal: String,
}

/// The secret in a file, and whether it carries this store's seal for this id. A seal that is there
/// and wrong is refused
fn open(path: &Path, id: &str, key: &x25519::Identity) -> Result<(Secret, bool)> {
    let raw = fs::read(path)?;
    let mut plain = crypto::decrypt(&raw, &[Box::new(key.clone())])?;
    let sealed: Result<Sealed> =
        serde_json::from_slice(&plain).context("secret file is not valid json");
    plain.zeroize();
    let sealed = sealed?;
    match sealed.seal.as_deref() {
        Some(seal) if matches(key, id, &sealed.secret, seal) => Ok((sealed.secret, true)),
        Some(_) => bail!("it carries a seal this store did not make for this file"),
        None => Ok((sealed.secret, false)),
    }
}

fn write_sealed(path: &Path, id: &str, secret: &Secret, key: &x25519::Identity) -> Result<()> {
    let sealed = SealedRef {
        secret,
        seal: hex::encode(mac(key, id, secret)?.finalize().into_bytes()),
    };
    let mut json = serde_json::to_vec(&sealed)?;
    let ct = crypto::encrypt(&json, &[Box::new(key.to_public())]);
    json.zeroize();
    write_private(path, &ct?)
}

/* age lets anyone who knows the public recipient write a file the store key opens, and the
recipient sits in every synced copy. The seal is an HMAC keyed from the store key, over the file's
id and the secret, so a planted file has none and a signed one moved to another id fails */
/// A file's name and the hash of its bytes, one line of the `sealing` list
fn file_line(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let name = path.file_name()?.to_string_lossy();
    Some(format!("{name} {}\n", hex::encode(Sha256::digest(&bytes))))
}

fn mac(key: &x25519::Identity, id: &str, secret: &Secret) -> Result<Hmac<Sha256>> {
    let mut seed = Sha256::new();
    seed.update(b"passbox secret seal\n");
    seed.update(secrecy::ExposeSecret::expose_secret(&key.to_string()).as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&seed.finalize())
        .map_err(|_| anyhow!("could not key the seal"))?;
    mac.update(id.as_bytes());
    mac.update(b"\n");
    mac.update(&serde_json::to_vec(secret)?);
    Ok(mac)
}

/// A tombstone's seal over its id and time, keyed apart from a secret's
fn tomb_mac(key: &x25519::Identity, id: &str, stamp: u64) -> Result<Hmac<Sha256>> {
    let mut seed = Sha256::new();
    seed.update(b"passbox tombstone\n");
    seed.update(secrecy::ExposeSecret::expose_secret(&key.to_string()).as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&seed.finalize())
        .map_err(|_| anyhow!("could not key the seal"))?;
    mac.update(format!("{id}\n{stamp}").as_bytes());
    Ok(mac)
}

/// The YubiKey list's seal, keyed apart from a secret's so one can never pass for the other
#[cfg(feature = "host")]
fn list_mac(key: &x25519::Identity, all: &[String]) -> Result<Hmac<Sha256>> {
    let mut seed = Sha256::new();
    seed.update(b"passbox yubikey list\n");
    seed.update(secrecy::ExposeSecret::expose_secret(&key.to_string()).as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&seed.finalize())
        .map_err(|_| anyhow!("could not key the seal"))?;
    mac.update(all.join("\n").as_bytes());
    Ok(mac)
}

fn matches(key: &x25519::Identity, id: &str, secret: &Secret, given: &str) -> bool {
    let (Ok(mac), Ok(given)) = (mac(key, id, secret), hex::decode(given)) else {
        return false;
    };
    mac.verify_slice(&given).is_ok()
}

/// Write through a temporary file so a crash cannot leave a half written secret.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    // Its own temporary file, so two writers of one path, such as a prompt and a phone, never share it
    static WRITES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = WRITES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = path
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().to_string());
    let tmp = path.with_file_name(format!(".{name}.{}-{n}.tmp", std::process::id()));
    fs::write(&tmp, bytes)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, path)?;
    Ok(())
}

impl Secret {
    /// A note is one text, so it lists no fields and a picker copies it whole. Any other entry
    /// with no name to list fails, so a picker never mistakes it for a note
    pub(crate) fn field_names(&self) -> Result<Vec<String>> {
        if self.blob {
            return Ok(Vec::new());
        }

        let names = labels(&self.value);
        if names.is_empty() {
            bail!("{} has no field to copy", self.name);
        }
        Ok(names)
    }

    /// One field, and none from a note, which is one text
    pub(crate) fn field(&self, want: &str) -> Result<String> {
        if self.blob {
            bail!(
                "{} is a note, which has no fields, read it without --field",
                self.name
            );
        }

        pick(&self.name, &self.value, want)
    }
}

/* The `pass` layout, which import keeps: the first line is the secret and later `key: value`
lines are fields. Reading one field hands a caller the password without the note beside it. */
pub(crate) fn fields(value: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut lines = value.lines();
    if let Some(first) = lines.next() {
        out.push(("password".to_string(), first.to_string()));
    }
    for line in lines {
        if let Some((key, v)) = line.split_once(':') {
            let (key, v) = (key.trim().to_lowercase(), v.trim());
            if !key.is_empty() && !v.is_empty() {
                out.push((key, v.to_string()));
            }
        }
    }
    out
}

/// One field of a value, where an empty first line is no password
pub(crate) fn pick(name: &str, value: &str, want: &str) -> Result<String> {
    if want == "password" && value.lines().next().is_none_or(str::is_empty) {
        bail!("{name} has no password, read one of its fields with --field");
    }

    // A key written twice reads as its last value
    fields(value)
        .into_iter()
        .rev()
        .find(|(key, _)| key == want)
        .map(|(_, v)| v)
        .with_context(|| format!("{name} has no field {want}"))
}

/// The fields `get --field` reads, each once and in the order they are written, and no value
pub(crate) fn labels(value: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (key, v) in fields(value) {
        if !v.is_empty() && looks_like_a_label(&key) && !out.contains(&key) {
            out.push(key);
        }
    }
    out
}

/* A note's free text can hold `my pin is 4821: bank` or a token before a colon, which the parse
reads as a key. Listing only short, plain names keeps such a line out of a picker and its logs,
and `--field` still reads it by its exact name */
fn looks_like_a_label(key: &str) -> bool {
    let plain = key
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '_' | '.' | '-'));
    let digits = key
        .split(|c: char| !c.is_ascii_digit())
        .all(|run| run.len() < 4);
    plain
        && digits
        && key.chars().count() <= 32
        && key.split_whitespace().all(|w| w.chars().count() <= 20)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_follow_the_order_written_and_skip_an_empty_password() {
        let login = "pw\nusername: gb\nurl: x\na note line\npassword 2: b\nurl: y";
        assert_eq!(labels(login), ["password", "username", "url", "password 2"]);
        let note = "\nbank: itau\npix: me@x";
        assert_eq!(labels(note), ["bank", "pix"]);
        // A note line that only happens to hold a colon names no field a picker should show
        let text = "pw\nuser: gb\nmy pin is 4821: bank\nsk_live_9f3a8c2b7d6e5f4a3b2c1d: old";
        assert_eq!(labels(text), ["password", "user"]);
        assert_eq!(labels(""), Vec::<String>::new());
    }

    #[test]
    fn removing_an_old_name_index_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store {
            dir: dir.path().to_path_buf(),
        };
        std::fs::write(dir.path().join("names"), "a/one\n").unwrap();
        store.remove_name_index().unwrap();
        assert!(!dir.path().join("names").exists());
        store.remove_name_index().unwrap();
    }

    #[cfg(feature = "host")]
    #[test]
    fn a_stamp_goes_stale_when_the_entry_is_rewritten_or_deleted() {
        let (_tmp, store, key) = store();
        let secret = |v: &str| Secret {
            name: "a/b".into(),
            value: v.into(),
            created: 0,
            updated: 0,
            blob: false,
        };
        store.put("id1", &secret("one"), &key).unwrap();
        let stamp = store.stamp("id1").unwrap();
        assert!(store.is_current("id1", stamp));

        store.delete("id1", &key).unwrap();
        assert!(!store.is_current("id1", stamp));

        store.put("id1", &secret("two"), &key).unwrap();
        assert!(!store.is_current("id1", stamp));
        assert!(store.is_current("id1", store.stamp("id1").unwrap()));
    }

    fn store() -> (tempfile::TempDir, Store, x25519::Identity) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store {
            dir: tmp.path().to_path_buf(),
        };
        let pass = SecretString::from("hunter2".to_string());
        let key = store.init().unwrap();
        store
            .create_recovery_wrap_with_factor(&key, pass, Some(10))
            .unwrap();
        (tmp, store, key)
    }

    fn secret(name: &str, value: &str) -> Secret {
        Secret {
            name: name.to_string(),
            value: value.to_string(),
            created: now(),
            updated: now(),
            blob: false,
        }
    }

    /// What anyone holding a synced copy can write: a file the store key opens, sealed by `sealer`
    fn planted(store: &Store, secret: &Secret, sealer: Option<&x25519::Identity>) -> String {
        let id = new_id();
        let mut json = serde_json::to_value(secret).unwrap();
        if let Some(sealer) = sealer {
            let seal = mac(sealer, &id, secret).unwrap().finalize().into_bytes();
            json["seal"] = hex::encode(seal).into();
        }
        let to = store.recipient().unwrap();
        let ct = crypto::encrypt(json.to_string().as_bytes(), &[Box::new(to)]).unwrap();
        write_private(&store.secret_path(&id), &ct).unwrap();
        id
    }

    /* age lets anyone with the public recipient, which sits in every synced copy, write a file the
    store key opens. Without this store's tag it is skipped, so it neither shadows nor adds a name */
    #[test]
    fn a_file_planted_with_the_public_recipient_is_skipped() {
        let (_tmp, store, key) = store();
        store
            .put(&new_id(), &secret("wallet/main", "mine"), &key)
            .unwrap();
        let theirs = planted(&store, &secret("wallet/main", "theirs"), None);
        planted(&store, &secret("extra/name", "theirs"), None);

        assert_eq!(
            store.find("wallet/main", &key).unwrap().unwrap().1.value,
            "mine"
        );
        assert_eq!(store.names(&key).unwrap(), ["wallet/main"]);
        let Err(err) = store.load(&theirs, &key) else {
            panic!("a planted file loaded");
        };
        assert!(err.to_string().contains("not sealed"), "{err}");
    }

    #[test]
    fn a_seal_another_key_made_is_refused() {
        let (_tmp, store, key) = store();
        let other = x25519::Identity::generate();
        let id = planted(&store, &secret("wallet/main", "theirs"), Some(&other));
        let Err(err) = store.load(&id, &key) else {
            panic!("a forged seal loaded");
        };
        assert!(
            err.to_string().contains("seal this store did not make"),
            "{err}"
        );
    }

    /// A sealed file copied to another id would let an old value sit beside the current one
    #[test]
    fn a_seal_moved_to_another_id_is_refused() {
        let (_tmp, store, key) = store();
        let id = new_id();
        store.put(&id, &secret("wallet/main", "old"), &key).unwrap();
        let moved = new_id();
        fs::copy(store.secret_path(&id), store.secret_path(&moved)).unwrap();
        let Err(err) = store.load(&moved, &key) else {
            panic!("a moved seal loaded");
        };
        assert!(err.to_string().contains("for this file"), "{err}");
    }

    /* A Mac that joins a store another Mac already sealed has no marker yet. The sealed files show
    the store upgraded, so an unsigned one beside them was planted and is not sealed with them */
    #[test]
    fn a_mac_joining_a_sealed_store_does_not_seal_a_planted_file() {
        let (_tmp, store, key) = store();
        store
            .put(&new_id(), &secret("wallet/main", "mine"), &key)
            .unwrap();
        let theirs = planted(&store, &secret("wallet/other", "theirs"), None);
        fs::remove_file(store.signed_path()).unwrap();

        store
            .unlock_with_passphrase(SecretString::from("hunter2".to_string()))
            .unwrap();
        assert!(store.load(&theirs, &key).is_err());
        assert_eq!(store.names(&key).unwrap(), ["wallet/main"]);
    }

    /// A file that does not open is moved aside, so it neither keeps the store unsealed nor locks it
    #[test]
    fn one_broken_file_is_moved_aside_on_upgrade() {
        let (_tmp, store, key) = store();
        fs::remove_file(store.pin_path()).unwrap();
        fs::remove_file(store.signed_path()).unwrap();
        let mine = planted(&store, &secret("wallet/main", "mine"), None);
        let broken = new_id();
        write_private(&store.secret_path(&broken), b"not age").unwrap();

        store
            .unlock_with_passphrase(SecretString::from("hunter2".to_string()))
            .unwrap();
        assert!(store.sealed());
        assert_eq!(store.load(&mine, &key).unwrap().value, "mine");
        assert!(!store.secret_path(&broken).exists());
        let aside = store
            .secrets_dir()
            .join(".quarantine")
            .join(format!("{broken}.age"));
        assert!(aside.exists(), "the broken file was lost");
    }

    /* A Mac joining takes the store from a copy that may have had its sealed files taken out and its
    own planted, so it adopts nothing unsealed */
    #[test]
    fn a_joining_mac_adopts_nothing_unsealed() {
        let (_tmp, store, key) = store();
        fs::remove_file(store.pin_path()).unwrap();
        fs::remove_file(store.signed_path()).unwrap();
        let theirs = planted(&store, &secret("github/token", "theirs"), None);

        store.join().unwrap();
        store
            .unlock_with_passphrase(SecretString::from("hunter2".to_string()))
            .unwrap();
        assert!(
            store.load(&theirs, &key).is_err(),
            "a joining Mac adopted a planted file"
        );
    }

    /* A first seal cut off by a crash or a full disk left some files sealed. This Mac began it, so the
    next unlock seals the rest rather than refusing them as another Mac's leftovers */
    #[test]
    fn a_first_seal_cut_off_midway_resumes() {
        let (_tmp, store, key) = store();
        fs::remove_file(store.signed_path()).unwrap();
        let old: Vec<String> = (0..4)
            .map(|n| planted(&store, &secret(&format!("old/{n}"), "v"), None))
            .collect();
        store
            .put(&new_id(), &secret("done/one", "v"), &key)
            .unwrap();
        let list: String = old
            .iter()
            .filter_map(|id| file_line(&store.secret_path(id)))
            .collect();
        write_private(&store.sealing_path(), list.as_bytes()).unwrap();
        // A sync brought this in after the cut-off, so it is not on the list
        let theirs = planted(&store, &secret("old/9", "theirs"), None);

        store
            .unlock_with_passphrase(SecretString::from("hunter2".to_string()))
            .unwrap();
        for id in &old {
            assert!(
                store.load(id, &key).is_ok(),
                "a file the cut-off seal missed was refused"
            );
        }
        assert!(
            store.load(&theirs, &key).is_err(),
            "the resume adopted a file it never listed"
        );
        assert!(!store.sealing_path().exists());
    }

    /* A backup last written by passbox 2.4.1 holds no sealed file. A Mac restoring it adopts nothing
    on its own, and `machine add` seals the lot once the person says the copy is theirs */
    #[test]
    fn a_copy_with_no_seal_is_adopted_only_when_asked() {
        let (_tmp, store, key) = store();
        fs::remove_file(store.pin_path()).unwrap();
        fs::remove_file(store.signed_path()).unwrap();
        let old = planted(&store, &secret("github/token", "mine"), None);

        store.join().unwrap();
        store
            .unlock_with_passphrase(SecretString::from("hunter2".to_string()))
            .unwrap();
        assert!(store.load(&old, &key).is_err());

        let (files, any_sealed) = store.by_seal(&key).unwrap();
        assert!(!any_sealed);
        store.seal_files(&files, &key, |_| true).unwrap();
        assert_eq!(store.load(&old, &key).unwrap().value, "mine");
    }

    /* A version kept before this Mac sealed its files is its own and comes back sealed. An unsealed one
    kept after was a refused file a write moved aside, and restoring it is refused */
    #[test]
    fn only_a_version_kept_before_sealing_is_restored_unsealed() {
        let (_tmp, store, key) = store();
        let id = planted(&store, &secret("db/pass", "old"), None);
        store.keep_version(&id).unwrap();
        store.put(&id, &secret("db/pass", "new"), &key).unwrap();
        let (_, old) = store.versions(&id).unwrap().into_iter().next().unwrap();

        write_private(&store.signed_path(), b"1").unwrap();
        let Err(err) = store.restore_version(&id, &old, &key) else {
            panic!("an unsealed version kept after sealing came back");
        };
        assert!(err.to_string().contains("did not write it here"), "{err}");

        let later = (now() + 60).to_string();
        write_private(&store.signed_path(), later.as_bytes()).unwrap();
        store.restore_version(&id, &old, &key).unwrap();
        assert_eq!(store.load(&id, &key).unwrap().value, "old");
    }

    /* A synced copy that swapped wraps/recipient for its own key would get every later write. The pin
    still names the store's key, and opening the store puts the store's own file back */
    #[test]
    fn a_swapped_recipient_changes_nothing_and_is_put_back_on_unlock() {
        let (_tmp, store, key) = store();
        let theirs = x25519::Identity::generate().to_public().to_string();
        write_private(&store.recipient_path(), theirs.as_bytes()).unwrap();
        // The pin names the recipient, so a write or an audit line still goes to the store's key
        assert_eq!(
            store.recipient().unwrap().to_string(),
            key.to_public().to_string()
        );

        store
            .unlock_with_passphrase(SecretString::from("hunter2".to_string()))
            .unwrap();
        assert_eq!(
            store.recipient().unwrap().to_string(),
            key.to_public().to_string()
        );
    }

    /// A wrap is a key sealed to a public key, so a copy can plant one that opens to its own key
    #[test]
    fn a_wrap_that_opens_another_key_is_refused() {
        let (_tmp, store, _key) = store();
        let theirs = x25519::Identity::generate();
        store
            .create_recovery_wrap_with_factor(
                &theirs,
                SecretString::from("theirs".to_string()),
                Some(10),
            )
            .unwrap();
        let Err(err) = store.unlock_with_passphrase(SecretString::from("theirs".to_string()))
        else {
            panic!("the wrong key opened");
        };
        assert!(
            err.to_string().contains("not the store key this Mac knows"),
            "{err}"
        );
    }

    /// An upgraded Mac trusts the files it already has once, signs them, and from then on refuses
    /// an unsigned one. With no pin yet, a recipient and key that disagree pin nothing
    #[test]
    fn the_first_unlock_after_an_upgrade_signs_what_is_there() {
        let (_tmp, store, key) = store();
        fs::remove_file(store.pin_path()).unwrap();
        fs::remove_file(store.signed_path()).unwrap();
        let old = planted(&store, &secret("db/old", "v"), None);
        assert_eq!(store.load(&old, &key).unwrap().value, "v");

        store
            .unlock_with_passphrase(SecretString::from("hunter2".to_string()))
            .unwrap();
        let (_, signed) = open(&store.secret_path(&old), &old, &key).unwrap();
        assert!(signed, "not sealed");
        let late = planted(&store, &secret("db/late", "v"), None);
        assert!(store.load(&late, &key).is_err());

        fs::remove_file(store.pin_path()).unwrap();
        let theirs = x25519::Identity::generate().to_public().to_string();
        write_private(&store.recipient_path(), theirs.as_bytes()).unwrap();
        let Err(err) = store.unlock_with_passphrase(SecretString::from("hunter2".to_string()))
        else {
            panic!("the wrong key opened");
        };
        assert!(err.to_string().contains("disagree"), "{err}");
        assert!(!store.pin_path().exists());
    }

    #[test]
    fn round_trip_by_name() {
        let (_tmp, store, key) = store();
        store
            .put(&new_id(), &secret("github/token", "ghp_abc"), &key)
            .unwrap();

        let (_id, found) = store.find("github/token", &key).unwrap().unwrap();
        assert_eq!(found.value, "ghp_abc");
        assert!(store.find("missing", &key).unwrap().is_none());
    }

    #[test]
    fn filename_never_holds_the_name() {
        let (_tmp, store, key) = store();
        store
            .put(&new_id(), &secret("github/token", "ghp_abc"), &key)
            .unwrap();

        for id in store.ids().unwrap() {
            assert!(!id.contains("github"));
            assert!(!id.contains("token"));
            let raw = fs::read(store.secret_path(&id)).unwrap();
            assert!(!String::from_utf8_lossy(&raw).contains("github"));
        }
    }

    #[test]
    fn wrong_passphrase_is_refused() {
        let (_tmp, store, _key) = store();
        let wrong = SecretString::from("hunter3".to_string());
        assert!(store.unlock_with_passphrase(wrong).is_err());
    }

    #[test]
    fn overwrite_keeps_a_version() {
        let (_tmp, store, key) = store();
        let id = new_id();
        store.put(&id, &secret("db", "old"), &key).unwrap();
        store.put(&id, &secret("db", "new"), &key).unwrap();

        assert_eq!(store.load(&id, &key).unwrap().value, "new");
        assert_eq!(store.versions(&id).unwrap().len(), 1);
    }

    #[test]
    fn versions_are_trimmed() {
        let (_tmp, store, key) = store();
        let id = new_id();
        for i in 0..KEEP_VERSIONS + 4 {
            store
                .put(&id, &secret("db", &format!("v{i}")), &key)
                .unwrap();
        }
        assert_eq!(store.versions(&id).unwrap().len(), KEEP_VERSIONS);
    }

    #[test]
    fn delete_leaves_a_tombstone_and_hides_the_id() {
        let (_tmp, store, key) = store();
        let id = new_id();
        store.put(&id, &secret("db", "v"), &key).unwrap();
        store.delete(&id, &key).unwrap();

        assert_eq!(store.ids().unwrap(), Vec::<String>::new());
        assert!(store.tomb_path(&id).exists());
        assert_eq!(store.versions(&id).unwrap().len(), 1);
    }

    #[test]
    fn writing_again_clears_the_tombstone() {
        let (_tmp, store, key) = store();
        let id = new_id();
        store.put(&id, &secret("db", "v"), &key).unwrap();
        store.delete(&id, &key).unwrap();
        store.put(&id, &secret("db", "back"), &key).unwrap();

        assert_eq!(store.ids().unwrap().len(), 1);
        assert_eq!(store.load(&id, &key).unwrap().value, "back");
    }

    /// A name added back reuses its id, so a copy that puts the old sealed tombstone back must not
    /// prune the history of the secret that lives there now
    #[test]
    fn an_old_tombstone_beside_a_live_secret_prunes_nothing() {
        let (_tmp, store, key) = store();
        let id = new_id();
        store.put(&id, &secret("db", "v1"), &key).unwrap();
        store.delete(&id, &key).unwrap();
        store.put(&id, &secret("db", "v2"), &key).unwrap();
        store.write_tomb(&id, 1, &key).unwrap();

        assert_eq!(store.prune_tombs(&key).unwrap(), 0);
        assert!(store.versions_dir().join(&id).exists());
    }

    #[test]
    fn fresh_tombstones_survive_pruning() {
        let (_tmp, store, key) = store();
        let id = new_id();
        store.put(&id, &secret("db", "v"), &key).unwrap();
        store.delete(&id, &key).unwrap();

        assert_eq!(store.prune_tombs(&key).unwrap(), 0);
        // A copy's tombstone, old and unsealed, would prune the history if it were trusted
        write_private(&store.tomb_path(&id), b"1").unwrap();
        assert_eq!(store.prune_tombs(&key).unwrap(), 0);
        assert!(store.versions_dir().join(&id).exists());

        store.write_tomb(&id, 1, &key).unwrap();
        assert_eq!(store.prune_tombs(&key).unwrap(), 1);
        assert!(!store.versions_dir().join(&id).exists());
    }

    /* The reference `age` CLI is a separate implementation in another language. If it can open
    what we wrote, the files are standard age files rather than something only this crate reads,
    and the store stays recoverable with off the shelf tools if passbox ever goes away. */
    #[test]
    fn a_secret_file_opens_with_the_reference_age_cli() {
        let Ok(age_cli) = which("age") else {
            eprintln!("skipped, the age CLI is not installed");
            return;
        };
        let (tmp, store, key) = store();
        let id = new_id();
        store.put(&id, &secret("db", "swordfish"), &key).unwrap();

        let identity = tmp.path().join("identity.txt");
        fs::write(
            &identity,
            secrecy::ExposeSecret::expose_secret(&key.to_string()),
        )
        .unwrap();

        let out = std::process::Command::new(age_cli)
            .arg("--decrypt")
            .arg("-i")
            .arg(&identity)
            .arg(store.secret_path(&id))
            .output()
            .unwrap();

        assert!(
            out.status.success(),
            "age refused our file: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let plain = String::from_utf8_lossy(&out.stdout);
        assert!(plain.contains("swordfish"), "{plain}");
        assert!(plain.contains("\"name\":\"db\""), "{plain}");
    }

    fn which(tool: &str) -> Result<PathBuf> {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {tool}"))
            .output()?;
        let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if path.is_empty() {
            bail!("{tool} not found");
        }
        Ok(PathBuf::from(path))
    }

    #[cfg(feature = "host")]
    #[test]
    fn a_tampered_audit_line_is_refused() {
        let (_tmp, store, key) = store();
        let line = crypto::encrypt_line(b"{\"at\":1}", &store.recipient().unwrap()).unwrap();

        assert!(crypto::decrypt_line(&line, &key).is_ok());

        let mut bytes = line.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'a' { b'b' } else { b'a' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(crypto::decrypt_line(&tampered, &key).is_err());
    }

    /// A flipped byte must fail rather than hand back something that looks like a secret
    #[test]
    fn a_tampered_secret_file_is_refused() {
        let (_tmp, store, key) = store();
        let id = new_id();
        store.put(&id, &secret("db", "swordfish"), &key).unwrap();

        let path = store.secret_path(&id);
        let mut raw = fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        fs::write(&path, &raw).unwrap();

        let opened = store.load(&id, &key);
        assert!(opened.is_err(), "a tampered file decrypted");
    }

    #[test]
    fn a_truncated_secret_file_is_refused() {
        let (_tmp, store, key) = store();
        let id = new_id();
        store.put(&id, &secret("db", "swordfish"), &key).unwrap();

        let path = store.secret_path(&id);
        let raw = fs::read(&path).unwrap();
        fs::write(&path, &raw[..raw.len() / 2]).unwrap();

        assert!(store.load(&id, &key).is_err());
    }

    #[test]
    fn a_tampered_recovery_wrap_is_refused() {
        let (_tmp, store, _key) = store();
        let path = store.wraps_dir().join("recovery.age");
        let mut raw = fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        fs::write(&path, &raw).unwrap();

        let pass = SecretString::from("hunter2".to_string());
        assert!(store.unlock_with_passphrase(pass).is_err());
    }

    /* A copy that adds its own "YubiKey" to the list would get the store key at the next yubikey-add.
    The seal shows the list is one this store wrote, a line added after it is refused, and a list from
    before sealing is reported unsealed, so a person checks it */
    #[cfg(feature = "host")]
    #[test]
    fn a_yubikey_list_a_copy_added_to_is_refused() {
        let (_tmp, store, key) = store();
        let mine = vec!["age1yubikey1mine".to_string()];
        write_private(&store.yubikey_recipients_path(), mine.join("\n").as_bytes()).unwrap();
        let (_, sealed) = store.yubikey_list(&key).unwrap();
        assert!(!sealed, "a list with no seal passed as sealed");

        let seal = hex::encode(list_mac(&key, &mine).unwrap().finalize().into_bytes());
        write_private(&store.yubikey_seal_path(), seal.as_bytes()).unwrap();
        assert_eq!(store.yubikey_list(&key).unwrap(), (mine, true));

        let added = "age1yubikey1mine\nage1yubikey1theirs";
        write_private(&store.yubikey_recipients_path(), added.as_bytes()).unwrap();
        let Err(err) = store.yubikey_list(&key) else {
            panic!("a list with a line added passed");
        };
        assert!(err.to_string().contains("changed outside passbox"), "{err}");
    }

    #[cfg(feature = "host")]
    #[test]
    fn yubikey_recipients_accumulate_on_disk() {
        let (_tmp, store, _key) = store();
        assert_eq!(store.yubikey_recipients(), Vec::<String>::new());

        write_private(
            &store.yubikey_recipients_path(),
            b"age1yubikey1aaa\nage1yubikey1bbb\n",
        )
        .unwrap();
        assert_eq!(
            store.yubikey_recipients(),
            vec!["age1yubikey1aaa", "age1yubikey1bbb"]
        );
    }

    #[cfg(feature = "host")]
    #[test]
    fn a_yubikey_wrap_counts_as_a_way_off_this_mac() {
        let (_tmp, store, _key) = store();
        assert!(
            store.has_portable_wrap(),
            "the test store has a passphrase wrap"
        );

        fs::remove_file(store.wraps_dir().join("recovery.age")).unwrap();
        assert!(!store.has_portable_wrap());

        write_private(&store.yubikey_wrap_path(), b"x").unwrap();
        assert!(store.has_portable_wrap());
    }

    #[test]
    fn init_refuses_twice() {
        let (_tmp, store, _key) = store();
        assert!(store.init().is_err());
    }

    #[test]
    fn a_blob_flag_survives_and_an_old_entry_reads_as_not_a_blob() {
        let (_tmp, store, key) = store();
        let mut blob = secret("tls/key", "a\nb: c");
        blob.blob = true;
        store.put("id1", &blob, &key).unwrap();
        store.put("id2", &secret("plain", "x"), &key).unwrap();

        assert!(store.load("id1", &key).unwrap().blob);
        assert!(!store.load("id2", &key).unwrap().blob);
        let old: Secret =
            serde_json::from_str(r#"{"name":"n","value":"v","created":1,"updated":1}"#).unwrap();
        assert!(!old.blob);
    }
}
