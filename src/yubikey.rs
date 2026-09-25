/* A wrap opened by a YubiKey instead of a passphrase.

The passphrase wrap is the one file in a synced store worth attacking, because it can be ground
offline by anyone holding a copy. This wrap has nothing to grind: the private half lives in the
token's secure element and the copy is inert without it in your hand. */

use age::cli_common::UiCallbacks;
use age::plugin::{Identity, IdentityPluginV1, Recipient, RecipientPluginV1};
use anyhow::{Context, Result, anyhow, bail};
use std::str::FromStr;

/* Two different names. The binary on PATH is `age-plugin-yubikey`, and the name inside a
recipient is `yubikey`, which is what the age plugin API matches on. Comparing a parsed
recipient against the binary name rejects every real token. */
const PLUGIN: &str = "age-plugin-yubikey";
const PLUGIN_NAME: &str = "yubikey";

/// Recipients look like `age1yubikey1...` and identities like `AGE-PLUGIN-YUBIKEY-1...`
pub fn recipient(text: &str) -> Result<Box<dyn age::Recipient + Send>> {
    let parsed = Recipient::from_str(text.trim())
        .map_err(|e| anyhow!("{text} is not an age recipient: {e}"))?;
    if parsed.plugin() != PLUGIN_NAME {
        bail!(
            "{} is a {} recipient, not a YubiKey one",
            text,
            parsed.plugin()
        );
    }
    let name = parsed.plugin().to_string();
    let plugin = RecipientPluginV1::new(&name, &[parsed], &[], UiCallbacks)
        .context("age-plugin-yubikey is not on PATH")?;
    Ok(Box::new(plugin))
}

/// Asks the plugin for whichever token is plugged in, so no identity file has to be kept
pub fn identity() -> Result<Box<dyn age::Identity>> {
    let found = Identity::default_for_plugin(PLUGIN_NAME)
        .map_err(|e| anyhow!("no YubiKey identity: {e}"))?;
    let plugin = IdentityPluginV1::new(PLUGIN_NAME, &[found], UiCallbacks)
        .context("age-plugin-yubikey is not on PATH")?;
    Ok(Box::new(plugin))
}

/* Offer rather than act. Installing software is a change to the user's machine, and this
particular binary goes on to handle key material, so it is not something to do quietly. */
pub fn offer_install() -> Result<()> {
    if installed() {
        return Ok(());
    }
    let brew = std::process::Command::new("brew").arg("--version").output();
    if brew.is_err() || !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        bail!("{PLUGIN} is not on PATH, install it with `brew install {PLUGIN}`");
    }

    eprintln!("passbox needs {PLUGIN} to talk to the token, and it is not installed.");
    eprintln!("It is the age plugin that holds the key in the YubiKey's secure element.");
    eprint!("Install it with Homebrew now? [y/N] ");
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("could not read the answer")?;
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        bail!("install it with `brew install {PLUGIN}` and run this again");
    }

    let status = std::process::Command::new("brew")
        .args(["install", PLUGIN])
        .status()
        .context("could not run brew")?;
    if !status.success() || !installed() {
        bail!("brew could not install {PLUGIN}");
    }
    Ok(())
}

/// None means ykman is missing or the applet could not be read
fn piv_info() -> Option<String> {
    let out = std::process::Command::new("ykman")
        .args(["piv", "info"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/* What the PIV applet already holds. OpenPGP is a separate applet on the same chip, so PGP keys
are never at risk, but a PIV slot in use is worth seeing before provisioning one. None means the
check could not run. */
pub fn piv_slots_in_use() -> Option<Vec<String>> {
    Some(
        piv_info()?
            .lines()
            .filter(|l| l.trim_start().starts_with("Slot "))
            .map(|l| l.trim().to_string())
            .collect(),
    )
}

/* age-plugin-yubikey authenticates with the PIV management key and supports TDES only, so an AES
key fails after the PIN prompt with an error naming neither the cause nor the token. Recent ykman
picks AES192 when it sets a management key, so this is the state a careful user lands in.
See https://github.com/str4d/age-plugin-yubikey/issues/92 */
pub fn management_key_is_supported() -> Result<()> {
    match piv_info() {
        // No ykman, so let the plugin speak for itself
        None => Ok(()),
        Some(info) => check_management_key(&info),
    }
}

fn check_management_key(info: &str) -> Result<()> {
    let Some(algorithm) = info
        .lines()
        .find_map(|l| l.trim().strip_prefix("Management key algorithm:"))
    else {
        return Ok(());
    };
    let algorithm = algorithm.trim();
    if algorithm.eq_ignore_ascii_case("TDES") {
        return Ok(());
    }
    const DEFAULT_TDES: &str = "010203040506070801020304050607080102030405060708";
    bail!(
        "the PIV management key is {algorithm}, and {PLUGIN} can only use TDES.\n\
         Firmware 5.7 sets {algorithm} on a new token and on a factory reset, so this\n\
         is the state a new YubiKey arrives in. Change it, which touches the PIV\n\
         applet only and leaves OpenPGP keys alone:\n\
         \n    ykman piv access change-management-key -a tdes -n {DEFAULT_TDES}\n"
    )
}

/* GPG's scdaemon opens the card exclusively and holds it, so it lands between the plugin's key
generation and its certificate write and the write comes back as an authentication error. The
card is released when scdaemon stops, and gpg-agent starts it again the next time GPG wants it. */
pub fn scdaemon_is_running() -> bool {
    std::process::Command::new("pgrep")
        .args(["-x", "scdaemon"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Stopping another program's daemon is not something to do quietly, so it is offered
pub fn offer_to_stop_scdaemon() -> Result<()> {
    if !scdaemon_is_running() {
        return Ok(());
    }

    eprintln!("GPG's scdaemon is running and is holding the smart card.");
    eprintln!("It takes the card back mid-generation, and the plugin fails with");
    eprintln!("an authentication error that names neither the cause nor the fix.");
    eprintln!("Stopping it frees the card. GPG starts it again on its next use,");
    eprintln!("and your OpenPGP keys and PIN are untouched either way.");
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        bail!("stop it with `gpgconf --kill scdaemon` and run this again");
    }
    eprint!("Stop scdaemon for this step? [y/N] ");

    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("could not read the answer")?;
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        bail!("stop it with `gpgconf --kill scdaemon` and run this again");
    }

    let status = std::process::Command::new("gpgconf")
        .args(["--kill", "scdaemon"])
        .status()
        .context("could not run gpgconf")?;
    if !status.success() || scdaemon_is_running() {
        bail!("scdaemon is still running, stop it with `gpgconf --kill scdaemon`");
    }
    Ok(())
}

/// Recipients already provisioned on whatever token is plugged in
pub fn recipients() -> Result<Vec<String>> {
    let out = std::process::Command::new(PLUGIN)
        .arg("--list")
        .output()
        .context("could not run age-plugin-yubikey")?;

    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().find(|w| w.starts_with("age1yubikey1")))
        .map(str::to_string)
        .collect())
}

/// Provisioning a PIV slot changes the token, so it runs only when the user says so
pub fn generate() -> Result<()> {
    let status = std::process::Command::new(PLUGIN)
        .arg("--generate")
        .status()
        .context("could not run age-plugin-yubikey --generate")?;
    if !status.success() {
        bail!("age-plugin-yubikey --generate did not finish");
    }
    Ok(())
}

pub fn installed() -> bool {
    std::process::Command::new(PLUGIN)
        .arg("--version")
        .output()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_x25519_recipient_is_refused() {
        let err = match recipient("age1yyc8rqn67hcupyasv6d0tdpghndh2nnkk599emt3z8cqzkhr5ccqg4xglx")
        {
            Ok(_) => panic!("an x25519 recipient was accepted as a YubiKey one"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("not an age recipient"), "{err}");
    }

    /* The exact `ykman piv info` shape this has to read, from a 5.7.4 token */
    const AES_INFO: &str = "PIV version:              5.7.4\nPIN tries remaining:      3/3\nManagement key algorithm: AES192\nManagement key is stored on the YubiKey, protected by PIN.\n";

    #[test]
    fn an_aes_management_key_is_refused_with_the_fix() {
        let err = check_management_key(AES_INFO).unwrap_err().to_string();
        assert!(err.contains("AES192"), "{err}");
        assert!(err.contains("change-management-key -a tdes"), "{err}");
    }

    #[test]
    fn a_tdes_management_key_passes() {
        let info = AES_INFO.replace("AES192", "TDES");
        assert!(check_management_key(&info).is_ok());
    }

    #[test]
    fn an_unreadable_applet_does_not_block_the_plugin() {
        assert!(check_management_key("").is_ok());
        assert!(check_management_key("PIV version: 5.7.4\n").is_ok());
    }

    /* A real recipient from a provisioned token. The plugin name inside it is `yubikey`, not the
    binary name, and comparing against the binary rejected every genuine token. */
    #[test]
    fn a_real_yubikey_recipient_is_accepted() {
        const REAL: &str =
            "age1yubikey1q0vlphw7w6z47hqzfl8x950zv7hy66aed5amgcvyx8cu4rqcfh7fswwqa7n";
        let parsed = Recipient::from_str(REAL).expect("a valid yubikey recipient");
        assert_eq!(parsed.plugin(), PLUGIN_NAME);
    }

    #[test]
    fn nonsense_is_refused() {
        assert!(recipient("hello").err().is_some());
        assert!(recipient("").err().is_some());
    }
}
