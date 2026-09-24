/* A wrap opened by a YubiKey instead of a passphrase.

The passphrase wrap is the one file in a synced store worth attacking, because it can be ground
offline by anyone holding a copy. This wrap has nothing to grind: the private half lives in the
token's secure element and the copy is inert without it in your hand. */

use age::cli_common::UiCallbacks;
use age::plugin::{Identity, IdentityPluginV1, Recipient, RecipientPluginV1};
use anyhow::{Context, Result, anyhow, bail};
use std::str::FromStr;

const PLUGIN: &str = "age-plugin-yubikey";

/// Recipients look like `age1yubikey1...` and identities like `AGE-PLUGIN-YUBIKEY-1...`
pub fn recipient(text: &str) -> Result<Box<dyn age::Recipient + Send>> {
    let parsed = Recipient::from_str(text.trim())
        .map_err(|e| anyhow!("{text} is not an age recipient: {e}"))?;
    if parsed.plugin() != PLUGIN {
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
    let found =
        Identity::default_for_plugin(PLUGIN).map_err(|e| anyhow!("no YubiKey identity: {e}"))?;
    let plugin = IdentityPluginV1::new(PLUGIN, &[found], UiCallbacks)
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
    bail!(
        "the PIV management key is {algorithm}, and {PLUGIN} can only use TDES.\n\
         Change it, which leaves your OpenPGP keys and any PIV slot untouched:\n\
         \n    ykman piv access change-management-key -a TDES --protect\n"
    )
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
        assert!(err.contains("change-management-key -a TDES"), "{err}");
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

    #[test]
    fn nonsense_is_refused() {
        assert!(recipient("hello").err().is_some());
        assert!(recipient("").err().is_some());
    }
}
