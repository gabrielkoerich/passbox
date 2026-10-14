//! The Secure Enclave helper's commands with no Enclave and no prompt, for `mock-enclave` tests.
//! Each prompt goes to `PASSBOX_FAKE_ENCLAVE_LOG`. `<log>.deny` holds `all`, a count or `unavailable`,
//! and while `<log>.hold` exists a prompt stays open, as it does when nobody is at the Mac

use std::io::{Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let pair = serde_json::json!({ "public_key": "ZmFrZQ==", "key_blob": "ZmFrZQ==" });
            println!("{pair}");
        }
        // The value comes back on unwrap untouched, there is no secrecy to keep in a test store
        Some("wrap") => {
            let request = stdin_json();
            let sealed = serde_json::json!({
                "ephemeral": "ZmFrZQ==",
                "ciphertext": request["plaintext"],
            });
            println!("{sealed}");
        }
        Some("unwrap") if args.len() == 3 && args[1] == "--reason" => unwrap(&args[2]),
        Some("clip") if args.len() == 3 && args[1] == "--clear" => clip(&args[2]),
        _ => {
            fail("usage: fake-enclave keygen | wrap | unwrap --reason <text> | clip --clear <secs>")
        }
    }
}

// A file stands in for the pasteboard, and the clear timeout is kept so a test can check it
fn clip(secs: &str) {
    let log = std::env::var("PASSBOX_FAKE_ENCLAVE_LOG").unwrap_or_else(|_| fail("no prompt log"));
    let mut value = String::new();
    std::io::stdin()
        .read_to_string(&mut value)
        .expect("read stdin");
    std::fs::write(format!("{log}.clipboard"), value).expect("write the clipboard");
    std::fs::write(format!("{log}.clear"), secs).expect("write the clear timeout");
    println!("ok");
}

fn unwrap(reason: &str) {
    let request = stdin_json();
    if let Ok(log) = std::env::var("PASSBOX_FAKE_ENCLAVE_LOG") {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .expect("open the prompt log");
        writeln!(file, "{reason}").expect("write the prompt log");
        drop(file);
        let hold = format!("{log}.hold");
        while std::path::Path::new(&hold).exists() {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let deny = format!("{log}.deny");
        // The real helper's wording for a closed lid, where no prompt can be shown at all
        if std::fs::read_to_string(&deny).is_ok_and(|t| t.trim() == "unavailable") {
            fail("Touch ID is unavailable on this Mac right now (the fake enclave)");
        }
        if refuse(&deny) {
            fail("denied: the fake enclave refused");
        }
    }
    let ciphertext = request["ciphertext"].as_str().expect("ciphertext");
    std::io::stdout()
        .write_all(&decode(ciphertext))
        .expect("write the plaintext");
}

// `all` refuses every prompt, a number refuses that many and counts down
fn refuse(path: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    match text.trim() {
        "all" => true,
        count => match count.parse::<u32>() {
            Ok(left) if left > 0 => {
                std::fs::write(path, (left - 1).to_string()).expect("count down");
                true
            }
            _ => false,
        },
    }
}

fn stdin_json() -> serde_json::Value {
    let mut text = String::new();
    std::io::stdin()
        .read_to_string(&mut text)
        .expect("read stdin");
    serde_json::from_str(&text).unwrap_or_else(|_| fail("stdin is not json"))
}

fn decode(text: &str) -> Vec<u8> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => fail("bad base64"),
    };
    let mut out = Vec::new();
    for chunk in text.trim_end_matches('=').as_bytes().chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= u32::from(value(c)) << (18 - 6 * i);
        }
        out.extend_from_slice(&n.to_be_bytes()[1..chunk.len()]);
    }
    out
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}
