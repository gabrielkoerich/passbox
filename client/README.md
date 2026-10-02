# passbox-client

Read secrets from [passbox](https://passbox.gabrielkoerich.com), or hand one to a child process without holding it.

It shells out to the `passbox` CLI, so it needs `passbox` on `PATH`. No key material enters your process, and the Touch ID prompt, grants and audit log apply as they do to any other caller.

```bash
cargo add passbox-client
```

```rust
use passbox::Passbox;

// One approval covers both secrets for 24 hours
let mut pb = Passbox::new(Some("acme"), Some("my-job"), &["api", "db"]);

// Preferred: the value goes from the broker into the child
let out = pb.run_with("API_KEY", "api", &["./deploy"])?;

// When a library needs the value in-process
let db = pb.fields("db")?;
let password = &db["password"];
```

`cargo run -p passbox-client --example selfcheck` runs a round trip against a throwaway store.
