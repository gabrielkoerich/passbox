class Passbox < Formula
  desc "Password store that asks for a fingerprint before an agent reads a secret"
  homepage "https://github.com/gabrielkoerich/passbox"
  url "https://github.com/gabrielkoerich/passbox/archive/refs/tags/v0.1.0.tar.gz"
  sha256 ""
  head "https://github.com/gabrielkoerich/passbox.git", branch: "main"
  license "MIT"

  depends_on "rust" => :build
  depends_on :macos

  # build.rs needs swiftc, which ships with the Command Line Tools that Homebrew already
  # requires. `depends_on xcode: :build` would demand a full Xcode.app install instead.

  def install
    system "cargo", "install", *std_cargo_args
  end

  # rclone is deliberately not a dependency. Syncing to a directory, which includes the
  # iCloud Drive folder used by default, is a plain file copy and needs nothing installed.
  def caveats
    <<~EOS
      Run `passbox init` to create the store at ~/.passbox. It binds to this Mac's
      Secure Enclave and asks for nothing else.

      The store opens on this Mac only. Lose the Mac and the secrets are gone.
      `passbox sync --enable` adds a recovery passphrase and a copy elsewhere.

      Install rclone only if you point PASSBOX_REMOTE at a cloud remote such as
      b2:passbox. A directory target needs no extra tools.
    EOS
  end

  test do
    assert_match "passbox", shell_output("#{bin}/passbox --version")
  end
end
