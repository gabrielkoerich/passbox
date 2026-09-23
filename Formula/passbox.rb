class Passbox < Formula
  desc "Password store that asks for a fingerprint before an agent reads a secret"
  homepage "https://github.com/gabrielkoerich/passbox"
  url "https://github.com/gabrielkoerich/passbox/archive/refs/tags/v0.1.0.tar.gz"
  sha256 ""
  head "https://github.com/gabrielkoerich/passbox.git", branch: "main"
  license "MIT"

  depends_on "rust" => :build
  depends_on :macos

  def install
    system "cargo", "install", *std_cargo_args
  end

  def caveats
    <<~EOS
      Run `passbox init` to create the store at ~/.passbox.

      Keep the recovery passphrase somewhere safe. It is the only way back if you
      lose this Mac, because the Secure Enclave key cannot leave it.
    EOS
  end

  test do
    assert_match "passbox", shell_output("#{bin}/passbox --version")
  end
end
