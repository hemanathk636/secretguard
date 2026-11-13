class Secretguard < Formula
  desc "Sub-millisecond terminal secret and privacy guard for developers and AI agents"
  homepage "https://github.com/hemanathk636/secretguard"
  version "0.1.1"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/hemanathk636/secretguard/releases/download/v0.1.1/secretguard-aarch64-apple-darwin.tar.gz"
    else
      url "https://github.com/hemanathk636/secretguard/releases/download/v0.1.1/secretguard-x86_64-apple-darwin.tar.gz"
    end
  end

  on_linux do
    url "https://github.com/hemanathk636/secretguard/releases/download/v0.1.1/secretguard-x86_64-unknown-linux-gnu.tar.gz"
  end

  def install
    bin.install "secretguard"
  end

  test do
    system "#{bin}/secretguard", "check", "git status"
  end
end
