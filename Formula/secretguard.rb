class Secretguard < Formula
  desc "Sub-millisecond terminal secret and privacy guard for developers and AI agents"
  homepage "https://github.com/hemanathk636/secretguard"
  version "0.2.1"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/hemanathk636/secretguard/releases/download/v0.2.1/secretguard-aarch64-apple-darwin.tar.gz"
      sha256 "9f99e6b81ce0cdc44de4a09c422ec2dc55d9f681f2c719f6aaf9713dbbc1ab79"
    else
      url "https://github.com/hemanathk636/secretguard/releases/download/v0.2.1/secretguard-x86_64-apple-darwin.tar.gz"
      sha256 "ff01781de91a64798181b959d23fe680bcfc8f6607006995e420fbe8159d32d5"
    end
  end

  on_linux do
    url "https://github.com/hemanathk636/secretguard/releases/download/v0.2.1/secretguard-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "9c350a93a8ef85173b84f4e299739f1fab24053582ab993c4ef7c763ea3b1e0b"
  end

  def install
    bin.install "secretguard"
  end

  test do
    system "#{bin}/secretguard", "check", "git status"
  end
end
