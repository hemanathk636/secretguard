class Secretguard < Formula
  desc "Sub-millisecond terminal secret and privacy guard for developers and AI agents"
  homepage "https://github.com/hemanathk636/secretguard"
  version "0.3.13"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/hemanathk636/secretguard/releases/download/v0.3.13/secretguard-aarch64-apple-darwin.tar.gz"
      sha256 "abfad6bb0bf4824b41d4f8e66d692ef8b394df7636cdf89b5232ad8f964be1d0"
    else
      url "https://github.com/hemanathk636/secretguard/releases/download/v0.3.13/secretguard-x86_64-apple-darwin.tar.gz"
      sha256 "09aef50aa3983bb12cf4014659cad8850ae91b971cb35136e3b7f5e49cf1c854"
    end
  end

  on_linux do
    url "https://github.com/hemanathk636/secretguard/releases/download/v0.3.13/secretguard-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "6e2ed911297558bcc8568334a4eb0e6b22eb9f745259f38962ae5245dba94cee"
  end

  def install
    bin.install "secretguard"
  end

  test do
    system "#{bin}/secretguard", "check", "git status"
  end
end
