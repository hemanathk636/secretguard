class Secretguard < Formula
  desc "Sub-millisecond terminal secret and privacy guard for developers and AI agents"
  homepage "https://github.com/hemanathk636/secretguard"
  version "0.1.2"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/hemanathk636/secretguard/releases/download/v0.1.2/secretguard-aarch64-apple-darwin.tar.gz"
      sha256 "56fa356ae5c0a7614127aaf09f8770957acc9886b04d011ccf6c82895128734f"
    else
      url "https://github.com/hemanathk636/secretguard/releases/download/v0.1.2/secretguard-x86_64-apple-darwin.tar.gz"
      sha256 "a4c07c9d0b890f675e5d6954f54578258c64070d7a3a66ce50b2abd5e35587dc"
    end
  end

  on_linux do
    url "https://github.com/hemanathk636/secretguard/releases/download/v0.1.2/secretguard-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "c76966466455a5614f073d7d6861c942fd326ddae2312ad4840754e9ec98f4c2"
  end

  def install
    bin.install "secretguard"
  end

  test do
    system "#{bin}/secretguard", "check", "git status"
  end
end
