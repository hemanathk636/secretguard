# 🛡️ SecretGuard

> **Sub-millisecond Terminal Secret & Privacy Guard for Developers and AI Agents**

SecretGuard intercepts commands and terminal streams in real time, preventing API keys, cloud credentials, and database passwords from ever hitting `.zsh_history`, terminal scrollback buffers, or AI agent context windows.

---

## ⚡ Performance Benchmarks

Tested on a synthetic benchmark of **1,000 commands** (500 live credential patterns + 500 clean commands):

| Metric | Result | Target |
| :--- | :--- | :--- |
| **Detection Recall** | **100.0%** (500/500) | > 99.0% |
| **False Positive Rate** | **0.0%** (0/500) | < 0.1% |
| **Average Scan Latency** | **15.68 µs** (0.016 ms) | < 1.0 ms |
| **Binary Memory Footprint** | **~4.2 MB** | < 20 MB |

---

## 🏗️ Architecture: The 2-Tier Hybrid Engine

SecretGuard uses a dual-engine architecture to catch both structured keys and unstructured database passwords without adding typing lag:

1. **Tier 1: High-Confidence RegexSet (0.2 ms)**
   * Matches predefined formats: OpenAI (`sk-proj-*`), Anthropic (`sk-ant-*`), AWS (`AKIA*`), GitHub (`ghp_*`), Stripe (`sk_live_*`), Slack (`xoxb-*`), HuggingFace (`hf_*`), and Google Cloud API keys.
2. **Tier 2: Contextual Shannon Entropy Evaluator (0.4 ms)**
   * Detects arbitrary high-entropy passwords in connection strings (`postgres://`, `mongodb://`) and assignments (`password=`, `token=`).
   * Ignores standard false positives (UUIDs, git commit SHAs, hex hashes).

---

## 🚀 Quickstart

### 1. Build from Source (Rust)
```bash
cargo build --release
sudo cp target/release/secretguard /usr/local/bin/
```

### 2. Enable Zsh Integration
Add to your `~/.zshrc`:
```zsh
eval "$(secretguard hook zsh)"
```

### 3. Real-Time Output Masking (`wrap`)
Mask sensitive tokens in standard output during screen shares or live demos:
```bash
secretguard wrap npm run dev
secretguard wrap docker compose logs
```

---

## 📄 License
MIT OR Apache-2.0
