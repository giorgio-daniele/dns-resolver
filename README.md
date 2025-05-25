# dns-resolver

A simple, recursive DNS resolver written in Rust. This tool listens on `localhost` port `53` and performs full DNS resolution by querying upstream servers recursively.

Since port `53` is a privileged port, running the resolver requires administrative privileges (`sudo` on Unix-like systems or Administrator rights on Windows).

## Usage

```bash
git clone https://github.com/giorgio-daniele/dns-resolver.git
cargo build
sudo target/debug/dns-resolver
```
