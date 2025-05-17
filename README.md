# dns-resolver

A simple recursive DNS resolver written in Rust. It listens on `localhost` port `53`, so it requires `sudo` (or administrator privileges) to run.

## Usage

```bash
git clone https://github.com/giorgio-daniele/dns-resolver.git
cd  dns-resolver
cargo run