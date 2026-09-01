# IncomUdon Native Rust

A Rust-native implementation of the IncomUdon client.

This repository is intentionally organized as a workspace so that transport,
cryptography, audio, platform integration, and UI can evolve independently.
The first skeleton does not ship a UI yet; Slint integration is planned after
the protocol and runtime foundations are validated.

## Workspace

- `crates/incomudon-protocol`: versioned wire protocol types and packet codecs.
- `crates/incomudon-crypto`: AES-GCM key derivation and packet encryption helpers.
- `crates/incomudon-audio`: bounded real-time audio-frame queues.
- `crates/incomudon-core`: profiles and platform-neutral application state.
- `crates/incomudon-platform`: traits for Android, desktop, and device services.
- `apps/desktop`: temporary executable entry point; it will become the Slint desktop app.

The normative protocol specification is maintained separately in
[`IncomUdon-Spec`](https://github.com/FriedOUDON/IncomUdon-Spec), currently
version `v0.1.0-draft`.

## Toolchain`n`nThe workspace requires Rust `1.92` or newer because Slint `1.17` has that minimum supported Rust version.`n`n## Development

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p incomudon-desktop
```

## License

MIT. See `LICENSE`.

