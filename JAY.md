# Jay's EasyTier build

This branch is upstream EasyTier at a pinned tag plus a few small hardening patches for
[Jay](https://github.com/warriorleavestar/jay-launcher). Jay ships these builds instead of the
upstream release zips. EasyTier is LGPL-3.0, and so is everything here.

## Base

- Upstream tag: `v2.6.4` (commit `8428a89d2dabc94c97d370ec607c6ca142473626`)
- Branch: `jay/v2.6.4`

## Patches

1. **No silent cipher fallback, no xor.** An unknown `--encryption-algorithm` used to fall back
   to the default with a warning, and `xor` was accepted. Both now get a cipher that refuses every
   packet, so traffic is dropped rather than sent weakly. The build fails to compile without an
   AEAD feature. (`easytier/src/peers/encrypt/mod.rs`)
2. **Management API on loopback only.** A bare `--rpc-portal <port>` used to bind `0.0.0.0`, and
   any address was accepted. It now binds `127.0.0.1`, and a non-loopback address is an error.
   (`easytier/src/rpc_service/api.rs`)
3. **No remote management.** `--config-server` hands the whole node to a web console on another
   machine. Jay never uses it, so `easytier-core` refuses to start with it. (`easytier/src/core.rs`)
4. **Fewer features.** Built with `--no-default-features --features
   wireguard,smoltcp,tun,socks5,quic,zstd`. Websocket, KCP, FakeTCP and magic DNS are left out.
5. **Build hygiene** (`.github/workflows/jay-build.yml`):
   - The build runs with `--locked`, and `cargo audit` runs on every build.
   - protoc is downloaded with a pinned SHA-256, not by the Windows build script.
   - The prebuilt Windows files in `easytier/third_party` are pinned by SHA-256. wintun and the
     WinDivert driver must carry valid Authenticode signatures.

## What Jay should also do (not patches)

- Start `easytier-core` with `--secure-mode` (Noise XX key exchange with a network-secret proof)
  and an explicit `--encryption-algorithm`. Without secure mode, the data key is derived from the
  network secret with a fast, unkeyed hash (SipHash via `DefaultHasher`). That key is static and
  has no forward secrecy. Check compatibility with the relay nodes Jay uses before turning it on.

## Updating to a new upstream version

1. Read the upstream diff between the old and the new tag, paying most attention to
   `Cargo.lock`, `build.rs`, `easytier/third_party` and anything that touches the network.
2. Create `jay/<new tag>` from the new tag, and cherry-pick the patch commits from this branch.
3. Update the pins in the workflow if `third_party` changed (and say why in the commit).
4. Tag `jay-v<version>-<n>`. The release job publishes the zips and `SHA256SUMS.txt`.
5. In Jay, update the version, asset names, sizes and SHA-256 values in
   `src/Amber.Core/Multiplayer/EasyTier.cs`.
