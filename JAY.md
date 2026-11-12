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
4. **No VPN portal, no http(s) peer lists.** The WireGuard VPN portal opens an extra public port
   for plain WireGuard clients, and an `http(s)://` peer URL lets that web server choose which
   nodes this one joins. They can't be compiled out separately, so the build refuses them at runtime.
   (`easytier/src/instance/instance.rs`, `easytier/src/connector/mod.rs`)
5. **Fewer features.** Built with `--no-default-features --features
   wireguard,smoltcp,tun,socks5,quic,zstd`. Websocket, KCP, FakeTCP and magic DNS are left out.
6. **No built-in public DNS servers.** When the system resolver failed, upstream also asked two fixed
   public DNS servers, in plain UDP, for the host name. Only the system's own name servers are used now.
   (`easytier/src/common/dns.rs`)
7. **Relay only stays relay only.** With `--disable-p2p` the node answers no address-list or
   hole-punch requests, makes no exception for peers that ask for p2p (`need_p2p`), and doesn't use
   STUN. (`easytier/src/peers/peer_rpc_service.rs`, `easytier/src/connector/`,
   `easytier/src/common/global_ctx.rs`)
8. **Build hygiene** (`.github/workflows/jay-build.yml`):
   - The build runs with `--locked`, and `cargo audit` runs on every build. Any advisory not reviewed
     in `.cargo/audit.toml` fails the build, so no release goes out with an unreviewed advisory.
   - Every GitHub Action is pinned to a commit hash.
   - protoc is downloaded with a pinned SHA-256, not by the Windows build script.
   - The prebuilt Windows files in `easytier/third_party` are pinned by SHA-256. wintun and the
     WinDivert driver must carry valid Authenticode signatures.

## What Jay should also do (not patches)

- Start `easytier-core` with `--secure-mode` (Noise XX key exchange with a network-secret proof)
  and an explicit `--encryption-algorithm`. Without secure mode, the data key is derived from the
  network secret with a fast, unkeyed hash (SipHash via `DefaultHasher`). That key is static and
  has no forward secrecy. Check compatibility with the relay nodes Jay uses before turning it on.

## Security updates

Upstream releases are not taken wholesale. When an upstream release or advisory fixes a security
problem, we write or port the fix on this branch ourselves after reading it. Other upstream changes
are only taken when Jay needs them. Watch the EasyTier repo's releases and the RustSec advisories that
`cargo audit` reports.

### Log

- **jay-v2.6.4-2** (2026-11-11). Checked upstream v2.7.0 and RustSec. Updated within semver:
  quinn-proto 0.11.18 (remote DoS and panics in the QUIC tunnel and proxy), rustls 0.23.46 and
  rustls-webpki 0.103.16 (handshake and certificate checks), h2 0.4.19, bytes 1.11.1,
  crossbeam-channel 0.5.15, crossbeam-epoch 0.9.20, tracing-subscriber 0.3.23, webpki-roots 1.0.10,
  zstd 0.13.4 / zstd-safe 7.4.0 / zstd-sys 2.0.17. Removed the built-in public DNS servers (patch 6).
  Not taken: hickory-proto 0.26 (breaking; see `.cargo/audit.toml`). Upstream's ACL bypass fix does not
  apply (Jay doesn't use EasyTier ACLs).

## Updating to a new upstream version

1. Read the upstream diff between the old and the new tag, paying most attention to
   `Cargo.lock`, `build.rs`, `easytier/third_party` and anything that touches the network.
2. Create `jay/<new tag>` from the new tag, and cherry-pick the patch commits from this branch.
3. Update the pins in the workflow if `third_party` changed (and say why in the commit).
4. Tag `jay-v<version>-<n>`. The release job creates a **draft** release with the zips,
   `SHA256SUMS.txt` and `SIZES.txt`.
5. Have it signed (below), then publish the draft.
6. In Jay, update the version, asset names, sizes, SHA-256 values, full commit and seq in
   `src/Amber.Core/Multiplayer/EasyTier.cs`, and copy `SHA256SUMS.txt` and `SHA256SUMS.txt.sigs` into
   `src/Amber.Core/Multiplayer/EasyTierSigned/`.

## Signing

Every release is signed by 2 of the 3 Jay trustees with their release keys (never their network keys), each with Ed25519 and ML-DSA-65, the same way as a
Jay release but marked as an EasyTier build so the two can't be swapped. The keys stay on the trustees'
offline machines; CI never has one. The seq is 1 for `jay-v2.6.4-1` and one more for every later release.

```bash
gh release download <tag> --repo Yumao-Feather/jay-easytier --pattern 'SHA256SUMS.txt' --dir et
jay-server release prepare --component easytier --tag <tag> --seq <n> --commit <full commit id> --sums et/SHA256SUMS.txt
jay-server release cosign --key jay-release.key --sums et/SHA256SUMS.txt   # each of two trustees, offline
gh release upload <tag> --repo Yumao-Feather/jay-easytier et/SHA256SUMS.txt.sigs
jay-server release verify et/<one package>.zip --component easytier --tag <tag>
```

Jay ships the signature and refuses to install EasyTier when it doesn't verify (once release keys are
built into Jay). Details: `docs/security/release-signing.md` in the Jay repository.
