# EasyTier code map (for Jay)

A map of EasyTier v2.6.4 (`easytier/src`, about 100k lines of Rust), written for the people who
maintain Jay's patched build. It is organised around what Jay uses. `python3 tools/jay-index.py`
builds a searchable symbol index in `.jay-index/`, which is not committed.

## How one `easytier-core` process runs

1. `easytier-core.rs` → `core.rs`: clap options (`Cli`, `NetworkOptions`, `RpcPortalOptions`). The
   options become a `TomlConfigLoader` in `NetworkOptions::merge_into`, which is where every flag
   Jay passes ends up. `run_main` starts the management RPC (`rpc_service/api.rs`) and the
   `NetworkInstanceManager`.
2. `instance_manager.rs` / `launcher.rs`: the `NetworkInstance` lifecycle and the config ↔ API
   conversion (`NetworkConfig`).
3. `instance/instance.rs`: `Instance::run` wires everything for one network. That covers the peer
   manager, listeners, connectors, the virtual NIC or no-TUN mode, the gateway proxies, SOCKS5,
   port forwards, the VPN portal, the DNS server and the Windows UDP broadcast relay.
4. `peers/`: the overlay itself. It covers peer connections and handshakes, encryption, routing,
   relaying for other networks, and peer RPC.
5. `tunnel/`: byte transports between two machines (TCP, UDP, QUIC, WireGuard, WS, FakeTCP, ring).
   `connector/` dials them and `instance/listeners.rs` accepts them.
6. `gateway/`: turns IP packets into sockets (smoltcp user-space stack, TCP, UDP and ICMP proxies,
   KCP and QUIC proxies, SOCKS5 server). This is what makes `--no-tun` and `--port-forward` work.

## Folders

| Folder | What it does | Start with |
|---|---|---|
| `common/` | Config (`config.rs`: `TomlConfigLoader`, `Flags`, `NetworkIdentity`, `EncryptionAlgorithm`), global state (`global_ctx.rs`: `GlobalCtx`, **key derivation `get_128_key`/`get_256_key`**), ACLs (`acl_processor.rs`), STUN and NAT type (`stun.rs`), UPnP, interface configuration per OS (`ifcfg/`), machine id, logging | `config.rs`, `global_ctx.rs` |
| `peers/` | `peer_manager.rs` (send/receive pipeline, encryption choice, foreign networks), `peer_conn.rs` (**handshake**: legacy digest handshake and secure-mode `Noise_XX_25519_ChaChaPoly_SHA256` with HMAC secret proof), `peer_session.rs` / `secure_datagram.rs` (secure-mode session keys and per-packet AEAD), `encrypt/` (AES-GCM / ChaCha20 via ring, xor), `peer_ospf_route.rs` (route propagation; the largest file), `foreign_network_manager.rs` / `foreign_network_client.rs` (**relaying other networks' traffic**: what public relay nodes do), `relay_peer_map.rs`, `credential_manager.rs` (credential-based nodes), `acl_filter.rs` | `peer_manager.rs`, `peer_conn.rs` |
| `tunnel/` | `packet_def.rs` (`ZCPacket` wire format and headers), `tcp.rs`, `udp.rs`, `quic.rs`, `wireguard.rs`, `websocket.rs`, `fake_tcp/`, `ring.rs` (in-process), `filter.rs`, `common.rs` (framing) | `packet_def.rs`, `mod.rs` |
| `connector/` | `manual.rs` (the `--peers` list and reconnecting), `direct.rs` (direct connections between members), `udp_hole_punch/` and `tcp_hole_punch.rs` (NAT traversal), `dns_connector.rs` (`txt://`/`srv://` peer discovery), `http_connector.rs` (`http(s)://` peer lists; refused in Jay's build), `mod.rs` (`create_connector_by_url`) | `mod.rs`, `manual.rs` |
| `gateway/` | `tcp_proxy.rs` (subnet and exit proxy), `udp_proxy.rs`, `icmp_proxy.rs`, `quic_proxy.rs` (`--enable-quic-proxy`, which Jay turns on), `kcp_proxy.rs` (not in Jay's build), `socks5.rs` + `fast_socks5/` (`--socks5`, and **`--port-forward` is implemented here**), `tokio_smoltcp/` (user-space TCP/IP for no-TUN mode) | `socks5.rs`, `tcp_proxy.rs` |
| `instance/` | `instance.rs` (wiring), `virtual_nic.rs` (TUN device), `listeners.rs`, `windows_udp_broadcast.rs` (`--enable-udp-broadcast-relay`, uses WinDivert), `dns_server/` (magic DNS; not in Jay's build), `public_ipv6_provider.rs`, `proxy_cidrs_monitor.rs` | `instance.rs` |
| `rpc_service/` | Local management API used by `easytier-cli`: `api.rs` (server and **portal binding**), `port_forward_manage.rs`, peer and route queries | `api.rs` |
| `proto/` | Protobuf definitions (`*.proto`) for the RPCs and the handshake messages; `build.rs` compiles them | `peer_rpc.proto`, `api_instance.proto` |
| `web_client/` | Connects a node to a remote web console (`--config-server`; refused in Jay's build) | `mod.rs` |
| `vpn_portal/` | WireGuard portal for plain WireGuard clients (refused in Jay's build) | `wireguard.rs` |
| `peer_center/` | Collects the peer graph that `easytier-cli peer-center` shows | `instance.rs` |
| `arch/`, `service_manager/`, `utils/` | Windows helpers, installing as an OS service, small utilities | |
| `tests/` | Multi-node integration tests. They need network namespaces and root, so Jay's CI doesn't run them. | `three_node.rs` |
| `easytier-cli.rs` | The CLI Jay calls (`peer`, `connector add`, …) against the RPC portal | |

Outside `easytier/`: `easytier-web` (web console server), `easytier-gui` (Tauri app),
`easytier-contrib` (FFI, Android, uptime). Jay doesn't build these. `easytier/third_party` holds
prebuilt Windows DLLs and drivers, which are pinned in `jay-build.yml`.

## Where Jay's flags land

| Jay passes | Parsed in | Implemented in |
|---|---|---|
| `--network-name`, `ET_NETWORK_SECRET` | `core.rs` `NetworkOptions` | `common/config.rs` `NetworkIdentity`; digest and keys in `common/global_ctx.rs`, checked in `peers/peer_conn.rs` |
| `--ipv4`, `--dhcp`, `--hostname`, `--machine-id` | `core.rs` | `instance/instance.rs`, `common/machine_id.rs` |
| `--peers`, `--listeners`, `--no-listener`, `--mapped-listeners` | `core.rs` | `connector/manual.rs`, `instance/listeners.rs` |
| `--no-tun`, `--dev-name` | `core.rs` | `instance/virtual_nic.rs`, `gateway/tokio_smoltcp/` |
| `--port-forward` | `core.rs` → `PortForwardConfig` | `gateway/socks5.rs` (port forward over smoltcp / the NIC) |
| `--tcp-whitelist`, `--udp-whitelist` | `core.rs` | Turned into ACL rules in `common/acl_processor.rs`, enforced by `peers/acl_filter.rs` |
| `--enable-quic-proxy` | `core.rs` | `gateway/quic_proxy.rs` |
| `--socks5` | `core.rs` | `gateway/socks5.rs` |
| `--enable-exit-node`, `--exit-nodes`, `--manual-routes` | `core.rs` | `peers/peer_manager.rs`, `gateway/tcp_proxy.rs` |
| `--relay-network-whitelist` | `core.rs` | `peers/foreign_network_manager.rs`, `common/global_ctx.rs` |
| `--disable-p2p`, `--latency-first`, `--multi-thread` | `core.rs` `Flags` | `connector/direct.rs`, `peers/peer_ospf_route.rs`, runtime setup in `core.rs` |
| `--enable-udp-broadcast-relay` (Windows) | `core.rs` | `instance/windows_udp_broadcast.rs` |
| `--rpc-portal`, `--rpc-portal-whitelist` | `core.rs` `RpcPortalOptions` | `rpc_service/api.rs` |
| `--bind-device`, `--accept-dns`, `--instance-recv-bps-limit` | `core.rs` | `connector/mod.rs`, `instance/dns_server/`, `peers/peer_manager.rs` |

## Security hot spots (read these first on every upgrade)

- `common/global_ctx.rs` (`get_128_key`, `get_256_key`) and `tunnel/mod.rs`
  (`generate_digest_from_str`): legacy key and digest derivation (SipHash, no KDF).
- `peers/peer_conn.rs`: the handshake, network identity checks, secure mode, and the secret proof.
- `peers/encrypt/` and `peers/secure_datagram.rs`: AEAD, nonces, and cipher selection.
- `peers/foreign_network_manager.rs`: what a relay node accepts from other networks.
- `common/acl_processor.rs`, `peers/acl_filter.rs`, `gateway/tcp_proxy.rs`: whitelists and the
  exit node. This decides what remote members can reach on your machine.
- `rpc_service/api.rs`: the local management API (no authentication; loopback-only in Jay's build).
- `instance/windows_udp_broadcast.rs`: runs with WinDivert in the kernel path on Windows.
- `build.rs`, `Cargo.lock`, `easytier/third_party/`: the build's own supply chain.
