use anyhow::Context;
use cidr::Ipv4Inet;
use core::panic;
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket, ipv4_checksum};
use socket2::{SockRef, TcpKeepalive};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU16};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::Instrument;

use crate::common::error::Result;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx};
use crate::common::join_joinset_background;
use crate::common::log;
use crate::common::stats_manager::{LabelSet, LabelType, MetricName};
use crate::peers::peer_manager::PeerManager;
use crate::peers::{NicPacketFilter, PeerPacketFilter};
use crate::proto::api::instance::{
    ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyEntry, TcpProxyEntryState,
    TcpProxyEntryTransportType, TcpProxyRpc,
};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::packet_def::{PacketType, PeerManagerHeader, ZCPacket};

use super::CidrSet;

#[cfg(feature = "smoltcp")]
use super::tokio_smoltcp::{self, Net, NetConfig, channel_device};

#[async_trait::async_trait]
pub(crate) trait NatDstConnector: Send + Sync + Clone + 'static {
    type DstStream: AsyncRead + AsyncWrite + Unpin + Send;

    async fn connect(&self, src: SocketAddr, dst: SocketAddr) -> anyhow::Result<Self::DstStream>;
    fn check_packet_from_peer_fast(&self, cidr_set: &CidrSet, global_ctx: &GlobalCtx) -> bool;
    fn check_packet_from_peer(
        &self,
        cidr_set: &CidrSet,
        global_ctx: &GlobalCtx,
        hdr: &PeerManagerHeader,
        ipv4: &Ipv4Addr,
        real_dst_ip: &mut Ipv4Addr,
    ) -> bool;
    fn transport_type(&self) -> TcpProxyEntryTransportType;
}

/// Jay: environment switch that makes connections handed to a local service carry a stand-in
/// for the caller. Off unless set to exactly "1".
pub(crate) const LOOPBACK_SOURCE_ENV: &str = "JAY_ET_LOOPBACK_SOURCE";

pub(crate) fn loopback_source_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var(LOOPBACK_SOURCE_ENV).is_ok_and(|v| v == "1"))
}

/// Jay's public network (where the room directory lives): callers inside it keep their own
/// stand-in address.
const PUBLIC_NETWORK: [u8; 2] = [10, 235];

/// The one stand-in for every caller that doesn't get its own. Local services count all of
/// them as a single caller, never as this machine itself.
pub(crate) const SHARED_LOOPBACK_SOURCE: std::net::Ipv4Addr =
    std::net::Ipv4Addr::new(127, 255, 255, 254);

/// The source to use for a caller whose address could not be confirmed: it maps to
/// [`SHARED_LOOPBACK_SOURCE`].
pub(crate) const UNCONFIRMED_SOURCE: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// The loopback address standing for a caller at `src`: 127.235.c.d for a confirmed caller at
/// 10.235.c.d (Jay's public network, except its network, broadcast and directory addresses), and
/// [`SHARED_LOOPBACK_SOURCE`] for anything else, so a caller can neither take another one's
/// stand-in nor arrive as 127.0.0.1.
pub(crate) fn loopback_source_for(src: SocketAddr) -> std::net::Ipv4Addr {
    if let IpAddr::V4(v4) = src.ip().to_canonical() {
        let [a, b, c, d] = v4.octets();
        let reserved = matches!((c, d), (0, 0) | (0, 1) | (255, 255));
        if [a, b] == PUBLIC_NETWORK && !reserved {
            return std::net::Ipv4Addr::new(127, b, c, d);
        }
    }
    SHARED_LOOPBACK_SOURCE
}

/// The public-network address whose stand-in (see [`loopback_source_for`]) is `peer`'s own:
/// 10.235.c.d with c.d from a keyed hash of the peer id, never the network, broadcast or
/// directory address. The key is random per process, so no peer can pick a peer id that lands on
/// a chosen caller's stand-in; two peers can still share one by chance (1 in 65533). The address
/// stands for the peer only to tell callers apart; it is not the peer's own address.
pub(crate) fn peer_source(peer: crate::common::PeerId) -> std::net::Ipv4Addr {
    use std::hash::BuildHasher;
    static KEY: std::sync::OnceLock<std::collections::hash_map::RandomState> =
        std::sync::OnceLock::new();
    let hash = KEY
        .get_or_init(std::collections::hash_map::RandomState::new)
        .hash_one(peer);
    // 2..=65534: skips .0.0, .0.1 and .255.255.
    let n = (hash % 65533) as u16 + 2;
    let [c, d] = n.to_be_bytes();
    std::net::Ipv4Addr::new(PUBLIC_NETWORK[0], PUBLIC_NETWORK[1], c, d)
}

/// The source a stream from `from_peer` is given (the caller's own `claimed` address is not
/// used): [`peer_source`] of the sending peer when the route table knows that peer, and
/// [`UNCONFIRMED_SOURCE`] otherwise. Route entries aren't signed by the peer they describe, so the
/// address a peer declares can't decide whose stand-in a caller gets; the peer id can. `from_peer`
/// is the sending peer id from the packet header: relayed packets aren't checked against the
/// connection they came over, so a peer that forwards traffic between a caller and this node
/// could still forge it. With the switch off, `claimed` is returned unchanged.
pub(crate) async fn confirmed_source(
    route: &(dyn crate::peers::route_trait::Route + Send + Sync),
    from_peer: Option<crate::common::PeerId>,
    claimed: SocketAddr,
) -> SocketAddr {
    if !loopback_source_enabled() {
        return claimed;
    }
    let known = match from_peer {
        Some(peer) => route.get_peer_info(peer).await.is_some(),
        None => false,
    };
    source_of(from_peer.filter(|_| known), claimed)
}

/// [`peer_source`] of `known_peer` (a sending peer the route table knows), keeping `claimed`'s
/// port, or [`UNCONFIRMED_SOURCE`] without one. `claimed`'s address is never used.
pub(crate) fn source_of(
    known_peer: Option<crate::common::PeerId>,
    claimed: SocketAddr,
) -> SocketAddr {
    match known_peer {
        Some(peer) => SocketAddr::new(IpAddr::V4(peer_source(peer)), claimed.port()),
        None => UNCONFIRMED_SOURCE,
    }
}

/// Does a connection need its claimed source confirmed? Only with the switch on, for a plain TCP
/// connection (the KCP / QUIC source-side connectors pass the source on to the remote side
/// unchanged) to a local service on loopback.
pub(crate) fn needs_confirmation(
    enabled: bool,
    transport: TcpProxyEntryTransportType,
    nat_dst: SocketAddr,
) -> bool {
    enabled && transport == TcpProxyEntryTransportType::Tcp && nat_dst.ip().is_loopback()
}

/// True at most once a minute per `last` (seconds on a monotonic clock, from 1, of the last
/// true): keeps a flood of failures from flooding the log too. A clock set back can't silence it.
pub(crate) fn once_a_minute(last: &std::sync::atomic::AtomicU64) -> bool {
    use std::sync::atomic::Ordering;
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let now = START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs()
        + 1;
    let prev = last.load(Ordering::Relaxed);
    (prev == 0 || now >= prev + 60)
        && last
            .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

/// When `enabled` and the connection goes to a local service on loopback, binds the socket to
/// the caller's stand-in so the service can tell callers apart. If that bind fails the
/// connection is refused rather than going out as 127.0.0.1 (so on macOS, which only has
/// 127.0.0.1, the switch must stay off).
fn bind_loopback_source(
    enabled: bool,
    socket: &TcpSocket,
    src: SocketAddr,
    nat_dst: SocketAddr,
) -> std::io::Result<()> {
    if !enabled || !nat_dst.ip().is_loopback() {
        return Ok(());
    }
    let local = loopback_source_for(src);
    socket
        .bind(SocketAddr::new(local.into(), 0))
        .inspect_err(|error| {
            static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            if once_a_minute(&LAST) {
                tracing::warn!(
                    ?error,
                    ?local,
                    "bind loopback source failed, refusing the connection"
                );
            }
        })
}

#[cfg(test)]
mod loopback_source_tests {
    use super::*;

    fn v4(s: &str) -> std::net::Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn maps_public_network_callers_to_their_own_stand_in() {
        let at = |s: &str| loopback_source_for(s.parse().unwrap());
        assert_eq!(at("10.235.1.2:5000"), v4("127.235.1.2"));
        assert_eq!(at("10.235.255.254:5000"), v4("127.235.255.254"));
        assert_eq!(at("[::ffff:10.235.1.2]:5000"), v4("127.235.1.2"));
        // Everything else: one shared stand-in, never someone else's or 127.0.0.1.
        for other in [
            "10.235.0.0:1",
            "10.235.0.1:1",
            "10.235.255.255:1",
            "172.16.235.2:5000",
            "10.234.0.9:1",
            "10.0.0.1:80",
            "100.64.0.1:80",
            "0.0.0.0:0",
            "127.0.0.1:80",
            "[fd00::1]:80",
        ] {
            assert_eq!(at(other), SHARED_LOOPBACK_SOURCE, "{other}");
        }
        assert_eq!(
            loopback_source_for(UNCONFIRMED_SOURCE),
            SHARED_LOOPBACK_SOURCE
        );
    }

    #[test]
    fn each_peer_gets_its_own_public_network_source() {
        let mut seen = std::collections::HashSet::new();
        for peer in 0..2000u32 {
            let ip = peer_source(peer);
            let [a, b, c, d] = ip.octets();
            assert_eq!([a, b], PUBLIC_NETWORK);
            assert!(!matches!((c, d), (0, 0) | (0, 1) | (255, 255)), "{ip}");
            // Stable for a peer, and maps to a stand-in of its own (not the shared one).
            assert_eq!(peer_source(peer), ip);
            assert_eq!(
                loopback_source_for(SocketAddr::new(IpAddr::V4(ip), 1)),
                std::net::Ipv4Addr::new(127, b, c, d)
            );
            seen.insert(ip);
        }
        // Different peers almost always get different sources (a few chance collisions at most).
        assert!(seen.len() > 1950, "{}", seen.len());
    }

    #[test]
    fn the_source_follows_the_sending_peer_not_the_claimed_address() {
        // Peer 7 claiming any address, another peer's included, gets its own source.
        let own = SocketAddr::new(IpAddr::V4(peer_source(7)), 4000);
        for claimed in [
            "10.235.4.7:4000",
            "10.235.4.8:4000",
            "[fd00::1]:4000",
            "0.0.0.0:4000",
        ] {
            assert_eq!(
                source_of(Some(7), claimed.parse().unwrap()),
                own,
                "{claimed}"
            );
        }
        // No known sending peer: the shared stand-in, whatever it claims.
        assert_eq!(
            source_of(None, "10.235.4.7:4000".parse().unwrap()),
            UNCONFIRMED_SOURCE
        );
        assert_eq!(
            loopback_source_for(source_of(None, "10.235.4.7:4000".parse().unwrap())),
            SHARED_LOOPBACK_SOURCE
        );
    }

    #[test]
    fn only_plain_tcp_to_a_local_service_is_confirmed() {
        use TcpProxyEntryTransportType as T;
        let local: SocketAddr = "127.0.0.1:47668".parse().unwrap();
        let local6: SocketAddr = "[::1]:47668".parse().unwrap();
        let remote: SocketAddr = "10.235.4.8:47668".parse().unwrap();
        assert!(needs_confirmation(true, T::Tcp, local));
        assert!(needs_confirmation(true, T::Tcp, local6));
        assert!(!needs_confirmation(false, T::Tcp, local));
        assert!(!needs_confirmation(true, T::Tcp, remote));
        assert!(!needs_confirmation(true, T::Kcp, local));
        assert!(!needs_confirmation(true, T::Quic, local));
    }

    #[test]
    fn once_a_minute_lets_one_through() {
        let last = std::sync::atomic::AtomicU64::new(0);
        assert!(once_a_minute(&last));
        assert!(!once_a_minute(&last));
        assert!(!once_a_minute(&last));
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[tokio::test]
    async fn local_service_sees_the_callers_stand_in() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dst = listener.local_addr().unwrap();
        let peer_of = |src: SocketAddr| {
            let listener = &listener;
            async move {
                let socket = TcpSocket::new_v4().unwrap();
                bind_loopback_source(true, &socket, src, dst).unwrap();
                let _stream = socket.connect(dst).await.unwrap();
                listener.accept().await.unwrap().1.ip()
            }
        };
        assert_eq!(
            peer_of("10.235.7.8:4000".parse().unwrap()).await,
            v4("127.235.7.8")
        );
        assert_eq!(peer_of(UNCONFIRMED_SOURCE).await, SHARED_LOOPBACK_SOURCE);
    }

    #[tokio::test]
    async fn binds_only_when_on_and_going_to_loopback() {
        let src: SocketAddr = "10.235.7.8:4000".parse().unwrap();
        // Off: never bound.
        let socket = TcpSocket::new_v4().unwrap();
        bind_loopback_source(false, &socket, src, "127.0.0.1:80".parse().unwrap()).unwrap();
        assert!(socket.local_addr().is_err() || socket.local_addr().unwrap().ip().is_unspecified());
        // On, but going elsewhere: never bound.
        let socket = TcpSocket::new_v4().unwrap();
        bind_loopback_source(true, &socket, src, "10.235.0.1:80".parse().unwrap()).unwrap();
        assert!(socket.local_addr().is_err() || socket.local_addr().unwrap().ip().is_unspecified());
    }

    #[tokio::test]
    async fn a_failed_bind_refuses_the_connection() {
        // A socket that is already bound can't be bound again: stands in for any bind failure.
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let src: SocketAddr = "10.235.9.11:1".parse().unwrap();
        assert!(bind_loopback_source(true, &socket, src, "127.0.0.1:80".parse().unwrap()).is_err());
    }
}

#[derive(Debug, Clone)]
pub struct NatDstTcpConnector;

#[async_trait::async_trait]
impl NatDstConnector for NatDstTcpConnector {
    type DstStream = TcpStream;
    async fn connect(
        &self,
        src: SocketAddr,
        nat_dst: SocketAddr,
    ) -> anyhow::Result<Self::DstStream> {
        let socket = TcpSocket::new_v4()
            .inspect_err(|error| log::error!(?error, "create v4 socket failed"))?;
        bind_loopback_source(loopback_source_enabled(), &socket, src, nat_dst)?;

        let stream = timeout(Duration::from_secs(10), socket.connect(nat_dst))
            .await?
            .with_context(|| format!("connect to nat dst failed: {:?}", nat_dst))?;

        prepare_kernel_tcp_socket(&stream)?;

        Ok(stream)
    }

    fn check_packet_from_peer_fast(&self, cidr_set: &CidrSet, global_ctx: &GlobalCtx) -> bool {
        !cidr_set.is_empty() || global_ctx.enable_exit_node() || global_ctx.no_tun()
    }

    fn check_packet_from_peer(
        &self,
        cidr_set: &CidrSet,
        global_ctx: &GlobalCtx,
        hdr: &PeerManagerHeader,
        ipv4: &Ipv4Addr,
        real_dst_ip: &mut Ipv4Addr,
    ) -> bool {
        let is_exit_node = hdr.is_exit_node();

        if !(cidr_set.contains_v4(*ipv4, real_dst_ip)
            || is_exit_node
            || global_ctx.no_tun()
                && Some(*ipv4) == global_ctx.get_ipv4().as_ref().map(Ipv4Inet::address))
        {
            return false;
        }

        true
    }

    fn transport_type(&self) -> TcpProxyEntryTransportType {
        TcpProxyEntryTransportType::Tcp
    }
}

type NatDstEntryState = TcpProxyEntryState;

#[derive(Debug)]
pub struct NatDstEntry {
    id: uuid::Uuid,
    src: SocketAddr,
    /// Jay: the peer id the SYN came from, to confirm `src` before a TCP connection to a local
    /// service (see [`confirmed_source`]).
    from_peer: Option<crate::common::PeerId>,
    real_dst: SocketAddr,
    mapped_dst: SocketAddr,
    start_time: Instant,
    start_time_local: chrono::DateTime<chrono::Local>,
    tasks: Mutex<JoinSet<()>>,
    state: AtomicCell<NatDstEntryState>,
}

impl NatDstEntry {
    pub fn new(src: SocketAddr, real_dst: SocketAddr, mapped_dst: SocketAddr) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            src,
            from_peer: None,
            real_dst,
            mapped_dst,
            start_time: Instant::now(),
            start_time_local: chrono::Local::now(),
            tasks: Mutex::new(JoinSet::new()),
            state: AtomicCell::new(NatDstEntryState::SynReceived),
        }
    }

    fn parse_as_pb(&self, transport_type: TcpProxyEntryTransportType) -> TcpProxyEntry {
        TcpProxyEntry {
            src: Some(self.src.into()),
            dst: Some(self.real_dst.into()),
            start_time: self.start_time_local.timestamp() as u64,
            state: self.state.load().into(),
            transport_type: transport_type.into(),
        }
    }
}

enum ProxyTcpStream {
    KernelTcpStream(TcpStream),
    #[cfg(feature = "smoltcp")]
    SmolTcpStream(tokio_smoltcp::TcpStream),
}

impl ProxyTcpStream {
    pub fn set_nodelay(&self, nodelay: bool) -> Result<()> {
        match self {
            Self::KernelTcpStream(stream) => stream.set_nodelay(nodelay).map_err(Into::into),
            #[cfg(feature = "smoltcp")]
            Self::SmolTcpStream(_stream) => {
                tracing::warn!("smol tcp stream set_nodelay not implemented");
                Ok(())
            }
        }
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        match self {
            Self::KernelTcpStream(stream) => {
                stream.shutdown().await?;
                Ok(())
            }
            #[cfg(feature = "smoltcp")]
            Self::SmolTcpStream(stream) => {
                stream.shutdown().await?;
                Ok(())
            }
        }
    }

    pub async fn copy_bidirectional<D: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        dst: &mut D,
    ) -> Result<()> {
        match self {
            Self::KernelTcpStream(stream) => {
                copy_bidirectional(stream, dst).await?;
                Ok(())
            }
            #[cfg(feature = "smoltcp")]
            Self::SmolTcpStream(stream) => {
                copy_bidirectional(stream, dst).await?;
                Ok(())
            }
        }
    }
}

#[cfg(feature = "smoltcp")]
type SmolTcpAcceptResult = Result<(tokio_smoltcp::TcpStream, SocketAddr)>;
#[cfg(feature = "smoltcp")]
struct SmolTcpListener {
    stream_tx: mpsc::UnboundedSender<SmolTcpAcceptResult>,
    stream_rx: mpsc::UnboundedReceiver<SmolTcpAcceptResult>,

    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

#[cfg(feature = "smoltcp")]
impl SmolTcpListener {
    pub async fn new() -> Self {
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "smoltcp listener".to_owned());

        let (tx, rx) = mpsc::unbounded_channel();

        Self {
            stream_tx: tx,
            stream_rx: rx,
            tasks,
        }
    }

    pub async fn accept(&mut self) -> SmolTcpAcceptResult {
        self.stream_rx.recv().await.unwrap()
    }

    pub fn stream_tx(&self) -> mpsc::UnboundedSender<SmolTcpAcceptResult> {
        self.stream_tx.clone()
    }

    pub async fn add_listener(
        tx: mpsc::UnboundedSender<SmolTcpAcceptResult>,
        net: Arc<Mutex<Option<Net>>>,
        tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    ) {
        let locked_net = net.lock().await;
        let mut tcp = locked_net
            .as_ref()
            .unwrap()
            .tcp_bind("0.0.0.0:8899".parse().unwrap())
            .await
            .unwrap();
        tasks.lock().unwrap().spawn(async move {
            let ret = timeout(Duration::from_secs(10), tcp.accept()).await;
            if let Ok(accept_ret) = ret {
                tx.send(accept_ret.map_err(|e| {
                    anyhow::anyhow!("smol tcp listener accept failed: {:?}", e).into()
                }))
                .unwrap();
            } else {
                tracing::error!("smol tcp listener accept timeout");
            }
        });
    }
}

enum ProxyTcpListener {
    KernelTcpListener(TcpListener),
    #[cfg(feature = "smoltcp")]
    SmolTcpListener(SmolTcpListener),
}

fn prepare_kernel_tcp_socket(stream: &TcpStream) -> Result<()> {
    const TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(5);
    const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);
    const TCP_KEEPALIVE_RETRIES: u32 = 2;

    let ka = TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_TIME)
        .with_interval(TCP_KEEPALIVE_INTERVAL);

    #[cfg(not(target_os = "windows"))]
    let ka = ka.with_retries(TCP_KEEPALIVE_RETRIES);

    let sf = SockRef::from(&stream);
    sf.set_tcp_keepalive(&ka)?;
    if let Err(e) = sf.set_nodelay(true) {
        tracing::warn!("set_nodelay failed, ignore it: {:?}", e);
    }

    Ok(())
}

impl ProxyTcpListener {
    pub async fn accept(&mut self) -> Result<(ProxyTcpStream, SocketAddr)> {
        match self {
            Self::KernelTcpListener(listener) => {
                let (stream, addr) = listener.accept().await?;
                prepare_kernel_tcp_socket(&stream)?;
                Ok((ProxyTcpStream::KernelTcpStream(stream), addr))
            }
            #[cfg(feature = "smoltcp")]
            Self::SmolTcpListener(listener) => {
                let Ok((stream, src)) = listener.accept().await else {
                    return Err(anyhow::anyhow!("smol tcp listener closed").into());
                };
                tracing::info!(?src, "smol tcp listener accepted");
                Ok((ProxyTcpStream::SmolTcpStream(stream), src))
            }
        }
    }
}

type ArcNatDstEntry = Arc<NatDstEntry>;

type SynSockMap = Arc<DashMap<SocketAddr, ArcNatDstEntry>>;
type ConnSockMap = Arc<DashMap<uuid::Uuid, ArcNatDstEntry>>;
// peer src addr to nat entry, when respond tcp packet, should modify the tcp src addr to the nat entry's dst addr
type AddrConnSockMap = Arc<DashMap<SocketAddr, ArcNatDstEntry>>;

#[derive(Debug)]
pub struct TcpProxy<C: NatDstConnector> {
    global_ctx: Arc<GlobalCtx>,
    peer_manager: Weak<PeerManager>,
    local_port: AtomicU16,

    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,

    syn_map: SynSockMap,
    conn_map: ConnSockMap,
    addr_conn_map: AddrConnSockMap,

    cidr_set: CidrSet,

    smoltcp_stack_sender: Option<mpsc::Sender<ZCPacket>>,
    smoltcp_stack_receiver: Arc<Mutex<Option<mpsc::Receiver<ZCPacket>>>>,
    #[cfg(feature = "smoltcp")]
    smoltcp_net: Arc<Mutex<Option<Net>>>,
    #[cfg(feature = "smoltcp")]
    smoltcp_listener_tx: std::sync::Mutex<Option<mpsc::UnboundedSender<SmolTcpAcceptResult>>>,
    enable_smoltcp: Arc<AtomicBool>,

    connector: C,
}

#[async_trait::async_trait]
impl<C: NatDstConnector> PeerPacketFilter for TcpProxy<C> {
    async fn try_process_packet_from_peer(&self, mut packet: ZCPacket) -> Option<ZCPacket> {
        if self.try_handle_peer_packet(&mut packet).await.is_some() {
            if self.is_smoltcp_enabled() {
                let smoltcp_stack_sender = self.smoltcp_stack_sender.as_ref().unwrap();
                if let Err(e) = smoltcp_stack_sender.try_send(packet) {
                    tracing::error!("send to smoltcp stack failed: {:?}", e);
                }
            } else if let Some(peer_manager) = self.get_peer_manager()
                && let Err(e) = peer_manager.get_nic_channel().send(packet).await
            {
                tracing::error!("send to nic failed: {:?}", e);
            }
            return None;
        } else {
            Some(packet)
        }
    }
}

#[async_trait::async_trait]
impl<C: NatDstConnector> NicPacketFilter for TcpProxy<C> {
    async fn try_process_packet_from_nic(&self, zc_packet: &mut ZCPacket) -> bool {
        let Some(my_ipv4_inet) = self.get_local_inet() else {
            return false;
        };
        let my_ipv4 = my_ipv4_inet.address();

        let data = zc_packet.payload();
        let ip_packet = Ipv4Packet::new(data).unwrap();
        if ip_packet.get_version() != 4
            || ip_packet.get_source() != my_ipv4
            || ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
        {
            return false;
        }

        let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();
        if tcp_packet.get_source() != self.get_local_port() {
            return false;
        }

        let mut dst_addr = SocketAddr::V4(SocketAddrV4::new(
            ip_packet.get_destination(),
            tcp_packet.get_destination(),
        ));
        let mut need_transform_dst = false;

        // for kcp proxy, the src ip of nat entry will be converted from my ip to fake ip
        // here we need to convert it back
        if !self.is_smoltcp_enabled() && dst_addr.ip() == Self::get_fake_local_ipv4(&my_ipv4_inet) {
            dst_addr.set_ip(IpAddr::V4(my_ipv4));
            need_transform_dst = true;
        }

        tracing::trace!(dst_addr = ?dst_addr, "tcp packet try find entry");
        let entry = if let Some(entry) = self.addr_conn_map.get(&dst_addr) {
            entry
        } else {
            let Some(syn_entry) = self.syn_map.get(&dst_addr) else {
                return false;
            };
            syn_entry
        };
        let nat_entry = entry.clone();
        drop(entry);
        assert_eq!(nat_entry.src, dst_addr);

        let IpAddr::V4(ip) = nat_entry.mapped_dst.ip() else {
            panic!("v4 nat entry src ip is not v4");
        };

        zc_packet
            .mut_peer_manager_header()
            .unwrap()
            .set_no_proxy(true);
        if need_transform_dst {
            zc_packet.mut_peer_manager_header().unwrap().to_peer_id = self.get_my_peer_id().into();
        }

        let mut ip_packet = MutableIpv4Packet::new(zc_packet.mut_payload()).unwrap();
        ip_packet.set_source(ip);
        if need_transform_dst {
            ip_packet.set_destination(my_ipv4);
        }
        let dst = ip_packet.get_destination();

        let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
        tcp_packet.set_source(nat_entry.real_dst.port());

        Self::update_tcp_packet_checksum(&mut tcp_packet, &ip, &dst);
        drop(tcp_packet);
        Self::update_ip_packet_checksum(&mut ip_packet);

        tracing::trace!(dst_addr = ?dst_addr, nat_entry = ?nat_entry, packet = ?ip_packet, "tcp packet after modified");

        true
    }
}

impl<C: NatDstConnector> TcpProxy<C> {
    pub fn new(peer_manager: Arc<PeerManager>, connector: C) -> Arc<Self> {
        let (smoltcp_stack_sender, smoltcp_stack_receiver) = mpsc::channel::<ZCPacket>(1000);
        let global_ctx = peer_manager.get_global_ctx();

        Arc::new(Self {
            global_ctx: global_ctx.clone(),
            peer_manager: Arc::downgrade(&peer_manager),

            local_port: AtomicU16::new(0),
            tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),

            syn_map: Arc::new(DashMap::new()),
            conn_map: Arc::new(DashMap::new()),
            addr_conn_map: Arc::new(DashMap::new()),

            cidr_set: CidrSet::new(global_ctx),

            smoltcp_stack_sender: Some(smoltcp_stack_sender),
            smoltcp_stack_receiver: Arc::new(Mutex::new(Some(smoltcp_stack_receiver))),

            #[cfg(feature = "smoltcp")]
            smoltcp_net: Arc::new(Mutex::new(None)),
            #[cfg(feature = "smoltcp")]
            smoltcp_listener_tx: std::sync::Mutex::new(None),

            enable_smoltcp: Arc::new(AtomicBool::new(true)),

            connector,
        })
    }

    pub fn get_peer_manager(&self) -> Option<Arc<PeerManager>> {
        self.peer_manager.upgrade()
    }

    fn update_tcp_packet_checksum(
        tcp_packet: &mut MutableTcpPacket,
        ipv4_src: &Ipv4Addr,
        ipv4_dst: &Ipv4Addr,
    ) {
        tcp_packet.set_checksum(ipv4_checksum(
            &tcp_packet.to_immutable(),
            ipv4_src,
            ipv4_dst,
        ));
    }

    fn update_ip_packet_checksum(ip_packet: &mut MutableIpv4Packet) {
        ip_packet.set_checksum(pnet::packet::ipv4::checksum(&ip_packet.to_immutable()));
    }

    pub async fn start(self: &Arc<Self>, add_pipeline: bool) -> Result<()> {
        self.run_syn_map_cleaner().await?;
        self.run_listener().await?;
        if add_pipeline {
            let peer_manager = self
                .get_peer_manager()
                .ok_or_else(|| anyhow::anyhow!("peer manager is gone"))?;
            peer_manager
                .add_packet_process_pipeline(Box::new(self.clone()))
                .await;
            peer_manager
                .add_nic_packet_process_pipeline(Box::new(self.clone()))
                .await;
        }
        join_joinset_background(self.tasks.clone(), "TcpProxy".to_owned());

        Ok(())
    }

    async fn run_syn_map_cleaner(&self) -> Result<()> {
        let syn_map = self.syn_map.clone();
        let tasks = self.tasks.clone();
        let syn_map_cleaner_task = async move {
            loop {
                syn_map.retain(|_, entry| {
                    if entry.start_time.elapsed() > Duration::from_secs(30) {
                        tracing::warn!(entry = ?entry, "syn nat entry expired");
                        entry.state.store(NatDstEntryState::Closed);
                        false
                    } else {
                        true
                    }
                });
                syn_map.shrink_to_fit();
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        };
        tasks.lock().unwrap().spawn(syn_map_cleaner_task);

        Ok(())
    }

    async fn get_proxy_listener(&self) -> Result<ProxyTcpListener> {
        #[cfg(feature = "smoltcp")]
        if self.global_ctx.get_flags().use_smoltcp
            || self.global_ctx.no_tun()
            || cfg!(any(
                target_os = "android",
                any(
                    target_os = "ios",
                    all(target_os = "macos", feature = "macos-ne")
                ),
                target_env = "ohos"
            ))
        {
            // use smoltcp network stack

            use crate::gateway::tokio_smoltcp::BufferSize;
            self.local_port
                .store(8899, std::sync::atomic::Ordering::Relaxed);

            let mut cap = smoltcp::phy::DeviceCapabilities::default();
            cap.max_transmission_unit = 1280;
            cap.medium = smoltcp::phy::Medium::Ip;
            let (dev, stack_sink, mut stack_stream) = channel_device::ChannelDevice::new(cap);

            let mut smoltcp_stack_receiver =
                self.smoltcp_stack_receiver.lock().await.take().unwrap();
            self.tasks.lock().unwrap().spawn(async move {
                while let Some(packet) = smoltcp_stack_receiver.recv().await {
                    tracing::trace!(?packet, "receive from peer send to smoltcp packet");
                    if let Err(e) = stack_sink.send(Ok(packet.payload().to_vec())).await {
                        tracing::error!("send to smoltcp stack failed: {:?}", e);
                    }
                }
                tracing::error!("smoltcp stack sink exited");
            });

            let peer_mgr = self.peer_manager.clone();
            self.tasks.lock().unwrap().spawn(async move {
                while let Some(data) = stack_stream.recv().await {
                    tracing::trace!(
                        ?data,
                        "receive from smoltcp stack and send to peer mgr packet"
                    );
                    let Some(ipv4) = Ipv4Packet::new(&data) else {
                        tracing::error!(?data, "smoltcp stack stream get non ipv4 packet");
                        continue;
                    };

                    let dst = ipv4.get_destination();
                    let packet = ZCPacket::new_with_payload(&data);
                    let Some(peer_mgr) = peer_mgr.upgrade() else {
                        tracing::warn!("peer manager is gone, smoltcp sender exited");
                        return;
                    };
                    if let Err(e) = peer_mgr
                        .send_msg_by_ip(packet, IpAddr::V4(dst), false)
                        .await
                    {
                        tracing::error!("send to peer failed in smoltcp sender: {:?}", e);
                    }
                }
                tracing::error!("smoltcp stack stream exited");
            });

            let interface_config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
            let net = Net::new(
                dev,
                NetConfig::new(
                    interface_config,
                    format!("{}/24", self.get_local_ip().unwrap())
                        .parse()
                        .unwrap(),
                    vec![format!("{}", self.get_local_ip().unwrap()).parse().unwrap()],
                    Some(BufferSize {
                        tcp_rx_size: 1024 * 16,
                        tcp_tx_size: 1024 * 16,
                        ..Default::default()
                    }),
                ),
            );
            net.set_any_ip(true);
            self.smoltcp_net.lock().await.replace(net);
            let tcp = SmolTcpListener::new().await;
            self.smoltcp_listener_tx
                .lock()
                .unwrap()
                .replace(tcp.stream_tx());

            self.enable_smoltcp
                .store(true, std::sync::atomic::Ordering::Relaxed);

            return Ok(ProxyTcpListener::SmolTcpListener(tcp));
        }

        {
            // use kernel network stack
            let listen_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
            let net_ns = self.global_ctx.net_ns.clone();
            let tcp_listener = net_ns
                .run_async(|| async { TcpListener::bind(&listen_addr).await })
                .await?;
            self.local_port.store(
                tcp_listener.local_addr()?.port(),
                std::sync::atomic::Ordering::Relaxed,
            );

            self.enable_smoltcp
                .store(false, std::sync::atomic::Ordering::Relaxed);

            Ok(ProxyTcpListener::KernelTcpListener(tcp_listener))
        }
    }

    async fn run_listener(&self) -> Result<()> {
        // bind on both v4 & v6
        let mut tcp_listener = self.get_proxy_listener().await?;

        let global_ctx = self.global_ctx.clone();
        let tasks = Arc::downgrade(&self.tasks);
        let syn_map = self.syn_map.clone();
        let conn_map = self.conn_map.clone();
        let addr_conn_map = self.addr_conn_map.clone();
        let connector = self.connector.clone();
        let peer_mgr = self.peer_manager.clone();
        let accept_task = async move {
            let conn_map = conn_map.clone();
            loop {
                let accept_ret = tcp_listener.accept().await;
                let Ok((tcp_stream, mut socket_addr)) = accept_ret else {
                    tracing::error!("nat tcp listener accept failed: {:?}", accept_ret.err());
                    continue;
                };

                let my_ip_inet = global_ctx.get_ipv4();
                let my_ip = my_ip_inet
                    .as_ref()
                    .map(Ipv4Inet::address)
                    .unwrap_or(Ipv4Addr::UNSPECIFIED);

                if my_ip_inet.is_some()
                    && socket_addr.ip() == Self::get_fake_local_ipv4(&my_ip_inet.unwrap())
                {
                    socket_addr.set_ip(IpAddr::V4(my_ip));
                }

                let Some(entry) = syn_map.get(&socket_addr) else {
                    tracing::error!(
                        ?my_ip,
                        ?socket_addr,
                        "tcp connection from unknown source, ignore it"
                    );
                    continue;
                };
                tracing::info!(
                    ?socket_addr,
                    "tcp connection accepted for proxy, nat dst: {:?}",
                    entry.real_dst
                );
                assert_eq!(entry.state.load(), NatDstEntryState::SynReceived);

                let entry_clone = entry.clone();
                drop(entry);
                syn_map.remove_if(&socket_addr, |_, entry| entry.id == entry_clone.id);

                entry_clone.state.store(NatDstEntryState::ConnectingDst);

                let _ = addr_conn_map.insert(entry_clone.src, entry_clone.clone());
                let old_nat_val = conn_map.insert(entry_clone.id, entry_clone.clone());
                assert!(old_nat_val.is_none());

                let Some(tasks) = tasks.upgrade() else {
                    tracing::error!("tcp proxy tasks is dropped, exit accept loop");
                    break;
                };

                tasks.lock().unwrap().spawn(Self::connect_to_nat_dst(
                    connector.clone(),
                    peer_mgr.clone(),
                    global_ctx.clone(),
                    tcp_stream,
                    conn_map.clone(),
                    addr_conn_map.clone(),
                    entry_clone,
                ));
            }
        };
        self.tasks
            .lock()
            .unwrap()
            .spawn(accept_task.instrument(tracing::info_span!("tcp_proxy_listener")));

        Ok(())
    }

    fn remove_entry_from_all_conn_map(
        conn_map: ConnSockMap,
        addr_conn_map: AddrConnSockMap,
        nat_entry: ArcNatDstEntry,
    ) {
        conn_map.remove(&nat_entry.id);
        addr_conn_map.remove_if(&nat_entry.src, |_, entry| entry.id == nat_entry.id);
        if conn_map.capacity() - conn_map.len() > 16 {
            conn_map.shrink_to_fit();
        }
        if addr_conn_map.capacity() - addr_conn_map.len() > 16 {
            addr_conn_map.shrink_to_fit();
        }
    }

    async fn connect_to_nat_dst(
        connector: C,
        peer_mgr: Weak<PeerManager>,
        global_ctx: ArcGlobalCtx,
        src_tcp_stream: ProxyTcpStream,
        conn_map: ConnSockMap,
        addr_conn_map: AddrConnSockMap,
        nat_entry: ArcNatDstEntry,
    ) {
        if let Err(e) = src_tcp_stream.set_nodelay(true) {
            tracing::warn!("set_nodelay failed, ignore it: {:?}", e);
        }

        if global_ctx.should_deny_proxy(&nat_entry.real_dst, false) {
            tracing::error!(
                ?nat_entry,
                "nat dst port {} is in running listeners, ignore it",
                nat_entry.real_dst.port()
            );
            nat_entry.state.store(NatDstEntryState::Closed);
            Self::remove_entry_from_all_conn_map(conn_map, addr_conn_map, nat_entry);
            return;
        }

        let nat_dst = if global_ctx.is_ip_local_virtual_ip(&nat_entry.real_dst.ip()) {
            format!("127.0.0.1:{}", nat_entry.real_dst.port())
                .parse()
                .unwrap()
        } else {
            nat_entry.real_dst
        };

        global_ctx
            .stats_manager()
            .get_counter(
                MetricName::TcpProxyConnect,
                LabelSet::new()
                    .with_label_type(LabelType::Protocol(
                        connector.transport_type().as_str_name().to_string(),
                    ))
                    .with_label_type(LabelType::DstIp(nat_dst.ip().to_string()))
                    .with_label_type(LabelType::MappedDstIp(
                        nat_entry.mapped_dst.ip().to_string(),
                    )),
            )
            .inc();

        // Jay: only a plain TCP connection to a local service gets a confirmed stand-in.
        let src = if needs_confirmation(
            loopback_source_enabled(),
            connector.transport_type(),
            nat_dst,
        ) {
            match peer_mgr.upgrade() {
                Some(peer_manager) => {
                    let route = peer_manager.get_route();
                    confirmed_source(route.as_ref(), nat_entry.from_peer, nat_entry.src).await
                }
                None => UNCONFIRMED_SOURCE,
            }
        } else {
            nat_entry.src
        };

        let _guard = global_ctx.net_ns.guard();
        let Ok(dst_tcp_stream) = connector.connect(src, nat_dst).await else {
            // Jay: with the switch on, at most one error a minute (a refused stand-in bind or a
            // closed port can be triggered by any caller), the rest at debug. Off: as upstream.
            static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            if !loopback_source_enabled() || once_a_minute(&LAST) {
                tracing::error!("connect to dst failed: {:?}", nat_entry);
            } else {
                tracing::debug!("connect to dst failed: {:?}", nat_entry);
            }
            nat_entry.state.store(NatDstEntryState::Closed);
            Self::remove_entry_from_all_conn_map(conn_map, addr_conn_map, nat_entry);
            return;
        };
        drop(_guard);

        tracing::info!(?nat_entry, ?nat_dst, "tcp connection to dst established");

        assert_eq!(nat_entry.state.load(), NatDstEntryState::ConnectingDst);
        nat_entry.state.store(NatDstEntryState::Connected);

        Self::handle_nat_connection(
            src_tcp_stream,
            dst_tcp_stream,
            conn_map,
            addr_conn_map,
            nat_entry,
        )
        .await;
    }

    async fn handle_nat_connection(
        mut src_tcp_stream: ProxyTcpStream,
        mut dst_tcp_stream: C::DstStream,
        conn_map: ConnSockMap,
        addr_conn_map: AddrConnSockMap,
        nat_entry: ArcNatDstEntry,
    ) {
        let nat_entry_clone = nat_entry.clone();
        nat_entry.tasks.lock().await.spawn(async move {
            let ret = src_tcp_stream.copy_bidirectional(&mut dst_tcp_stream).await;
            tracing::info!(nat_entry = ?nat_entry_clone, ret = ?ret, "nat tcp connection closed");

            nat_entry_clone.state.store(NatDstEntryState::ClosingSrc);
            let ret = timeout(Duration::from_secs(10), src_tcp_stream.shutdown()).await;
            tracing::info!(nat_entry = ?nat_entry_clone, ret = ?ret, "src tcp stream shutdown");

            nat_entry_clone.state.store(NatDstEntryState::ClosingDst);
            let ret = timeout(Duration::from_secs(10), dst_tcp_stream.shutdown()).await;
            tracing::info!(nat_entry = ?nat_entry_clone, ret = ?ret, "dst tcp stream shutdown");

            drop(src_tcp_stream);
            drop(dst_tcp_stream);

            nat_entry_clone.state.store(NatDstEntryState::Closed);
            // sleep later so the fin packet can be processed
            tokio::time::sleep(Duration::from_secs(10)).await;

            Self::remove_entry_from_all_conn_map(conn_map, addr_conn_map, nat_entry_clone);
        });
    }

    pub fn get_local_port(&self) -> u16 {
        self.local_port.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn get_my_peer_id(&self) -> u32 {
        self.peer_manager
            .upgrade()
            .map(|pm| pm.my_peer_id())
            .unwrap_or_default()
    }

    pub fn get_local_ip(&self) -> Option<Ipv4Addr> {
        self.get_local_inet().map(|inet| inet.address())
    }

    pub fn get_local_inet(&self) -> Option<Ipv4Inet> {
        if self.is_smoltcp_enabled() {
            Some(Ipv4Inet::new(Ipv4Addr::new(192, 88, 99, 254), 24).unwrap())
        } else {
            self.global_ctx.get_ipv4().as_ref().cloned()
        }
    }

    pub fn get_global_ctx(&self) -> &ArcGlobalCtx {
        &self.global_ctx
    }

    pub fn is_smoltcp_enabled(&self) -> bool {
        self.enable_smoltcp
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn get_fake_local_ipv4(local_ip: &Ipv4Inet) -> Ipv4Addr {
        local_ip.first_address()
    }

    async fn try_handle_peer_packet(&self, packet: &mut ZCPacket) -> Option<()> {
        if !self
            .connector
            .check_packet_from_peer_fast(&self.cidr_set, &self.global_ctx)
        {
            return None;
        }

        let ipv4_inet = self.get_local_inet()?;
        let ipv4_addr = ipv4_inet.address();
        {
            let hdr = packet.peer_manager_header().unwrap();
            if (hdr.packet_type != PacketType::Data as u8
                && hdr.packet_type != PacketType::DataWithKcpSrcModified as u8
                && hdr.packet_type != PacketType::DataWithQuicSrcModified as u8)
                || hdr.is_no_proxy()
            {
                return None;
            };
        }

        let origin_ip = {
            let payload_bytes = packet.mut_payload();
            let ipv4 = Ipv4Packet::new(payload_bytes)?;
            if ipv4.get_version() != 4
                || ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
            {
                return None;
            }

            ipv4.get_destination()
        };
        let mut real_dst_ip = origin_ip;
        let hdr = packet.mut_peer_manager_header().unwrap();
        // Jay: the sending peer id from the header. Relayed packets aren't checked against the
        // connection they came over; the return route is what makes a forged one fail.
        let from_peer = hdr.from_peer_id.get();

        if !self.connector.check_packet_from_peer(
            &self.cidr_set,
            &self.global_ctx,
            hdr,
            &origin_ip,
            &mut real_dst_ip,
        ) {
            return None;
        }

        // restore to data packet
        hdr.packet_type = PacketType::Data as u8;

        tracing::trace!(ipv4 = ?origin_ip, cidr_set = ?self.cidr_set, "proxy tcp packet received");

        let payload_bytes = packet.mut_payload();
        let ip_packet = Ipv4Packet::new(payload_bytes).unwrap();
        let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();

        let source_ip = ip_packet.get_source();
        let source_port = tcp_packet.get_source();
        let src = SocketAddr::V4(SocketAddrV4::new(source_ip, source_port));

        let is_tcp_syn = tcp_packet.get_flags() & pnet::packet::tcp::TcpFlags::SYN != 0;
        let is_tcp_ack = tcp_packet.get_flags() & pnet::packet::tcp::TcpFlags::ACK != 0;
        if is_tcp_syn && !is_tcp_ack {
            let dest_ip = ip_packet.get_destination();
            let dest_port = tcp_packet.get_destination();
            let mapped_dst = SocketAddr::V4(SocketAddrV4::new(dest_ip, dest_port));
            let real_dst = SocketAddr::V4(SocketAddrV4::new(real_dst_ip, dest_port));

            let mut entry = NatDstEntry::new(src, real_dst, mapped_dst);
            entry.from_peer = Some(from_peer);
            let old_val = self.syn_map.insert(src, Arc::new(entry));
            tracing::info!(src = ?src, ?real_dst, ?mapped_dst, old_entry = ?old_val, "tcp syn received");

            // if smoltcp is enabled, add the listener to the net
            #[cfg(feature = "smoltcp")]
            if self.is_smoltcp_enabled() {
                let smoltcp_listener_tx = self.smoltcp_listener_tx.lock().unwrap().clone().unwrap();
                SmolTcpListener::add_listener(
                    smoltcp_listener_tx,
                    self.smoltcp_net.clone(),
                    self.tasks.clone(),
                )
                .await;
                tracing::info!("smol tcp listener added for src: {:?}", src);
            }
        } else if !self.addr_conn_map.contains_key(&src) && !self.syn_map.contains_key(&src) {
            // if not in syn map and addr conn map, may forwarding n2n packet
            return None;
        }

        let mut ip_packet = MutableIpv4Packet::new(payload_bytes).unwrap();
        if !self.is_smoltcp_enabled() && source_ip == ipv4_addr {
            // modify the source so the response packet can be handled by tun device
            ip_packet.set_source(Self::get_fake_local_ipv4(&ipv4_inet));
        }
        ip_packet.set_destination(ipv4_addr);
        let source = ip_packet.get_source();

        let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
        tcp_packet.set_destination(self.get_local_port());

        Self::update_tcp_packet_checksum(&mut tcp_packet, &source, &ipv4_addr);
        drop(tcp_packet);
        Self::update_ip_packet_checksum(&mut ip_packet);

        tracing::trace!(?source, ?ipv4_addr, ?packet, "tcp packet after modified");

        Some(())
    }

    pub fn is_tcp_proxy_connection(&self, src: SocketAddr) -> bool {
        self.syn_map.contains_key(&src) || self.addr_conn_map.contains_key(&src)
    }

    pub fn list_proxy_entries(&self) -> Vec<TcpProxyEntry> {
        let mut entries: Vec<TcpProxyEntry> = Vec::new();
        let transport_type = self.connector.transport_type();
        for entry in self.syn_map.iter() {
            entries.push(entry.value().as_ref().parse_as_pb(transport_type));
        }
        for entry in self.conn_map.iter() {
            entries.push(entry.value().as_ref().parse_as_pb(transport_type));
        }
        entries
    }

    pub fn get_transport_type(&self) -> TcpProxyEntryTransportType {
        self.connector.transport_type()
    }
}

#[derive(Clone)]
pub struct TcpProxyRpcService<C: NatDstConnector> {
    tcp_proxy: Weak<TcpProxy<C>>,
}

#[async_trait::async_trait]
impl<C: NatDstConnector> TcpProxyRpc for TcpProxyRpcService<C> {
    type Controller = BaseController;
    async fn list_tcp_proxy_entry(
        &self,
        _: BaseController,
        _request: ListTcpProxyEntryRequest, // Accept request of type HelloRequest
    ) -> std::result::Result<ListTcpProxyEntryResponse, rpc_types::error::Error> {
        let mut reply = ListTcpProxyEntryResponse::default();
        if let Some(tcp_proxy) = self.tcp_proxy.upgrade() {
            reply.entries = tcp_proxy.list_proxy_entries();
        }
        Ok(reply)
    }
}

impl<C: NatDstConnector> TcpProxyRpcService<C> {
    pub fn new(tcp_proxy: Arc<TcpProxy<C>>) -> Self {
        Self {
            tcp_proxy: Arc::downgrade(&tcp_proxy),
        }
    }
}
