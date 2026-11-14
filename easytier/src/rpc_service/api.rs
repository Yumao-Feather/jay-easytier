use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use cidr::IpCidr;

use crate::{
    instance::instance::InstanceRpcServerHook,
    instance_manager::NetworkInstanceManager,
    proto::{
        api::{
            config::ConfigRpcServer,
            instance::{
                AclManageRpcServer, ConnectorManageRpcServer, CredentialManageRpcServer,
                MappedListenerManageRpcServer, PeerManageRpcServer, PortForwardManageRpcServer,
                StatsRpcServer, TcpProxyRpcServer, VpnPortalRpcServer,
            },
            logger::LoggerRpcServer,
            manage::WebClientServiceServer,
        },
        peer_rpc::PeerCenterRpcServer,
        rpc_impl::{service_registry::ServiceRegistry, standalone::StandAloneServer},
        rpc_types::error::Error,
    },
    rpc_service::{
        acl_manage::AclManageRpcService, config::ConfigRpcService,
        connector_manage::ConnectorManageRpcService, credential_manage::CredentialManageRpcService,
        instance_manage::InstanceManageRpcService, logger::LoggerRpcService,
        mapped_listener_manage::MappedListenerManageRpcService,
        peer_center::PeerCenterManageRpcService, peer_manage::PeerManageRpcService,
        port_forward_manage::PortForwardManageRpcService, protected_port,
        proxy::TcpProxyRpcService, stats::StatsRpcService, vpn_portal::VpnPortalRpcService,
    },
    tunnel::{TunnelListener, tcp::TcpTunnelListener},
    web_client::WebClientHooks,
};

pub struct ApiRpcServer<T: TunnelListener + 'static> {
    rpc_server: StandAloneServer<T>,
    protected_tcp_port: Option<u16>,
}

impl ApiRpcServer<TcpTunnelListener> {
    pub fn new(
        rpc_portal: Option<String>,
        rpc_portal_whitelist: Option<Vec<IpCidr>>,
        instance_manager: Arc<NetworkInstanceManager>,
    ) -> anyhow::Result<Self> {
        let rpc_addr = parse_rpc_portal(rpc_portal)?;
        let mut server = Self::from_tunnel(
            TcpTunnelListener::new(
                format!("tcp://{}", rpc_addr)
                    .parse()
                    .context("failed to parse rpc portal address")?,
            ),
            instance_manager,
        );
        protected_port::register_protected_tcp_port(rpc_addr.port());
        server.protected_tcp_port = Some(rpc_addr.port());

        server
            .rpc_server
            .set_hook(Arc::new(InstanceRpcServerHook::new(rpc_portal_whitelist)));

        Ok(server)
    }
}

impl<T: TunnelListener + 'static> ApiRpcServer<T> {
    pub fn from_tunnel(tunnel: T, instance_manager: Arc<NetworkInstanceManager>) -> Self {
        let rpc_server = StandAloneServer::new(tunnel);
        register_api_rpc_service(&instance_manager, rpc_server.registry(), None);
        Self {
            rpc_server,
            protected_tcp_port: None,
        }
    }
}

impl<T: TunnelListener + 'static> ApiRpcServer<T> {
    pub async fn serve(mut self) -> Result<Self, Error> {
        self.rpc_server.serve().await?;
        Ok(self)
    }

    pub fn with_rx_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.rpc_server.set_rx_timeout(timeout);
        self
    }
}

impl<T: TunnelListener + 'static> Drop for ApiRpcServer<T> {
    fn drop(&mut self) {
        if let Some(port) = self.protected_tcp_port.take() {
            protected_port::unregister_protected_tcp_port(port);
        }
        self.rpc_server.registry().unregister_all();
    }
}

pub fn register_api_rpc_service(
    instance_manager: &Arc<NetworkInstanceManager>,
    registry: &ServiceRegistry,
    hooks: Option<Arc<dyn WebClientHooks>>,
) {
    registry.register(
        PeerManageRpcServer::new(PeerManageRpcService::new(instance_manager.clone())),
        "",
    );

    registry.register(
        ConnectorManageRpcServer::new(ConnectorManageRpcService::new(instance_manager.clone())),
        "",
    );

    registry.register(
        MappedListenerManageRpcServer::new(MappedListenerManageRpcService::new(
            instance_manager.clone(),
        )),
        "",
    );

    registry.register(
        VpnPortalRpcServer::new(VpnPortalRpcService::new(instance_manager.clone())),
        "",
    );

    for client_type in ["tcp", "kcp_src", "kcp_dst", "quic_src", "quic_dst"] {
        registry.register(
            TcpProxyRpcServer::new(TcpProxyRpcService::new(
                instance_manager.clone(),
                client_type,
            )),
            client_type,
        );
    }

    registry.register(
        AclManageRpcServer::new(AclManageRpcService::new(instance_manager.clone())),
        "",
    );

    registry.register(
        PortForwardManageRpcServer::new(PortForwardManageRpcService::new(instance_manager.clone())),
        "",
    );

    registry.register(
        StatsRpcServer::new(StatsRpcService::new(instance_manager.clone())),
        "",
    );

    registry.register(LoggerRpcServer::new(LoggerRpcService), "");

    registry.register(
        ConfigRpcServer::new(ConfigRpcService::new(instance_manager.clone())),
        "",
    );

    // Jay hardening: the local management API doesn't offer instance management (start,
    // stop, replace or read whole instance configs). Only the web-client session, which
    // this build refuses to start (`--config-server`), passes hooks and gets it.
    if let Some(hooks) = hooks {
        registry.register(
            WebClientServiceServer::new(InstanceManageRpcService::new(
                instance_manager.clone(),
                hooks,
            )),
            "",
        );
    }

    registry.register(
        PeerCenterRpcServer::new(PeerCenterManageRpcService::new(instance_manager.clone())),
        "",
    );

    registry.register(
        CredentialManageRpcServer::new(CredentialManageRpcService::new(instance_manager.clone())),
        "",
    );
}

// Jay hardening: the management API only ever listens on loopback. A bare port binds
// 127.0.0.1 instead of 0.0.0.0, and any non-loopback address is refused.
fn parse_rpc_portal(rpc_portal: Option<String>) -> anyhow::Result<SocketAddr> {
    let addr = if let Some(Ok(port)) = rpc_portal.as_ref().map(|s| s.parse::<u16>()) {
        SocketAddr::from(([127, 0, 0, 1], port))
    } else {
        let mut rpc_addr = rpc_portal
            .map(|addr| {
                addr.parse::<SocketAddr>()
                    .context("failed to parse rpc portal address")
            })
            .transpose()?;
        select_proper_rpc_port(&mut rpc_addr)?;
        rpc_addr.ok_or_else(|| anyhow::anyhow!("failed to parse rpc portal address"))?
    };
    if !addr.ip().is_loopback() {
        anyhow::bail!(
            "rpc portal must listen on a loopback address in this build, got {}",
            addr
        );
    }
    Ok(addr)
}

fn select_proper_rpc_port(addr: &mut Option<SocketAddr>) -> anyhow::Result<()> {
    match addr {
        None => {
            *addr = Some(SocketAddr::from(([127, 0, 0, 1], 0)));
            select_proper_rpc_port(addr)?;
            Ok(())
        }
        Some(addr) => {
            if addr.port() == 0 {
                let Some(port) = crate::utils::find_free_tcp_port(15888..15900) else {
                    tracing::warn!(
                        "No free port found for RPC portal, skipping setting RPC portal"
                    );
                    return Err(anyhow::anyhow!("No free port found for RPC portal"));
                };
                addr.set_port(port);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod jay_rpc_portal_tests {
    use super::parse_rpc_portal;

    #[test]
    fn bare_port_binds_loopback() {
        let addr = parse_rpc_portal(Some("15999".to_owned())).unwrap();
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 15999);
    }

    #[test]
    fn explicit_loopback_is_kept() {
        let addr = parse_rpc_portal(Some("127.0.0.1:15998".to_owned())).unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:15998");
        assert!(parse_rpc_portal(Some("[::1]:15997".to_owned())).is_ok());
    }

    #[test]
    fn non_loopback_is_refused() {
        assert!(parse_rpc_portal(Some("0.0.0.0:15996".to_owned())).is_err());
        assert!(parse_rpc_portal(Some("192.168.1.2:15995".to_owned())).is_err());
    }

    #[test]
    fn local_api_has_no_instance_management() {
        use super::*;
        use crate::web_client::DefaultHooks;

        let manager = Arc::new(NetworkInstanceManager::new());
        let registry = ServiceRegistry::new();
        register_api_rpc_service(&manager, &registry, None);

        // unregister() reports whether the service was there.
        let web_client = WebClientServiceServer::new(InstanceManageRpcService::new(
            manager.clone(),
            Arc::new(DefaultHooks),
        ));
        assert!(registry.unregister(web_client, "").is_none());
        let config = ConfigRpcServer::new(ConfigRpcService::new(manager.clone()));
        assert!(registry.unregister(config, "").is_some());
    }
}
