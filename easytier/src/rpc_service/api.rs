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

    registry.register(
        PeerCenterRpcServer::new(PeerCenterManageRpcService::new(instance_manager.clone())),
        "",
    );

    // Jay hardening: the local management API offers neither instance management (start,
    // stop, replace or read whole instance configs) nor credential management (issue, list
    // or revoke secure-mode credentials). Jay uses neither. Only the web-client session,
    // which passes hooks and which this build refuses to start (`--config-server`), gets them.
    if let Some(hooks) = hooks {
        registry.register(
            WebClientServiceServer::new(InstanceManageRpcService::new(
                instance_manager.clone(),
                hooks,
            )),
            "",
        );
        registry.register(
            CredentialManageRpcServer::new(CredentialManageRpcService::new(
                instance_manager.clone(),
            )),
            "",
        );
    }
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
        let credentials =
            CredentialManageRpcServer::new(CredentialManageRpcService::new(manager.clone()));
        assert!(registry.unregister(credentials, "").is_none());
        let config = ConfigRpcServer::new(ConfigRpcService::new(manager.clone()));
        assert!(registry.unregister(config, "").is_some());
        let connectors =
            ConnectorManageRpcServer::new(ConnectorManageRpcService::new(manager.clone()));
        assert!(registry.unregister(connectors, "").is_some());
    }

    #[test]
    fn web_client_session_keeps_management_services() {
        use super::*;
        use crate::web_client::DefaultHooks;

        let manager = Arc::new(NetworkInstanceManager::new());
        let registry = ServiceRegistry::new();
        register_api_rpc_service(&manager, &registry, Some(Arc::new(DefaultHooks)));

        let credentials =
            CredentialManageRpcServer::new(CredentialManageRpcService::new(manager.clone()));
        assert!(registry.unregister(credentials, "").is_some());
    }

    /// Over a real loopback connection, the credential calls are refused because the service
    /// isn't there (not because no instance matched), while connector calls still reach theirs.
    #[tokio::test]
    async fn local_api_refuses_credential_calls() {
        use super::*;
        use crate::proto::{
            api::instance::{
                ConnectorManageRpc, ConnectorManageRpcClientFactory, CredentialManageRpc,
                CredentialManageRpcClientFactory, GenerateCredentialRequest, ListConnectorRequest,
                ListCredentialsRequest, RevokeCredentialRequest,
            },
            rpc_types::controller::BaseController,
        };

        let manager = Arc::new(NetworkInstanceManager::new());
        let (server, mut client) = local_api(manager).await;
        let credentials = client
            .scoped_client::<CredentialManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .unwrap();

        let is_missing_service = |e: &Error| {
            matches!(e, Error::InvalidServiceKey(name, _)
                if name.trim_matches('"') == "CredentialManageRpc")
        };
        let err = credentials
            .generate_credential(
                BaseController::default(),
                GenerateCredentialRequest {
                    ttl_seconds: 3600,
                    credential_id: Some("known-id".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(is_missing_service(&err), "generate: {err:?}");
        let err = credentials
            .list_credentials(BaseController::default(), ListCredentialsRequest::default())
            .await
            .unwrap_err();
        assert!(is_missing_service(&err), "list: {err:?}");
        let err = credentials
            .revoke_credential(
                BaseController::default(),
                RevokeCredentialRequest {
                    credential_id: "known-id".to_string(),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(is_missing_service(&err), "revoke: {err:?}");

        // The connector service is there: with no instance running it answers with an
        // instance error, not a missing-service error.
        let connectors = client
            .scoped_client::<ConnectorManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .unwrap();
        let err = connectors
            .list_connector(BaseController::default(), ListConnectorRequest::default())
            .await
            .unwrap_err();
        assert!(
            !matches!(err, Error::InvalidServiceKey(..)),
            "connector: {err:?}"
        );

        drop(server);
    }

    /// A local management API on a free loopback port, and a client connected to it.
    async fn local_api(
        manager: std::sync::Arc<crate::instance_manager::NetworkInstanceManager>,
    ) -> (
        super::ApiRpcServer<crate::tunnel::tcp::TcpTunnelListener>,
        crate::proto::rpc_impl::standalone::StandAloneClient<
            crate::tunnel::tcp::TcpTunnelConnector,
        >,
    ) {
        use super::ApiRpcServer;
        use crate::proto::rpc_impl::standalone::StandAloneClient;
        use crate::tunnel::tcp::{TcpTunnelConnector, TcpTunnelListener};

        let port = crate::utils::find_free_tcp_port(20000..30000).expect("no free tcp port");
        let url = format!("tcp://127.0.0.1:{port}");
        let server =
            ApiRpcServer::from_tunnel(TcpTunnelListener::new(url.parse().unwrap()), manager)
                .serve()
                .await
                .unwrap();
        let client = StandAloneClient::new(TcpTunnelConnector::new(url.parse().unwrap()));
        (server, client)
    }

    /// A running instance holds a network secret, a secure-mode private key and an ACL group
    /// secret. None of them comes back over the local API, the instance keeps them, and the
    /// status and connector calls Jay uses still work.
    #[tokio::test]
    #[serial_test::serial]
    async fn local_api_hands_out_no_secrets() {
        use super::*;
        use crate::common::config::{
            ConfigFileControl, ConfigLoader, NetworkIdentity, TomlConfigLoader,
        };
        use crate::proto::{
            acl::{Acl, AclV1, GroupIdentity, GroupInfo},
            api::{
                config::{
                    ConfigPatchAction, ConfigRpc, ConfigRpcClientFactory, GetConfigRequest,
                    InstanceConfigPatch, PatchConfigRequest, UrlPatch,
                },
                instance::{
                    ConnectorManageRpc, ConnectorManageRpcClientFactory, InstanceIdentifier,
                    ListConnectorRequest, PeerManageRpc, PeerManageRpcClientFactory,
                    ShowNodeInfoRequest, instance_identifier::Selector,
                },
            },
            common::SecureModeConfig,
            rpc_types::controller::BaseController,
        };
        use base64::Engine as _;

        const NETWORK_SECRET: &str = "jay-test-network-secret";
        const GROUP_SECRET: &str = "jay-test-group-secret";
        let private = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = x25519_dalek::PublicKey::from(&private);
        let b64 = base64::engine::general_purpose::STANDARD;
        let private_key = b64.encode(private.to_bytes());

        let cfg = TomlConfigLoader::new_from_str("listeners = []").unwrap();
        cfg.set_inst_name("jay-secret-test".into());
        cfg.set_network_identity(NetworkIdentity::new(
            "jay-net".into(),
            NETWORK_SECRET.into(),
        ));
        cfg.set_secure_mode(Some(SecureModeConfig {
            enabled: true,
            local_private_key: Some(private_key.clone()),
            local_public_key: Some(b64.encode(public.as_bytes())),
        }));
        cfg.set_acl(Some(Acl {
            acl_v1: Some(AclV1 {
                chains: vec![],
                group: Some(GroupInfo {
                    declares: vec![GroupIdentity {
                        group_name: "g".into(),
                        group_secret: GROUP_SECRET.into(),
                    }],
                    members: vec![],
                }),
            }),
        }));
        let mut flags = cfg.get_flags();
        flags.no_tun = true;
        cfg.set_flags(flags);

        let manager = Arc::new(NetworkInstanceManager::new());
        let inst_id = manager
            .run_network_instance(cfg.clone(), false, ConfigFileControl::STATIC_CONFIG)
            .unwrap();
        // The instance starts on its own thread; wait (bounded) until its API service is up.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while manager.get_instance_service(&inst_id).is_none() {
            let error = manager
                .iter()
                .find(|i| *i.key() == inst_id)
                .and_then(|i| i.value().get_latest_error_msg());
            assert!(error.is_none(), "instance failed to start: {error:?}");
            assert!(
                std::time::Instant::now() < deadline,
                "instance not ready after 30 s"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let instance = Some(InstanceIdentifier {
            selector: Some(Selector::Id(inst_id.into())),
        });

        let (server, mut client) = local_api(manager.clone()).await;
        let assert_no_secret = |what: &str, text: &str| {
            for secret in [NETWORK_SECRET, GROUP_SECRET, private_key.as_str()] {
                assert!(!text.contains(secret), "{what} leaks a secret");
            }
        };

        let peers = client
            .scoped_client::<PeerManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .unwrap();
        let node = peers
            .show_node_info(
                BaseController::default(),
                ShowNodeInfoRequest {
                    instance: instance.clone(),
                },
            )
            .await
            .unwrap()
            .node_info
            .unwrap();
        assert_no_secret("ShowNodeInfo", &format!("{node:?}"));
        assert_eq!(
            node.config,
            crate::rpc_service::peer_manage::NODE_CONFIG_WITHHELD
        );
        assert_eq!(node.inst_id, inst_id.to_string());

        let config = client
            .scoped_client::<ConfigRpcClientFactory<BaseController>>("".to_string())
            .await
            .unwrap();
        let got = config
            .get_config(
                BaseController::default(),
                GetConfigRequest {
                    instance: instance.clone(),
                },
            )
            .await
            .unwrap();
        assert_no_secret("GetConfig", &format!("{got:?}"));
        assert_eq!(got.config.unwrap().network_name.as_deref(), Some("jay-net"));

        // Connector add and remove still work.
        let url: url::Url = "tcp://192.0.2.1:11010".parse().unwrap();
        let connectors = client
            .scoped_client::<ConnectorManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .unwrap();
        let list = || async {
            connectors
                .list_connector(
                    BaseController::default(),
                    ListConnectorRequest {
                        instance: instance.clone(),
                    },
                )
                .await
                .unwrap()
                .connectors
                .iter()
                .any(|c| c.url.as_ref().map(|u| u.url.as_str()) == Some(url.as_str()))
        };
        for (action, present) in [
            (ConfigPatchAction::Add, true),
            (ConfigPatchAction::Remove, false),
        ] {
            config
                .patch_config(
                    BaseController::default(),
                    PatchConfigRequest {
                        instance: instance.clone(),
                        patch: Some(InstanceConfigPatch {
                            connectors: vec![UrlPatch {
                                action: action.into(),
                                url: Some(url.clone().into()),
                            }],
                            ..Default::default()
                        }),
                    },
                )
                .await
                .unwrap();
            assert_eq!(list().await, present, "{action:?}");
        }

        // The instance itself still has its secrets.
        assert_eq!(
            cfg.get_network_identity().network_secret.as_deref(),
            Some(NETWORK_SECRET)
        );
        assert_eq!(
            cfg.get_secure_mode().unwrap().local_private_key.as_deref(),
            Some(private_key.as_str())
        );
        let group = cfg.get_acl().unwrap().acl_v1.unwrap().group.unwrap();
        assert_eq!(group.declares[0].group_secret, GROUP_SECRET);

        drop(server);
        manager.delete_network_instance(vec![inst_id]).unwrap();
    }
}
