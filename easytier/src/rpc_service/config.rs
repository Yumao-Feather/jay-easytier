use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::{
            config::{
                ConfigPatchAction, ConfigRpc, GetConfigRequest, GetConfigResponse,
                InstanceConfigPatch, PatchConfigRequest, PatchConfigResponse,
            },
            manage::NetworkConfig,
        },
        rpc_types::{self, controller::BaseController},
    },
};

#[derive(Clone)]
pub struct ConfigRpcService {
    instance_manager: Arc<NetworkInstanceManager>,
}

impl ConfigRpcService {
    pub fn new(instance_manager: Arc<NetworkInstanceManager>) -> Self {
        Self { instance_manager }
    }
}

#[async_trait::async_trait]
impl ConfigRpc for ConfigRpcService {
    type Controller = BaseController;

    async fn patch_config(
        &self,
        ctrl: Self::Controller,
        input: PatchConfigRequest,
    ) -> Result<PatchConfigResponse, rpc_types::error::Error> {
        if let Some(patch) = &input.patch {
            check_patch_allowed(patch)?;
        }
        super::get_instance_service(&self.instance_manager, &input.instance)?
            .get_config_service()
            .patch_config(ctrl, input)
            .await
    }

    async fn get_config(
        &self,
        ctrl: Self::Controller,
        input: GetConfigRequest,
    ) -> Result<GetConfigResponse, rpc_types::error::Error> {
        let mut response = super::get_instance_service(&self.instance_manager, &input.instance)?
            .get_config_service()
            .get_config(ctrl, input)
            .await?;
        if let Some(config) = response.config.as_mut() {
            redact_secrets(config);
        }
        Ok(response)
    }
}

// Jay hardening: the management API can only add or remove connectors (what Jay's
// `easytier-cli connector add` needs). Every other change to a running node is refused.
fn check_patch_allowed(patch: &InstanceConfigPatch) -> Result<(), anyhow::Error> {
    let connectors_only = InstanceConfigPatch {
        connectors: patch.connectors.clone(),
        ..Default::default()
    };
    if *patch != connectors_only {
        anyhow::bail!("this build only allows adding or removing connectors");
    }
    for c in &patch.connectors {
        match ConfigPatchAction::try_from(c.action) {
            Ok(ConfigPatchAction::Add) | Ok(ConfigPatchAction::Remove) => {}
            _ => anyhow::bail!("this build only allows adding or removing connectors"),
        }
    }
    Ok(())
}

// Jay hardening: the management API never hands out secrets from the running config.
fn redact_secrets(config: &mut NetworkConfig) {
    config.network_secret = None;
    if let Some(secure_mode) = config.secure_mode.as_mut() {
        secure_mode.local_private_key = None;
    }
    if let Some(group) = config
        .acl
        .as_mut()
        .and_then(|acl| acl.acl_v1.as_mut())
        .and_then(|v1| v1.group.as_mut())
    {
        for declare in &mut group.declares {
            declare.group_secret.clear();
        }
    }
}

#[cfg(test)]
mod jay_config_rpc_tests {
    use super::*;
    use crate::proto::{
        acl::{Acl, AclV1, GroupIdentity, GroupInfo},
        api::config::{PortForwardPatch, UrlPatch},
        common::SecureModeConfig,
    };

    fn url_patch(action: ConfigPatchAction) -> UrlPatch {
        UrlPatch {
            action: action.into(),
            url: Some("tcp://192.0.2.1:11010".parse::<url::Url>().unwrap().into()),
        }
    }

    #[test]
    fn jay_patch_allows_adding_and_removing_connectors() {
        let patch = InstanceConfigPatch {
            connectors: vec![
                url_patch(ConfigPatchAction::Add),
                url_patch(ConfigPatchAction::Remove),
            ],
            ..Default::default()
        };
        assert!(check_patch_allowed(&patch).is_ok());
        assert!(check_patch_allowed(&InstanceConfigPatch::default()).is_ok());
    }

    #[test]
    fn jay_patch_refuses_everything_else() {
        let clear = InstanceConfigPatch {
            connectors: vec![url_patch(ConfigPatchAction::Clear)],
            ..Default::default()
        };
        assert!(check_patch_allowed(&clear).is_err());

        let hostname = InstanceConfigPatch {
            hostname: Some("x".into()),
            ..Default::default()
        };
        assert!(check_patch_allowed(&hostname).is_err());

        let mixed = InstanceConfigPatch {
            connectors: vec![url_patch(ConfigPatchAction::Add)],
            port_forwards: vec![PortForwardPatch::default()],
            ..Default::default()
        };
        assert!(check_patch_allowed(&mixed).is_err());

        let listeners = InstanceConfigPatch {
            mapped_listeners: vec![url_patch(ConfigPatchAction::Add)],
            ..Default::default()
        };
        assert!(check_patch_allowed(&listeners).is_err());

        let relay = InstanceConfigPatch {
            disable_relay_data: Some(false),
            ..Default::default()
        };
        assert!(check_patch_allowed(&relay).is_err());
    }

    #[test]
    fn jay_get_config_hides_secrets() {
        let mut config = NetworkConfig {
            network_name: Some("net".into()),
            network_secret: Some("room secret".into()),
            secure_mode: Some(SecureModeConfig {
                enabled: true,
                local_private_key: Some("private".into()),
                local_public_key: Some("public".into()),
            }),
            acl: Some(Acl {
                acl_v1: Some(AclV1 {
                    chains: vec![],
                    group: Some(GroupInfo {
                        declares: vec![GroupIdentity {
                            group_name: "g".into(),
                            group_secret: "group secret".into(),
                        }],
                        members: vec![],
                    }),
                }),
            }),
            ..Default::default()
        };
        redact_secrets(&mut config);
        assert_eq!(config.network_secret, None);
        assert_eq!(config.network_name.as_deref(), Some("net"));
        let secure = config.secure_mode.as_ref().unwrap();
        assert_eq!(secure.local_private_key, None);
        assert_eq!(secure.local_public_key.as_deref(), Some("public"));
        let group = config.acl.unwrap().acl_v1.unwrap().group.unwrap();
        assert_eq!(group.declares[0].group_secret, "");
        assert_eq!(group.declares[0].group_name, "g");
    }
}
