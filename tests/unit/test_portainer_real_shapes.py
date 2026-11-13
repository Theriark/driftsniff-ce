"""The Portainer type table against fields a real Portainer BE 2.45.3 returned.

These are the paths that the lab server answered on 2026-11-13 and that the table did not name
before (list members share their list's path). Every one must be classified, and the cloud provider
keys of the settings must be secret.
"""

import pytest

from driftsniff.core.normalize import FieldClass
from driftsniff.rules.loader import load_rules

REAL_PATHS_2453 = {
    "portainer-environments": "ChangeWindow.Enabled ChangeWindow.EndTime ChangeWindow.StartTime "
    "EnableImageNotification Kubernetes.Configuration.EnableNodeShell "
    "Kubernetes.Configuration.IngressAvailabilityPerNamespace "
    "Kubernetes.Configuration.RestrictSecrets "
    "Kubernetes.Configuration.RestrictStandardUserIngressW LocalTimeZone StatusMessage.detail "
    "StatusMessage.operation StatusMessage.operationStatus StatusMessage.summary",
    "portainer-environment-groups": "Total TypeInfo.Docker TypeInfo.Kubernetes TypeInfo.Mixed "
    "TypeInfo.Podman",
    "portainer-registries": "Ecr.Region Github.OrganisationName Github.UseOrganisation "
    "Gitlab.InstanceURL Gitlab.ProjectId Gitlab.ProjectPath ManagementConfiguration.Authentication "
    "ManagementConfiguration.Ecr.Region ManagementConfiguration.Type "
    "ManagementConfiguration.Username Quay.OrganisationName",
    "portainer-settings": "AddonsCatalogURL AutoPatchSettings.Enabled AutoPatchSettings.PatchCron "
    "AutoPatchSettings.PortainerRepository AutoPatchSettings.RegistryID "
    "AutoPatchSettings.UpdaterRepository CloudApiKeys.CivoApiKey CloudApiKeys.DigitalOceanToken "
    "CloudApiKeys.GKEApiKey CloudApiKeys.LinodeToken CustomLoginBanner DefaultRegistry.Hide "
    "DisableKubeRolesSync DisableKubeShell DisableKubeconfigDownload Edge.CommandInterval "
    "Edge.MTLS.CaCertFile Edge.MTLS.CertFile Edge.MTLS.KeyFile Edge.MTLS.UseSeparateCert "
    "Edge.PingInterval Edge.SnapshotInterval Edge.TunnelServerAddress "
    "GlobalDeploymentOptions.hideAddWithForm GlobalDeploymentOptions.hideFileUpload "
    "GlobalDeploymentOptions.hideWebEditor GlobalDeploymentOptions.minApplicationNoteLength "
    "GlobalDeploymentOptions.perEnvOverride GlobalDeploymentOptions.requireNoteOnApplications "
    "LDAPSettings.AdminAutoPopulate LDAPSettings.AdminGroupSearchSettings.GroupAttribute "
    "LDAPSettings.AdminGroupSearchSettings.GroupBaseDN "
    "LDAPSettings.AdminGroupSearchSettings.GroupFilter LDAPSettings.ServerType "
    "OAuthSettings.HideInternalAuth OAuthSettings.MicrosoftTenantID "
    "OAuthSettings.OAuthAutoMapTeamMemberships OAuthSettings.TeamMemberships.AdminAutoPopulate "
    "OAuthSettings.TeamMemberships.OAuthClaimName",
    "portainer-stacks": "CreatedByUserId FilesystemPath HelmChartPath IsDetachedFromGit "
    "Option.HelmAtomic Option.Prune PreviousDeploymentInfo.FileVersion "
    "PreviousDeploymentInfo.Version Registries StackFileVersion SupportRelativePath Webhook",
}


@pytest.mark.parametrize("resource", sorted(REAL_PATHS_2453))
def test_every_field_a_real_2453_server_added_is_classified(resource: str) -> None:
    table = load_rules().type_tables[resource]
    unclassified = [
        path
        for path in REAL_PATHS_2453[resource].split()
        if table.field_class(path) is FieldClass.UNCLASSIFIED
    ]
    assert unclassified == []


@pytest.mark.parametrize(
    ("resource", "path"),
    [
        ("portainer-settings", "CloudApiKeys.CivoApiKey"),
        ("portainer-settings", "CloudApiKeys.DigitalOceanToken"),
        ("portainer-settings", "CloudApiKeys.GKEApiKey"),
        ("portainer-settings", "CloudApiKeys.LinodeToken"),
        ("portainer-stacks", "Webhook"),
    ],
)
def test_served_credentials_are_secret(resource: str, path: str) -> None:
    assert load_rules().type_tables[resource].field_class(path) is FieldClass.SECRET
