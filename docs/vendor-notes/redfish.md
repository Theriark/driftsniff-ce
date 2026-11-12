# Redfish vendor notes

driftsniff's own notes on the DMTF Redfish API that the Redfish collector reads
(`src/driftsniff/collectors/redfish/`, type table `src/driftsniff/rules/types/redfish.yaml`, packs
`src/driftsniff/rules/packs/redfish/`). Nothing here is copied from the vendors; every statement is
in our own words, with its source and the date it was read.

## Status in one paragraph

The property names were read from the DMTF Redfish JSON schemas on **2026-11-12**; the session
login and logout from HPE's Redfish authentication page and the DMTF Redfish School material (the
DMTF specification page DSP0266 refused the automated read with HTTP 403, so its normative wording
was **not** read). **No lab BMC was used**: no iDRAC, iLO or Supermicro answer was seen, and the
contract tests run against `tests/contract/fake_redfish.py`, which follows these notes. What a given
vendor and firmware returns (which optional properties, which services) is **UNVERIFIED**.

## Sources

| Id | Source | Read on |
|---|---|---|
| S1 | https://redfish.dmtf.org/schemas/v1/ServiceRoot.v1_17_0.json | 2026-11-12 |
| S2 | https://redfish.dmtf.org/schemas/v1/ComputerSystem.v1_23_0.json (Boot, SecureBoot and Bios links) | 2026-11-12 |
| S3 | https://redfish.dmtf.org/schemas/v1/SecureBoot.v1_1_2.json | 2026-11-12 |
| S4 | https://redfish.dmtf.org/schemas/v1/Bios.v1_2_3.json | 2026-11-12 |
| S5 | https://redfish.dmtf.org/schemas/v1/ManagerNetworkProtocol.v1_10_1.json | 2026-11-12 |
| S6 | https://redfish.dmtf.org/schemas/v1/EthernetInterface.v1_12_1.json | 2026-11-12 |
| S7 | https://redfish.dmtf.org/schemas/v1/AccountService.v1_16_0.json | 2026-11-12 |
| S8 | https://redfish.dmtf.org/schemas/v1/ManagerAccount.v1_13_0.json | 2026-11-12 |
| S9 | https://redfish.dmtf.org/schemas/v1/EventDestination.v1_15_0.json | 2026-11-12 |
| S10 | https://redfish.dmtf.org/schemas/v1/CertificateService.v1_1_0.json, CertificateLocations.v1_0_4.json, Certificate.v1_9_0.json | 2026-11-12 |
| S11 | https://redfish.dmtf.org/schemas/v1/SoftwareInventory.v1_11_0.json | 2026-11-12 |
| S12 | https://redfish.redoc.ly/docs/concepts/redfishauthentication/ (HPE iLO Redfish authentication and sessions) | 2026-11-12 |
| S13 | https://www.dmtf.org/sites/default/files/Redfish_School-Sessions.pdf (search summary only) | 2026-11-12 |
| S14 | https://pubs.lenovo.com/xcc-restapi/ (account slots: an empty slot has `UserName` `""`) and the community.general change "Redfish: Filter empty account slots from ListUsers" (search summaries only) | 2026-11-12 |

## Statements

| # | Statement | Source | Status |
|---|---|---|---|
| 1 | The service root `/redfish/v1/` answers without a credential (iLO: the only resource that does). It has `RedfishVersion`, `Vendor` (1.5), `Product` (1.3), links `Systems`, `Managers`, `AccountService`, `SessionService`, `EventService`, `UpdateService` (1.1), `CertificateService` (1.5), and `Links.Sessions`. | S1, S12 | schema, vendor doc |
| 2 | Sign in: `POST` of `{"UserName", "Password"}` to the session collection; `201` with headers `X-Auth-Token` (sent on every later request) and `Location` (the session). Sign out: `DELETE` of the `Location`. | S12, S13 | vendor doc (iLO), DMTF training; DSP0266 wording not read |
| 3 | HTTP Basic is accepted by iLO. driftsniff does not use it: sessions are documented and keep the password out of every request but one. | S12 | vendor doc |
| 4 | ComputerSystem: `BiosVersion`, `Boot` (`BootOrder`, `BootSourceOverrideEnabled`, `BootSourceOverrideMode`, `BootSourceOverrideTarget`, `UefiTargetBootSourceOverride`, `BootNext` and more), `PowerState`, `Status`, links `Bios` and `SecureBoot`. | S2 | schema |
| 5 | SecureBoot: `SecureBootEnable` (writable), `SecureBootMode` (`SetupMode`, `UserMode`, `AuditMode`, `DeployedMode`), `SecureBootCurrentBoot` (`Enabled`, `Disabled`, read-only state). | S3 | schema |
| 6 | Bios: `AttributeRegistry`, `Attributes` (names `^[A-Za-z][A-Za-z0-9_]+$`, scalar values), `ResetBiosToDefaultsPending`. The schema says nothing about password attributes in `Attributes`. | S4 | schema |
| 7 | ManagerNetworkProtocol: `HostName`, `FQDN`, and `HTTP`, `HTTPS`, `SSH`, `IPMI`, `Telnet`, `SSDP`, `KVMIP`, `VirtualMedia`, `RDP`, `RFB`, `FTP`, `FTPS`, `SFTP`, `DHCP`, `DHCPv6`, `NTP`, `SNMP`, each with `ProtocolEnabled` and `Port`; `NTP.NTPServers`; `SNMP` has `EnableSNMPv1`, `EnableSNMPv2c`, `EnableSNMPv3`, `CommunityStrings` (`Name`, `AccessMode`, `CommunityString`, address range) and `HideCommunityStrings`. | S5 | schema |
| 8 | EthernetInterface: `InterfaceEnabled`, `MACAddress`, `IPv4Addresses`, `IPv4StaticAddresses`, `IPv6Addresses`, `NameServers`, `StaticNameServers`, `DHCPv4` (`DHCPEnabled`, `UseDNSServers`, ...), `VLAN`, `LinkStatus`, `SpeedMbps`, `Status`. | S6 | schema; members of `VLAN` not read (**UNVERIFIED**) |
| 9 | AccountService: `MinPasswordLength`, `MaxPasswordLength`, `AccountLockoutThreshold` (`0`: never locked), `AccountLockoutDuration`, `AccountLockoutCounterResetAfter`, `LocalAccountAuth` (`Enabled`, `Disabled`, `Fallback`, `LocalFirst`), `HTTPBasicAuth` (1.15: `Enabled`, `Unadvertised`, `Disabled`), `LDAP` and `ActiveDirectory` (`ServiceEnabled`, `ServiceAddresses`, `Authentication`, `RemoteRoleMapping`, `LDAPService.SearchSettings`). `Authentication.Password` is null in responses. | S7 | schema |
| 10 | ManagerAccount: `UserName`, `RoleId`, `Enabled`, `Locked`, `AccountTypes`, `PasswordChangeRequired`, `PasswordExpiration`, `Password` (write-only, null in responses). | S8 | schema |
| 11 | EventDestination: `Destination`, `Protocol`, `SubscriptionType`, `EventTypes`, `RegistryPrefixes`, `ResourceTypes`, `Context`, `HttpHeaders` (null or empty in responses), `SNMP` keys (write-only). | S9 | schema |
| 12 | CertificateService links `CertificateLocations`, whose `Links.Certificates` lists every installed certificate. Certificate: `Subject`, `Issuer`, `ValidNotBefore`, `ValidNotAfter`, `SerialNumber`, `Fingerprint`, `FingerprintHashAlgorithm` (1.3), `KeyUsage`, `CertificateString`. | S10 | schema |
| 13 | SoftwareInventory (firmware inventory member): `Id`, `Name`, `Version`, `SoftwareId`, `ReleaseDate`, `Updateable`, `Status`. | S11 | schema |
| 14 | Some BMCs list fixed account slots; an unused slot has `UserName` `""` and `Enabled` false. | S14 | Lenovo doc and community code; Dell iDRAC slot behaviour **UNVERIFIED** |
| 15 | iDRAC uses ids `System.Embedded.1` and `iDRAC.Embedded.1`; iLO and Supermicro use `1`. iDRAC firmware inventory ids hold the version (`Installed-<component>-<version>`), so an update replaces the entry. | none read this time | **UNVERIFIED** (vendor knowledge; the collector does not depend on it) |
| 16 | Which privileges a ReadOnly account has for other accounts, the account service and event subscriptions differs per vendor. | none read | **UNVERIFIED** |
| 17 | The Manager schema (`FirmwareVersion`, `ManagerType`, `DateTime`, `DateTimeLocalOffset`, `GraphicalConsole`, `SerialConsole`, `CommandShell`, links `NetworkProtocol` and `EthernetInterfaces`) was not reread for this note. | none read | **UNVERIFIED** (long-standing names) |
| 18 | `RoleId` values other than the predefined `Administrator`, `Operator`, `ReadOnly` (iDRAC `None`, custom roles). | none read | **UNVERIFIED** |

## Decisions of driftsniff

- **One collector, vendor differences as data.** Every resource is reached by following links from
  the service root; no vendor id is written in code. `Oem` is ignored in every table, and a property
  a vendor adds that the table does not list stays unclassified (a fingerprint only).
- **Links are untrusted input.** Only a plain path below `/redfish/v1` is followed (no host, query,
  fragment, backslash or `..`), always on the address of the source.
- **Annotations are dropped** by the collector (any key holding `@`, such as `@odata.etag`, which
  changes on every write), and so is every value that is only a link.
- **Bounded runs:** at most 256 members per collection and 600 requests per run; each document is
  read once per run, so the probe and the resources share reads.
- **Session handling:** the password only in the sign in body; the token only in `X-Auth-Token`;
  the session is deleted at the end of every run. httpcore logs response headers at DEBUG, so the
  collector filters the trace line that holds `X-Auth-Token`. A refused sign in is never retried in
  the same run, because BMCs lock accounts.
- **Accounts are keyed by user name** and empty slots are left out, so a new account in a slot is an
  added account (critical by the floor), not a modified slot.
- **BIOS attributes are one object each** (`<system id>/<attribute>`), so a change shows the
  attribute and its values. An attribute whose name holds `password`, `passwd` or `pwd` keeps its
  value in `secret_value` (fingerprint only), in case a BMC returns it.
- **Secure Boot** is read from the standard SecureBoot resource and embedded in the system, so
  switching it off is one critical change whatever the vendor's BIOS attribute is called.
- **Firmware entries** are keyed by `Id`; where a vendor puts the version in the id, an update is a
  removed and an added entry, both medium by the floor.
- **Volatile:** power state, `Status` everywhere, readings, `DateTime`, `LinkStatus`, `SpeedMbps`,
  `Locked`, `PasswordExpiration`, `LastResetTime`, `SecureBootCurrentBoot`,
  `RemainingAutomaticRetryAttempts`. Sensors and sessions are not read at all.
- **Not read:** sensors, logs, chassis, storage, `$expand` (optional per service; not needed at this
  size), HTTP Basic, OEM extensions.
