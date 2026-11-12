# Setting up a Redfish source

This guide connects driftsniff to the BMC of a server (Dell iDRAC, HPE iLO, Supermicro or any other
DMTF Redfish service) so that it records changes to the boot settings, Secure Boot, BIOS settings,
the BMC's network services, interfaces, accounts and account policy, event subscriptions,
certificates and firmware versions.

## Read this first

- **No lab BMC has been used.** The names come from the DMTF Redfish schemas and vendor pages,
  read on 2026-11-12 (`docs/vendor-notes/redfish.md`). The collector is tested against a fake BMC
  on localhost (`tests/contract/fake_redfish.py`), not a real one. Which properties your firmware
  returns is NOT VERIFIED.
- driftsniff **only reads**. Per run it sends one `POST` to sign in, `GET` requests, and one
  `DELETE` to end its session. The account's role is still the real limit.

## What driftsniff reads

| Resource | Where it comes from |
|---|---|
| `redfish-systems` | each member of `Systems`, with its `SecureBoot` resource |
| `redfish-managers` | each member of `Managers` (the BMC and its firmware version) |
| `redfish-network-protocol` | `NetworkProtocol` of each manager (HTTP, HTTPS, SSH, IPMI, SNMP, NTP...) |
| `redfish-manager-interfaces` | `EthernetInterfaces` of each manager |
| `redfish-accounts` | `AccountService` then `Accounts` (empty slots are left out) |
| `redfish-account-service` | `AccountService` (password and lockout policy, LDAP, Active Directory) |
| `redfish-event-subscriptions` | `EventService` then `Subscriptions` |
| `redfish-certificates` | `CertificateService` then `CertificateLocations` |
| `redfish-bios` | `Bios` of each system, one object per attribute |
| `redfish-firmware` | `UpdateService` then `FirmwareInventory` |

A service your BMC does not offer, or that the account may not read, shows coverage `404` or `403`
and keeps its previous state; nothing is reported as removed. Power state, health, sensor readings
and clocks are not compared, so reading them creates no noise.

## Least privilege

Use a dedicated local account (for example `driftsniff`) with the **ReadOnly** role. Some BMCs let
a ReadOnly account see only its own account, or refuse the account service or subscriptions; those
resources then show `403` (NOT VERIFIED per vendor). Grant more only if you need that coverage.

## Steps

1. On the BMC, create a local account with the ReadOnly role and Redfish access.
2. In driftsniff, select **Add source**, choose **Redfish (iDRAC, iLO, Supermicro)**, and enter a
   name, the `https://` address of the BMC (no path), the user name, the password, the interval, the
   resources and the TLS mode. BMCs usually have a self-signed certificate: use the pinned or CA
   file mode rather than switching checks off.
3. Select **Test connection**. It reads the service root, signs in, reads each resource once,
   ends the session and stores nothing.

A run sends around 30 to 100 requests, depending on the number of accounts, BIOS attributes and
firmware entries; BMCs are slow, so keep the interval at 15 minutes or more.

## What is never stored in clear

The password, the session token, SNMP community strings, the context and headers of an event
subscription, LDAP and Active Directory credentials and BIOS password attributes: driftsniff keeps
only a keyed fingerprint of each, so it can tell that one changed but not what it is.
