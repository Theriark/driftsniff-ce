# Synology DSM vendor notes

driftsniff's own notes on the DSM Web API that the Synology collector reads. They are written for
the people who build and review the collector (`src/driftsniff/collectors/synology/`) and the type
table `src/driftsniff/rules/types/synology.yaml`. Nothing here is copied from the vendor; every
statement is in our own words, with its source and the date it was read.

## Status in one paragraph

**Nothing in this file is lab-verified.** No lab DSM was used. Synology documents the discovery
and sign in calls (`SYNO.API.Info`, `SYNO.API.Auth`) in its DSM Login Web API Guide, but it does
not document any `SYNO.Core.*` configuration API. Those names, methods, parameters and fields come
from two community client libraries (S2, S3) or, where a row says **unknown**, from no written
source at all. Every such name is **UNVERIFIED** and must be checked against a lab DSM 7.x before
it is relied on. The collector and the pipeline are tested against a fake NAS on localhost
(`tests/contract/fake_synology.py`), which shows how driftsniff behaves for the names it expects,
not that a real DSM answers with them.

## Sources

| Id | Source | Read on | Used for |
|---|---|---|---|
| S1 | Synology, *DSM Login Web API Guide* (global.download.synology.com, `DSM_Login_Web_API_Guide_enu.pdf`) and the developer help page *Application Authentication* (help.synology.com/developer-guide/integrate_dsm/web_authentication.html) | 2026-11-12 | `SYNO.API.Info` query, `SYNO.API.Auth` login and logout, the sid. The PDF was fetched but its text could not be extracted here, so the error code table below is from our earlier reading of the same guide and is marked **recheck** |
| S2 | N4S4/synology-api (Python), `synology_api/core_share.py`, `core_group.py`, `core_user.py`, `core_sys_info.py`, branch master | 2026-11-12 | API names, methods and request parameters of every `SYNO.Core.*` call; response fields shown in its docstrings |
| S3 | synology-community/go-synology (Go), `pkg/api/core/share.go`, `package.go`, `network.go`, branch main | 2026-11-12 | JSON field names of shares, installed packages and the network settings |
| S4 | Synology knowledge base, *Terminal & SNMP* help page | 2026-11-12 | that SSH and Telnet only accept accounts of the administrators group (no API names) |

## Statements

| # | Statement | Source | Status |
|---|---|---|---|
| 1 | `/webapi/query.cgi` with `api=SYNO.API.Info&version=1&method=query&query=ALL` lists every API with `path`, `minVersion` and `maxVersion`. | S1 | documented |
| 2 | `SYNO.API.Auth` `login` takes `account`, `passwd`, `session` and `format=sid` and returns `data.sid`; later calls carry the sid as `_sid`; `logout` ends it. On DSM 7 the API path is `entry.cgi` (older DSM: `auth.cgi`); the collector takes the path from statement 1. | S1 | documented |
| 3 | Answers are `{"success": true, "data": ...}` or `{"success": false, "error": {"code": n}}`. | S1 | documented |
| 4 | Error codes: 102 API does not exist, 103 method does not exist, 104 version not supported, 105 no privilege, 106 session timeout, 107 session ended by a duplicate sign in, 119 sid not found; sign in: 400 wrong account or password, 401 account disabled, 402 permission denied, 403 2-step code required, 404 2-step code failed, 406 2-step verification enforced, 407 address blocked, 408 to 410 password expired or must change. | S1 | recheck (from an earlier reading) |
| 5 | DSM accepts these parameters in a form-encoded POST body as well as in the query string. The collector always POSTs, so neither the password nor the sid is ever in a URL. | S1 (the guide shows both), S2 (uses POST for several calls) | unverified for the `SYNO.Core.*` calls |
| 6 | `SYNO.Core.Share` `list` with `additional` returns `data.shares[]`; fields `name`, `desc`, `vol_path`, `uuid`, `hidden`, `encryption`, `enable_recycle_bin`, `recycle_bin_admin_only`, `is_usb_share`, `unite_permission`, `is_aclmode`. | S2 (method, `additional` values), S3 (fields) | unverified (that the additional fields are flat in the share object) |
| 7 | `SYNO.Core.Share.Permission` `list` with `name`, `action=enum`, `user_group_type` (`local_user`, `local_group`), `offset`, `limit` returns `data.items[]` with `name`, `is_readonly`, `is_writable`, `is_deny`, `is_custom`, `is_admin`, `inherit` and `data.total`. The built in account `guest` is one of the `local_user` rows. | S2 | unverified (that guest is listed) |
| 8 | `SYNO.Core.User` `list` (`type=local`, `offset`, `limit`, `additional`) returns `data.users[]` with `name`, `uid`, `description`, `email`, `expired`, `cannot_chg_passwd`, `passwd_never_expire`, `password_last_change`, `2fa_status`. | S2 | unverified (the type of `2fa_status`; the rule assumes a boolean) |
| 9 | `SYNO.Core.Group` `list` (`type=local`, `name_only=false`) returns `data.groups[]` with `name`, `gid`, `description`; `SYNO.Core.Group.Member` `list` (`group`, `ingroup=true`) returns `data.users[]` with `name`, `uid`, `description`. | S2 | unverified |
| 10 | `SYNO.Core.Terminal` `get` returns the SSH and Telnet settings. Field names `enable_ssh`, `enable_telnet`, `ssh_port`. | S2 (API and method); fields: **unknown** | unverified / unknown |
| 11 | `SYNO.Core.Security.Firewall` `get` returns whether the firewall is on (`enable_firewall`) and the active profile (`profile_name`). | **unknown** (S2 lists only the Profile API) | unknown |
| 12 | `SYNO.Core.Security.Firewall.Profile` `list` lists the firewall profiles; the collector reads them under `data.profiles`, keyed by `name`; the rules inside stay unclassified. | S2 (API, method); the answer shape: **unknown** | unknown |
| 13 | `SYNO.Core.Security.AutoBlock` `get` (field `enable`), `SYNO.Core.OTP.EnforcePolicy` `get` (no field named) and `SYNO.Core.QuickConnect` `get` (fields `enabled`, `server_alias`). | **unknown**; S2 shows QuickConnect only with the method `get_misc_config` | unknown |
| 14 | `SYNO.Core.FileServ.SMB`, `.NFS`, `.AFP` `get` return the settings of each file service. No field is named by the type table. | S2 (API, method) | unverified |
| 15 | `SYNO.Core.Package` `list` with `additional` returns `data.packages[]` with `id`, `name`, `version`, `timestamp` and `additional.status`, `additional.startable`. | S2 (method), S3 (fields) | unverified |
| 16 | `SYNO.Core.Network` `get` returns `arp_ignore`, `dns_manual`, `dns_primary`, `dns_secondary`, `enable_ip_conflict_detect`, `enable_windomain`, `gateway`, `gateway_info` (`ifname`, `ip`, `mask`, `status`, `type`, `use_dhcp`), `ipv4_first`, `multi_gateway`, `server_name`, `use_dhcp_domain`, `v6gateway`. | S3 | unverified |
| 17 | `SYNO.Core.Network.Interface` `list` returns the interfaces as the `data` list itself, each with `ifname`, `ip`, `mask`, `status`, `type`, `use_dhcp`. | S2 (API, method); fields: our reading of S3's `GatewayInfo` | unknown |
| 18 | The configuration APIs need an account of the local `administrators` group; another account gets 105. SSH and Telnet accept only administrators. | S4 (SSH/Telnet); the rest: common knowledge of DSM, not a document | unverified |
| 19 | An account with 2-step verification needs `otp_code` at every sign in (or a device token from an interactive first sign in, `enable_device_token`). The collector sends neither, so such an account cannot be used. | S1 | unverified for DSM 7.2 |
| 20 | Repeated failed sign ins from one address trigger auto block (407 afterwards). The collector never retries a refused sign in. | S1, DSM Control Panel | unverified |

## Volatile fields (ignore class)

`password_last_change` (users), `uuid` (shares), `timestamp` and `additional.startable`
(packages), `status` (interfaces and `gateway_info`). No usage, uptime or counter field is requested.

## Views the collector builds

`synology-administrators` (members of `administrators`), `synology-guest-share-access` (shares on
which guest may read or write and is not denied) and the three file service objects keyed `smb`,
`nfs`, `afp` are built by driftsniff from the answers above; they are not DSM objects. The object
floors rate an added administrator and new guest access as critical, which a field rule could not
do (a rule cannot look at the name of the object it belongs to).

## What a lab check must confirm first

Statements 10 to 13 and 17 (no written source), then statement 4 (recheck), 6 (flat additional
fields), 7 (guest listed) and 8 (type of `2fa_status`). Record the DSM version and the date here.
