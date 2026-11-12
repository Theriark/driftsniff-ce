# QNAP QTS / QuTS hero vendor notes

These are driftsniff's own notes on the QNAP interface the QNAP collector reads
(`src/driftsniff/collectors/qnap/`). They are written for the people who build and review the
collector and the type table `src/driftsniff/rules/types/qnap.yaml`. Nothing is copied from the
sources below; every statement is in our own words, with its source and the date it was read.

## Status in one paragraph

**Nothing in this file is lab-verified.** QNAP publishes developer PDFs for authentication and the
File Station API, but the copies at `eu1.qnap.com/dev/` answered 404 on 2026-11-12, and QNAP
publishes no reference for the configuration CGIs at all. Every path, parameter and element name
below comes from open source clients that read real systems, and one of them ships answers captured
from real NAS models. Every name is therefore **UNVERIFIED** until a lab QNAP or a vendor document
confirms it. The contract tests run against a fake (`tests/contract/fake_qnap.py`) that serves the
shapes described here; that shows how driftsniff behaves for these shapes, not that a real NAS
answers with them.

## Sources

All sources were read on **2026-11-12**.

| Id | Source | What it was used for |
|---|---|---|
| S1 | python-qnapstats (`github.com/colinodell/python-qnapstats`, the library behind the Home Assistant QNAP integration), `qnapstats/qnap_stats.py` | Sign in (POST, base64 `pwd`, `authSid`, `authPassed`), the system information and disk usage CGIs and their element names |
| S2 | python-qnapstats test answers captured from real models (`tests/responses/TS-1677XU-RP-4.5.2`, `TS-451-4.2.2`) | The XML shape: `QDocRoot`, CDATA values, `firmware/version`, `hostname`, numbered adapter elements, `volumeList/volume`, `volumeUseList/volumeUse/folder_element/sharename` |
| S3 | nmap script `http-qnap-nas-info.nse` | The unauthenticated answer of `GET /cgi-bin/authLogin.cgi` and its web interface flags (`forceSSL`, `stunnelPort`, `QWebEnabled` and the others) |
| S4 | QNAP Go SDK `github.com/tmeckel/qnap-core-sdk-for-go` (`services/auth`, `services/apps`), last pushed 2023-12-18 | Sign out at `/cgi-bin/authLogout.cgi`; the app list call and the `qItem/attr` element names |
| S5 | Two further open source monitors that read QTS (`selfhostr/dumbmonit`, `crates/collectors/src/qnap/mod.rs`; `hyperprox/alpha`, `apps/api/src/lib/qnap/`) | Agreement on `authLogout.cgi?logout=1&sid=`; the 2-step verification marker `need_2sv` in the sign in answer |
| S6 | QNAP's user documentation (docs.qnap.com, QTS 5.x) | That most configuration needs the administrators group; that 2-step verification is a per-account setting |

## Statements

| # | Statement | Source | Status |
|---|---|---|---|
| 1 | Sign in is `POST /cgi-bin/authLogin.cgi` with form fields `user` and `pwd`, `pwd` being the UTF-8 password in base64. POST is accepted (S1 sends POST first and only falls back to GET on old firmware; S4 and S5 send POST only). driftsniff never uses the GET fallback, so the password is never in a URL. | S1, S4, S5 | unverified |
| 2 | The answer is a `QDocRoot` XML document; `authPassed` 1 and `authSid` mean signed in; `authPassed` 0 means refused. `isAdmin`, `username` and `groupname` are also present. | S1, S2 | unverified (captured answer of 4.5.2) |
| 3 | An account with 2-step verification answers `need_2sv` 1 instead of a session; driftsniff does not support such accounts and the probe fails with a fixed text. | S5 | unverified |
| 4 | Reads are `GET` with the session in the query parameter `sid`. A read without a valid session answers `authPassed` 0 (HTTP 200). | S1, S5 | unverified |
| 5 | Sign out is `GET /cgi-bin/authLogout.cgi?logout=1&sid=<sid>` (S5); S4 sends the same as a POST with `logout=1` in the body. The task brief named `authLogin.cgi?logout=1`; no source read here uses that path, so driftsniff follows the sources. | S4, S5 | unverified |
| 6 | `GET /cgi-bin/management/manaRequest.cgi?subfunc=sysinfo&hd=no&multicpu=1` returns `model/displayModelName`, `firmware/version`, `build`, `patch`, `hostname`, and under `func/ownContent/root` the `timezone`, the repeated `DNS_LIST` and per adapter numbered elements `ifname<N>`, `dname<N>`, `eth_ip<N>`, `eth_mask<N>`, `eth_mac<N>`, `eth_usage<N>` (`DHCP` or `STATIC`), `eth_max_speed<N>`, `eth_ipv6_info<N>/eth_ipv6_enable`, `dnsinfo<N>/dns1..`. | S1, S2 | unverified (captured answer of 4.5.2) |
| 7 | The same answer holds uptime, CPU and memory use, temperatures, fan speeds and packet counters. They are volatile and are never taken. | S2 | plan |
| 8 | `GET /cgi-bin/management/chartReq.cgi?chart_func=disk_usage&disk_select=all&include=all` returns `volumeList/volume` (`volumeValue`, `volumeLabel`, `volumeStat`, `volumeDisks`, `volumeType`, `encryptfs_bool`, `is_default_volume`, plus volatile sizes and progress) and `volumeUseList/volumeUse` with `volumeValue` and one `folder_element` per shared folder (`sharename`, `used_size`, and `type` `system` for system folders). | S1, S2 | unverified (captured answers of 4.2.2 and 4.5.2) |
| 9 | `GET /cgi-bin/application/appRequest.cgi?subfunc=qpkg&apply=10&action=reload&lang=eng` lists the installed apps as `func/ownContent/qItem` with `name` and `attr` (`displayName`, `version`, `build`, `enable` `TRUE`/`FALSE`, `provider`, `author`, `class`, `store`, `unofficial`, `code_signing_status`, `installPath`, `servPort`, `webPort`, `webSSLPort`, and run state fields). It is the call S4 names `List`; `apply=10&action=reload` is read as "reload the list", not as an action on an app. **This is the least certain call of the collector**: if a lab shows it changes anything, turn the resource `qnap-apps` off and remove it. | S4 | unverified |
| 10 | `GET /cgi-bin/authLogin.cgi` without parameters answers, without a session, with the model, firmware and the web interface flags `forceSSL`, `stunnelPort`, `webFSEnabled`, `QMultimediaEnabled`, `MSV2WebEnabled`, `QDownloadEnabled`, `NVREnabled`, `WFM2`, `QMusicsEnabled`, `QVideosEnabled`, `QPhotosEnabled`, `QWebEnabled`, `QWebPort`, `QWebSSLEnabled`, `QWebSSLPort`. | S3 | unverified |
| 11 | The system information, disk usage and app CGIs need an administrator; a normal user gets `authPassed` 0 or nothing. driftsniff reports such a read as coverage `403`. There is no read-only administrator role in QTS. | S6, our reading of S1 to S5 | unverified |
| 12 | Answers are `text/xml`. driftsniff does not rely on the content type; it parses the body and requires the root `QDocRoot`. | S1 | unverified |

## Not covered

No source read for this task names a read-only call for these, so the collector does not read them
and the rule pack has no rules for them:

- users and user groups (including "user added to administrators" and "admin account enabled");
- network services: SSH, Telnet, SMB, NFS, FTP;
- myQNAPcloud and UPnP port forwarding;
- the guest access and permissions of a shared folder.

The only user CGI found (`/cgi-bin/priv/privRequest.cgi?subfunc=user`) appears in a script that
**deletes** users; its read form is unknown. Guessing it is not acceptable for a read-only tool. To
add these resources, first capture the requests the QTS web interface makes on a lab NAS (browser
developer tools, administrator signed in, read-only pages only), record them here with the date and
firmware, then add the resources, type tables and the rules the plan asked for (Telnet on critical,
SSH on high, admin account enabled high, administrators membership critical, myQNAPcloud / UPnP
high, share guest access critical).

## Least privilege

QTS has no read-only administrator. The account driftsniff signs in with must be in the
administrators group for coverage of everything above (statement 11). Recommendations:

- a dedicated account, never a person's;
- 2-step verification is not supported (statement 3), so compensate with a long random password and
  network restrictions (allow the driftsniff host only, for example with the QTS Security / Allow
  list or a firewall in front of the NAS);
- driftsniff signs out after every check, so no session is left open.

With a normal (non-administrator) account the probe fails because the system information read is
refused; expect that, it is not a bug.
