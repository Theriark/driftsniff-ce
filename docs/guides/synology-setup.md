# Setting up a Synology DSM source

This guide connects driftsniff to a Synology NAS running DSM 7.x so that it records changes to
shared folders and their permissions, users, groups and administrators, SSH and Telnet, the
firewall, auto block, file services, packages, network settings and QuickConnect.

## Read this first: what is checked and what is not

- **No lab DSM has been used.** Synology documents only the sign in part of the Web API. Every
  configuration call (`SYNO.Core.*`) and field name comes from community libraries or, for SSH,
  firewall, auto block and QuickConnect, from no written source at all. They are listed with their
  status in [vendor-notes/synology.md](../vendor-notes/synology.md). Treat every statement about
  the DSM side as **NOT VERIFIED** until a lab check is dated there.
- The collector and the pipeline are tested against a fake NAS on localhost
  (`tests/contract/fake_synology.py`). That shows how driftsniff behaves; it does not show that a
  real DSM answers the same way.

## What driftsniff does with DSM

- **It only reads.** Every call is a `list` or `get`, plus the sign in and sign out.
- **DSM has no API keys**, so the source holds the user name and the password of a DSM account,
  in two fields. The password is encrypted at rest and never shown again.
- Each run signs in once (`SYNO.API.Auth`), reads, and signs out. The password and the session id
  travel only in the body of `POST` requests, never in a URL, a log line or an error text.
- A refused sign in is **not retried** in the same run, so driftsniff cannot trip auto block on
  its own. The next run tries again.
- A session that DSM ends in the middle of a run (restart, timeout) is renewed once.

## The account: least privilege, honestly

DSM has no read-only administrator. The configuration APIs answer only an account of the local
**administrators** group (NOT VERIFIED; another account gets error 105, shown as `403` on the
resources it may not read). So the account driftsniff uses **can change everything on the NAS**,
and it can sign in over SSH when SSH is on. Reduce the risk:

1. Create a **dedicated** account, for example `driftsniff-reader`, used by nothing else. Never use
   `admin` or a person's account.
2. Give it a long random password and set **Password never expires** for it, or put the renewal
   date in your calendar (an expired password stops collection with `password_expired`).
3. Add it to **administrators** only. Deny it every application it does not need in
   **Control Panel > User & Group > Edit > Applications**.
4. **2-step verification cannot be used** for this account: DSM asks for a code at every sign in
   and driftsniff cannot give one (`two_factor_required`). If you enforce 2-step verification for
   administrators, exempt this account and compensate with the next step.
5. Restrict where the account can sign in from: in **Control Panel > Security > Firewall** allow
   DSM (port 5001) only from the address of driftsniff, and keep **auto block** on.
6. Use `https://` (DSM usually listens on port 5001). For a self-signed DSM certificate use the
   **Pinned certificate** TLS mode, so the password is only sent to that certificate.

A non-administrator account works for nothing but the sign in; every resource then shows `403`.
DSM 7.2 delegated administration was not examined.

## Add the source

In driftsniff choose **Add source > Synology DSM** and enter:

| Field | Value |
|---|---|
| Name | for example `nas-office` |
| Address | `https://nas.example.invalid:5001` (no path, no user name) |
| User name | `driftsniff-reader` |
| Password | the password of that account |
| Resources | turn off what you do not want to track |
| TLS mode | Verify, your CA bundle, or Pinned certificate |

**Test connection** signs in, reads every resource once and signs out. It stores nothing.

## What is read and how changes are rated

| Resource | DSM API (unverified) | Rating (rule pack `packs/synology`) |
|---|---|---|
| Shared folders, with user and group permissions | `SYNO.Core.Share`, `SYNO.Core.Share.Permission` | added or removed high, any change high, description low |
| Guest access to shared folders | built from the guest permission rows | new guest access critical |
| Users | `SYNO.Core.User` | added or removed high, any change high, description and mail low, 2-step turned off critical |
| Groups, with members | `SYNO.Core.Group`, `SYNO.Core.Group.Member` | high |
| Administrators | members of `administrators` | added critical, removed high |
| SSH and Telnet | `SYNO.Core.Terminal` | Telnet on critical, SSH on high, port medium |
| Firewall, firewall profiles | `SYNO.Core.Security.Firewall`, `.Profile` | firewall off critical, any change high |
| Auto block | `SYNO.Core.Security.AutoBlock` | turned off high |
| 2-step verification policy | `SYNO.Core.OTP.EnforcePolicy` | high |
| File services (SMB, NFS, AFP) | `SYNO.Core.FileServ.*` | medium |
| Packages | `SYNO.Core.Package` | installed or removed medium, version low |
| Network settings, interfaces | `SYNO.Core.Network`, `.Network.Interface` | DNS and gateway high, others medium |
| QuickConnect | `SYNO.Core.QuickConnect` | turned on high |

Usage, uptime, timestamps and link status are not stored. A resource whose API the NAS does not
list shows `404` in the coverage panel and keeps its history.

## Troubleshooting

| Run error | Meaning |
|---|---|
| `unauthorized` | wrong user name or password (DSM error 400) |
| `two_factor_required` | the account has 2-step verification |
| `address_blocked` | auto block blocked driftsniff's address; unblock it in **Security > Protection** |
| `password_expired` | the password of the account expired or must be changed |
| `forbidden` (per resource) | the account is not an administrator (DSM error 105) |
| `no_api` | the address does not answer as DSM, or the sign in API is too old |
