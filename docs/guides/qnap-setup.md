# Setting up a QNAP source

This guide connects driftsniff to a QNAP NAS running QTS or QuTS hero, so that it records changes to
the system settings, network adapters, volumes, shared folders, web interface flags and installed
apps.

## Read this first: what is checked and what is not

- **No lab QNAP has been used.** QNAP publishes no reference for the configuration interface that
  driftsniff reads. The paths and names come from open source clients that read real systems
  (`docs/vendor-notes/qnap.md`, read on 2026-11-12). Every statement about the QNAP side is
  **NOT VERIFIED** until a lab result is dated there.
- The collector is tested against a fake QNAP on localhost (`tests/contract/fake_qnap.py`). That
  shows how driftsniff behaves for the answers it expects, not that a real NAS sends them.
- **Not watched:** users, user groups, SSH, Telnet, SMB, NFS, FTP, myQNAPcloud, UPnP port
  forwarding and the guest access of shared folders. No read-only call for them is known yet; the
  vendor notes say how to add them once one is captured on a lab NAS.

## What driftsniff does with the NAS

- **It only reads.** It signs in with `POST /cgi-bin/authLogin.cgi` (the password in the request
  body, base64 encoded as QNAP expects, never in a URL), reads with `GET`, and signs out
  (`/cgi-bin/authLogout.cgi`) at the end of every check. NOT VERIFIED: the paths.
- The session id goes in the `sid` query parameter of each read, as QNAP's own clients send it. It
  is never written to a log or an error text.
- If a session ends during a check, driftsniff signs in once more and repeats that read once. If
  the fresh session is refused too, the resource is shown as not readable (`403`) and its stored
  state is kept.
- Answers are XML. driftsniff refuses any answer with a document type declaration (no entity
  expansion, no external entities) and any answer over 16 MB.
- The password is **encrypted at rest** and never shown again.

## Before you start

1. The `https://` address of the NAS, for example `https://nas.example.invalid` (a placeholder).
   Plain `http://` needs the option **Allow a plain http address**, which writes an audit event; the
   password would then travel unencrypted.
2. The certificate of the NAS: a self-signed QTS certificate needs the mode **Pinned certificate**
   or **Your own CA bundle** (see configuration.md).
3. An account (below).

## The account

QTS has no read-only administrator, and the CGIs driftsniff reads need the administrators group
(NOT VERIFIED). So:

1. Create a **dedicated** user for driftsniff in the administrators group. Never reuse a person's
   account.
2. Do **not** turn on 2-step verification for it: driftsniff cannot answer the second step and the
   check fails with "the account uses 2-step verification". Compensate with a long random password.
3. Allow that account to sign in only from the driftsniff host if you can (QTS Security allow list,
   or a firewall in front of the NAS).

With a normal user, **Test connection** fails because the system information read is refused.

## Add the source

In driftsniff: **Sources**, **Add a source**, **QNAP QTS / QuTS hero**. Enter the name, the address,
the user name and the password, choose the TLS mode and the resources, then **Test connection** and
**Save**. Over the API the user name is the source option `username` and the password is the
credential.
