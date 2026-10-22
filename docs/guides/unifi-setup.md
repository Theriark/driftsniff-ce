# Setting up a UniFi source (P7-T6)

This guide connects driftsniff to a UniFi Network application so that it can record changes to the
configuration. It is written for the person who runs the controller and the driftsniff admin.

## Read this first: what is checked and what is not

- **No lab controller has been used.** Dependency D5 (the vendor reference) is open and
  `docs/lab-evidence.md` does not exist yet. Every statement about the UniFi side below is labelled
  **NOT VERIFIED** unless it says otherwise. Do not rely on a NOT VERIFIED statement for a
  production controller until it has been checked and dated here.
- Names of menus, roles and fields in the controller can differ from this guide. The names come from
  third party descriptions (`docs/vendor-notes/unifi.md`, read on 2026-10-21), not from the vendor.
- Some driftsniff parts named in the steps are **not built yet** (see "What is not built yet"). The
  steps describe the intended flow; the status of each part is stated where it matters.

## What driftsniff does with the controller

- It only reads. The client sends `GET` requests and nothing else, and no code path writes to the
  controller. The fake controller used in the tests implements `GET` only.
- It uses the integration API with an API key. The legacy private interface (the one the controller
  web page itself uses, with a user name and password) is **not used in CE v1**.
- The key is sent in one request header, `X-API-KEY`, and nowhere else. It is never put in a
  query string, a log line or an error text. NOT VERIFIED: that this is the header name the vendor
  uses (D5 open).
- The key is encrypted at rest (AES-256-GCM, see `key-management.md`) and is **never shown again**
  after you save it. To change it, enter a new one; to remove it, delete the source.

## Before you start

1. A controller that runs UniFi Network **10.1.84 or later**. This floor is our own decision. Below
   it the source is meant to be saved with the state `unsupported`, a plain explanation, and no
   collection (see "What is not built yet" for the status).
2. The address of the controller as an `https://` address, for example
   `https://controller.example.invalid` (a placeholder, not a real address). The address must
   not hold a user name, a password, a query or a fragment. Plain `http://` needs the per-source
   option `allow_plain_http`, which writes an audit event; do not use it on a network you do not
   control. Link-local and cloud metadata addresses (`169.254.0.0/16`, `fe80::/10`,
   `100.100.100.200`) are always refused.
3. The certificate of the controller. See step 4 for the four TLS modes.

## Step 1: create a dedicated local admin with the View Only role

On the controller, create a local account used only by driftsniff and give it the **View Only**
role. Do not reuse a person's account and do not use an owner or super admin account.

NOT VERIFIED: the menu path, the exact name of the role, and that this role exists for local
accounts on every supported version.

## Step 2: create the API key from that account

Sign in to the controller as the new account and create an API key in the integrations part of the
settings. Copy it once; the controller may not show it again.

NOT VERIFIED:

- **That a key inherits the role of its creator.** If it does not, a key made by a View Only account
  could be more powerful than intended. Phase 0 test U2 is meant to check this. Status: **not
  tested**.
- **That View Only is enough to read everything driftsniff lists.** If it is not, some resources
  will show `403` in the coverage panel (step 6) and are reported as stale, not as removed. Phase 0
  test U3 is meant to check this. Status: **not tested**.
- **Which secrets the API returns in clear.** driftsniff treats the WiFi passphrase, the RADIUS
  shared secret and the VPN pre-shared keys as secrets: it keeps a fingerprint (a keyed hash that
  shows that the value changed) and never stores or shows the value. Whether the controller
  actually returns those values in clear to a View Only key is **not verified** (tests U2 and U3);
  if it does, the key itself can read them from the controller, so protect the key like a password.
  VPN key behaviour is **unknown**.

When `docs/lab-evidence.md` exists, replace each NOT VERIFIED label above with the result and the
date of the test.

## Step 3: check what the key can do before you give it to driftsniff

Optional, and the only way to settle the questions in step 2 for your own controller: with the key,
try to read one thing and then try one write that you can undo (for example create and delete a test
tag). If the write succeeds, the key has more rights than View Only. Make a new account with a
narrower role. driftsniff itself never writes.

## Step 4: add the source

An admin adds a source with a name, the type `unifi`, the base address and the key. Choose the TLS
mode of the source (`docs/tls.md`):

| Mode | Use it when |
|---|---|
| `verify` (default) | the certificate chains to a normal public or system trusted authority |
| `ca_file` | your own certificate authority signed it; put the PEM bundle (certificates only, at most 64 KB) in `/data/ca` and give the file name |
| `pinned` | the controller uses a self-signed certificate; give the SHA-256 of the certificate in DER form (64 hex characters). Renewing the certificate changes the pin |
| `insecure` | never recommended; needs the confirmation text `I understand the risk`, writes an audit event and marks the source permanently |

The poll interval is 60 to 3600 seconds (default 300).

Status: the source service (`driftsniff.sources.service`) validates and stores all of this today.
The **web form for adding a source and the field for uploading a CA file are part of P10 and do not
exist yet**. The cloud connector address option (off by default, with a warning that configuration
data then passes through the vendor cloud) is **not added yet** either; do not point driftsniff at
the vendor cloud.

## Step 5: let the first collection run

On the first collection driftsniff probes the controller information endpoint to learn the
application version. It tries the direct integration path first (`/integration`) and then the
console proxy path (`/proxy/network/integration`); the first that answers wins. NOT VERIFIED: both
paths and the information endpoint (D5 open).

Then it reads each resource: sites, networks, WiFi broadcasts, firewall zones and policies, ACL
rules, DNS policies, traffic matching lists, WANs, site-to-site VPN tunnels and servers, RADIUS
profiles, device tags and devices. Firewall policies and ACL rules are read together with the
controller's own ordering lists, because their order is part of the configuration. Fields that move
by themselves (statistics, uptime, counters, a radio channel under automatic selection) are ignored.
The type table `src/driftsniff/rules/types/unifi.yaml` is the exact list; every UniFi field name in it
is NOT VERIFIED.

## Step 6: read the coverage panel

For every resource driftsniff keeps one coverage row. The statuses are:

| Status | Meaning | What to do |
|---|---|---|
| `200` | read; the object count and the time of the last good read are shown | nothing |
| `403` | the key may not read this resource. The resource is marked stale and its objects are **not** reported as removed | give the account a role that can read it, or accept the gap |
| `404` | this version of the controller does not offer the resource. Not a failure of the key | nothing, or upgrade the controller |
| `error` | timeout, server error, bad answer, paging that repeated, or a certificate refused. The previous state is kept and nothing is reported as removed | check the address, the TLS mode and the controller |

A run is `partial` when some resource failed, or when the ordering lists did not match the policies
(class `ordering_mismatch`): driftsniff then repairs the list and says so. Today the pipeline
also counts a `404` resource as a failed resource (the run is `partial`); whether it should not is
an open decision for Delivery.

Status: the coverage rows are written by the run pipeline and are stored in the table
`resource_coverage`. **The coverage panel itself is part of P10 and does not exist yet.**

## What is not collected

- The legacy private interface, and anything a read-only integration key cannot reach.
- Site level settings: no source names an endpoint for them, so none are read.
- The nested traffic filter objects of firewall policies and ACL rules are not classified yet (their
  field names are not known); a change in them is shown as a fingerprint only.

## What is not built yet

| Part | Status |
|---|---|
| Web form to add and edit a source, upload a CA file, coverage panel | P10, not built |
| Collector factory: builds the client from a stored source, stores the detected base path, saves the `unsupported` state | not built; `serve` starts no scheduler until it exists |
| First admin and login (`create-admin-code` prints "not implemented yet") | P9-T1, not built |
| Vendor reference (D5) and lab results (U2, U3) | open; no controller was used |

## Trying the steps without a controller

The tests use a fake controller on localhost (`tests/contract/fake_unifi.py`) with hand written
fixtures for the version bands 10.1.84, 10.3.58 and a newer invented one (10.4.12), all with
placeholder canary values (`tests/fixtures/unifi/`). They show the client flow of steps 5 and 6:
`tests/contract/test_unifi_client.py`, `test_unifi_collection.py`, `test_unifi_coverage.py` and
`test_unifi_bands.py`. Because the web form and the factory are not built, a person cannot yet
complete steps 4 to 6 in a browser against the fake server; the walk-through by someone who did not
write the code (acceptance check 1 of P7-T6) is pending the Test Engineer's review and is **not
claimed here**.

## If something goes wrong

- Nothing appears for a resource: read its status in step 6.
- The key leaked: delete the key in the controller, create a new one and replace it in the source.
- A certificate was renewed on a pinned source: update the pin.
- A key must never be pasted into a ticket, a comment or a chat.
