# Setting up a UniFi source (P7-T6)

This guide connects driftsniff to a UniFi Network application so that it can record changes to the
configuration. It is written for the person who runs the controller and the driftsniff admin.

## Read this first: what is checked and what is not

- **One real controller has been read** (2026-11-13): a UDM Pro Max running UniFi Network
  10.6.109, with an API key made by an **owner** account. What that reading settled is labelled
  **VERIFIED on 10.6.109** below; everything else is still labelled **NOT VERIFIED**. Dependency D5
  (the vendor reference) is open and the lab checks are recorded in `docs/lab-evidence.md`. Do not rely on a
  NOT VERIFIED statement for a production controller until it has been checked and dated here.
- Names of menus and roles in the controller can differ from this guide. Field names come from the
  10.6.109 reading (`docs/vendor-notes/unifi.md`); other versions may differ.
- Some driftsniff parts named in the steps are **not built yet** (see "What is not built yet"). The
  steps describe the intended flow; the status of each part is stated where it matters.

## What driftsniff does with the controller

- It only reads. The client sends `GET` requests and nothing else, and no code path writes to the
  controller. The fake controller used in the tests implements `GET` only.
- It uses the integration API with an API key. The legacy private interface (the one the controller
  web page itself uses, with a user name and password) is **not used in CE v1**.
- The key is sent in one request header, `X-API-KEY`, and nowhere else. It is never put in a
  query string, a log line or an error text. VERIFIED on 10.6.109 (2026-11-13): the controller
  accepts the key in this header.
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

VERIFIED on 10.6.109 (2026-11-13), with a key made by an owner account:

- **The key reads every resource driftsniff lists.** All fourteen resources answered `200`.
- **No credential is returned in clear.** WiFi broadcasts come with their security type only, not
  the passphrase. RADIUS profiles come without the shared secret. VPN servers and site-to-site
  tunnels come without keys. driftsniff still treats such fields as secrets (a fingerprint only,
  never the value) in case another version returns them. Protect the key like a password anyway:
  it reads the whole network layout.

NOT VERIFIED:

- **That a key inherits the role of its creator.** If it does not, a key made by a View Only account
  could be more powerful than intended. Phase 0 test U2 is meant to check this. Status: **not
  tested**; the 10.6.109 key was made by an owner account, so it says nothing about View Only.
- **That View Only is enough to read everything driftsniff lists.** If it is not, some resources
  will show `403` in the coverage panel (step 6) and are reported as stale, not as removed. Phase 0
  test U3 is meant to check this. Status: **not tested**, for the same reason.

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
console proxy path (`/proxy/network/integration`); the first that answers wins. VERIFIED on
10.6.109: the information endpoint answers with the version and the floor check passes. NOT
VERIFIED: which of the two paths answered there was not recorded.

Then it reads each resource: sites, networks, WiFi broadcasts, firewall zones and policies, ACL
rules, DNS policies, traffic matching lists, WANs, site-to-site VPN tunnels and servers, RADIUS
profiles, device tags and devices. Firewall policies and ACL rules are read together with the
controller's own ordering lists, because their order is part of the configuration. VERIFIED on
10.6.109: those lists name only the policies you made yourself; the policies the controller makes
(system defined and derived ones) are never in them, and driftsniff places them between the two
lists of their zone pair without counting them as a mismatch. Fields that move by themselves (the
connection state of a device, whether newer firmware exists) are ignored. The type table
`src/driftsniff/rules/types/unifi.yaml` is the exact list; its field names were VERIFIED on 10.6.109,
except those of ACL rules and device tags, which that controller did not have.

## Step 6: read the coverage panel

For every resource driftsniff keeps one coverage row. The statuses are:

| Status | Meaning | What to do |
|---|---|---|
| `200` | read; the object count and the time of the last good read are shown | nothing |
| `403` | the key may not read this resource. The resource is marked stale and its objects are **not** reported as removed | give the account a role that can read it, or accept the gap |
| `404` | this version of the controller does not offer the resource. Not a failure of the key | nothing, or upgrade the controller |
| `error` | timeout, server error, bad answer, paging that repeated, or a certificate refused. The previous state is kept and nothing is reported as removed | check the address, the TLS mode and the controller |

A run is `partial` when some resource failed, or when the ordering lists did not match the policies
you made (class `ordering_mismatch`): driftsniff then repairs the list and says so. Policies the
controller made itself are expected to be missing from those lists and do not make a run partial. Today the pipeline
also counts a `404` resource as a failed resource (the run is `partial`); whether it should not is
an open decision for Delivery.

Status: the coverage rows are written by the run pipeline and are stored in the table
`resource_coverage`. **The coverage panel itself is part of P10 and does not exist yet.**

## What is not collected

- The legacy private interface, and anything a read-only integration key cannot reach.
- Site level settings: no source names an endpoint for them, so none are read.
- The filters of ACL rules are not classified yet (no ACL rule has been seen on a real controller);
  a change in them is shown as a fingerprint only. The traffic filters of firewall policies are
  classified and shown.

## What is not built yet

| Part | Status |
|---|---|
| Web form to add and edit a source, upload a CA file, coverage panel | P10, not built |
| Collector factory: builds the client from a stored source, stores the detected base path, saves the `unsupported` state | not built; `serve` starts no scheduler until it exists |
| First admin and login: `driftsniff create-admin-code` and the setup, login and logout posts exist (P9-T1, `docs/auth.md`); the setup and login pages come with P10-T3 | partly built |
| Vendor reference (D5) and lab results (U2, U3) | open; one controller (10.6.109, owner key) was read on 2026-11-13 |

## Trying the steps without a controller

The tests use a fake controller on localhost (`tests/contract/fake_unifi.py`) with hand written
fixtures for the version bands 10.1.84, 10.6.109 and a newer invented one (10.7.0), all in the
shapes the 10.6.109 controller returned and with placeholder canary values (`tests/fixtures/unifi/`). They show the client flow of steps 5 and 6:
`tests/contract/test_unifi_client.py`, `test_unifi_collection.py`, `test_unifi_coverage.py`,
`test_unifi_bands.py` and `test_unifi_real_shapes.py`. Because the web form and the factory are not built, a person cannot yet
complete steps 4 to 6 in a browser against the fake server; the walk-through by someone who did not
write the code (acceptance check 1 of P7-T6) is pending the Test Engineer's review and is **not
claimed here**.

## If something goes wrong

- Nothing appears for a resource: read its status in step 6.
- The key leaked: delete the key in the controller, create a new one and replace it in the source.
- A certificate was renewed on a pinned source: update the pin.
- A key must never be pasted into a ticket, a comment or a chat.
