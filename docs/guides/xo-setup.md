# Setting up a Xen Orchestra source (P8-T5)

This guide connects driftsniff to a Xen Orchestra (XO) server so that it can record changes to the
configuration of your pools, hosts, networks, storage, backup jobs and XO's own users and groups. It
is written for the person who runs XO and the driftsniff admin.

## Read this first: what is checked and what is not

- **No lab Xen Orchestra has been used.** The vendor reference was not read for this guide, and
  `docs/lab-evidence.md` does not exist yet (Phase 0 tests X1 to X4 are open). Every statement about
  the XO side below is labelled **NOT VERIFIED** unless it says otherwise. Do not rely on a statement
  with that label for a production XO until it has been checked and dated here.
- Names of menus, roles, collections and fields can differ from this guide. The names come from our
  own plan and our own reading of how such an interface is laid out (`docs/vendor-notes/xo.md`, read
  on 2026-10-22), not from the vendor.
- Some driftsniff parts named in the steps are **not built yet** (see "What is not built yet"). The
  steps describe the intended flow; the status of each part is stated where it matters.
- The client and the pipeline are tested against a fake XO on localhost
  (`tests/contract/fake_xo.py`). That shows how driftsniff behaves for the names it expects. It does
  not show that a real XO answers with them.

## What driftsniff does with XO

- **It only reads.** The client sends `GET` requests and nothing else, and no code path writes to
  XO. The fake XO used in the tests implements `GET` only. This does not limit the credential you
  create: a credential has the rights of its user (see the two modes below), so the only protection
  against a write is the role you give that user.
- It uses the REST interface (`/rest/v0`). NOT VERIFIED: the prefix and the collection names.
- The credential is a session credential (a token) of an XO user. It is sent in one cookie named
  `authenticationToken` and nowhere else: never as basic credentials, never in a query string, a log
  line or an error text. NOT VERIFIED: that this is the cookie name XO uses.
- The credential is **encrypted at rest** (AES-256-GCM, see `key-management.md`) and is **never shown
  again** after you save it. To change it, enter a new one; to remove it, delete the source.
- Each collection is requested once, with an explicit list of the fields driftsniff keeps, as
  newline delimited JSON read line by line, so memory stays flat even for a large collection.
  Collections are treated as unpaginated and sorted by id after reading; the order XO returns is
  never trusted.
- The **XO configuration export is never ingested.** It holds credentials. Do not upload it to
  driftsniff, paste it into a ticket or attach it to an issue.

## Before you start

1. An XO server you can reach over `https://`, for example `https://xo.example.invalid` (a
   placeholder, not a real address). The address must not hold a user name, a password, a query or
   a fragment. Plain `http://` needs the per-source option `allow_plain_http`, which writes an audit
   event; do not use it on a network you do not control. Link-local and cloud metadata addresses
   (`169.254.0.0/16`, `fe80::/10`, `100.100.100.200`) are always refused.
2. The certificate of XO. See step 4 for the four TLS modes.
3. A decision about the mode of access, below. It is the most important choice in this guide.

## Choose the mode of access

| | (a) Admin session credential | (b) Non-admin user with a read-only ACL role |
|---|---|---|
| Set up | simple: one admin user, one credential | harder: a user, an ACL role that only reads, the objects it may read |
| Coverage | every collection driftsniff reads (expected) | narrower: the admin-only collections answer `403` (expected) |
| Risk if the credential leaks | **an attacker holds a full XO admin**: can change or delete VMs, hosts, storage, backups and users | an attacker can read what the role reads |
| Status | NOT VERIFIED | NOT VERIFIED (test X2) |

### Mode (a): an admin session credential

This is simple, and it is **over-privileged**. driftsniff only sends reads, but the credential can do
everything its admin user can do. If it leaks, the person who holds it controls your virtualisation
platform. Use it only when you need the changes that mode (b) cannot see, and then:

- create a **dedicated** admin user for driftsniff; never reuse a person's account;
- give the credential an expiry and put the renewal date in your calendar (see "Expiry and renewal");
- restrict at the network level who can reach XO from where driftsniff runs;
- treat the credential like a password: it must never be pasted into a ticket, a comment or a chat.

### Mode (b): a non-admin user with a read-only ACL role

Create a normal (non-admin) user and give it an ACL role that can only view, on the pools, hosts,
VMs, networks and storage you want watched. Then create the credential from that user.

**The coverage is narrower, and the missing part matters.** In the plan, a read-only role is
expected to get `403` on four collections (test X2 is open, so this is an expectation, not a result):

| Collection | What it holds | What you do not see in mode (b) |
|---|---|---|
| `users` | XO users, their permission level, groups and sign-in methods | a user promoted to admin |
| `groups` | XO groups, their members and ACL roles | a change of the roles of a group |
| `servers` | the connections from XO to hosts | a server set to read-write, or certificate checks switched off |
| `backup-repositories` | the backup remotes (shown as `remotes` in the plan) | a change of the backup destination |

These are some of the most security-sensitive changes driftsniff can report (the plan rates them
high or critical). In mode (b) they **cannot be observed**, and driftsniff shows `403` for them in
the coverage panel and marks them stale. Their objects are **not** reported as removed.

Collections expected to be reachable in mode (b) (the fake read-only fixture serves exactly these;
**NOT VERIFIED** for a real XO, test X2 open): `vms`, `vm-templates`, `hosts`, `pools`, `networks`,
`pifs`, `pbds`, `srs`, `vifs`, `vbds`, `vdis`, `backup-jobs`, `schedules`, `proxies`, `acl-roles` and
`acl-privileges`. NOT VERIFIED too: that an ACL role gives read access through the REST interface at
all, and whether a read-only user sees every object or only those the role names.

When `docs/lab-evidence.md` exists, replace each NOT VERIFIED label in this section with the result
and the date of test X2.

## Step 1: create the user

In XO, create the dedicated user for driftsniff: an admin user for mode (a), a non-admin user with a
read-only ACL role for mode (b). NOT VERIFIED: the menu path and the exact names of the roles.

## Step 2: create the credential

Sign in to XO as that user and create an authentication token (a session credential) from the
user's own settings. Copy it once; XO may not show it again. If XO lets you choose a lifetime, choose
a short one and note the date. NOT VERIFIED: where XO creates the token, whether it offers an
expiry, and whether the token has the rights of its user and no more (it may be wider if XO treats
tokens differently from the user).

## Step 3: check what the credential can do before you give it to driftsniff

Optional, and the only way to settle the questions above for your own XO. With the credential, read
one thing, then try one change that you can undo (for example rename a test VM and rename it back).
If the change succeeds, the credential can write. In mode (b) that means the role is too wide:
narrow it. Do this in a lab or on a test object only. driftsniff itself never writes.

## Step 4: add the source

An admin adds a source with a name, the type `xo`, the base address and the credential. Choose the
TLS mode of the source (`docs/tls.md`):

| Mode | Use it when |
|---|---|
| `verify` (default) | the certificate chains to a normal public or system trusted authority |
| `ca_file` | your own certificate authority signed it; put the PEM bundle (certificates only, at most 64 KB) in `/data/ca` and give the file name |
| `pinned` | XO uses a self-signed certificate; give the SHA-256 of the certificate in DER form (64 hex characters). Renewing the certificate changes the pin |
| `insecure` | never recommended; needs the confirmation text `I understand the risk`, writes an audit event and marks the source permanently |

XO is often installed with a self-signed certificate. Prefer `pinned` or `ca_file` over `insecure`.
The poll interval is 60 to 3600 seconds (default 300).

You can also enter the **expiry date of the credential** (optional, see the next section).

Status: the source service (`driftsniff.sources.service`) validates and stores the address, the
credential, the TLS options and the interval today. The **web form for adding a source, the field
for the expiry date and the upload of a CA file are part of P10 and do not exist yet.** The entered
expiry date has no stored option yet either (see "What is not built yet").

## Step 5: let the first collection run

On the first collection driftsniff checks the address and asks the REST root once. `401` or `403`
means XO refused the credential; a missing interface (a `404`, a web page, an answer that is not
JSON) is reported as "the Xen Orchestra REST interface did not answer". XO reports no version
through this call, so driftsniff stores none. NOT VERIFIED: the REST root and its behaviour.

Then it reads, one request per collection and in this order: `vms`, `vm-templates`, `hosts`,
`pools`, `networks`, `pifs`, `pbds`, `srs`, `vifs`, `vbds`, `vdis`, `backup-jobs`, `schedules`,
`backup-repositories`, `proxies`, `servers`, `users`, `groups`, `acl-roles` and, when the credential
can reach it, `acl-privileges`.

Fields that move by themselves are ignored, so a backup run does not look like a change: power
state, start times, memory usage, storage usage, current operations, values the guest reports
(addresses, operating system, tools), the lists of snapshots and disks, and parent references. The
test `tests/contract/test_xo_volatility.py` runs a simulated backup run through the whole pipeline
and expects zero change items. NOT VERIFIED: that a real XO has no other field that moves by itself;
a field the type table does not name is stored as a fingerprint, so such a field would show as a
change until it is classified (`rules/types/xo.yaml` is the exact list; every XO field name in it is
NOT VERIFIED).

## Step 6: read the coverage panel

For every collection driftsniff keeps one coverage row. The statuses are:

| Status | Meaning | What to do |
|---|---|---|
| `200` | read; the object count and the time of the last good read are shown | nothing |
| `403` | the credential may not read this collection. It is marked stale and its objects are **not** reported as removed | give the user a role that can read it, or accept the gap (mode (b) expects this for four collections) |
| `404` | this XO does not offer the collection. Not a failure of the credential | nothing, or upgrade XO |
| `error` | timeout, server error, a line that is not valid JSON, a stream cut short, or a certificate refused. The previous state is kept and nothing is reported as removed | check the address, the TLS mode and XO |

An unreadable collection goes stale on its own; the other collections are read as usual. In the
coverage panel, a value that XO itself hides is labelled **hidden by XO, changes not observable**.

Status: the coverage rows are written by the run pipeline and stored in the table
`resource_coverage`. **The coverage panel itself is part of P10 and does not exist yet.**

## Expiry and renewal

A credential that lives forever is a standing risk, so driftsniff warns before it ends.

- When you save the source you may enter the **expiry date** of the credential. An entered date means
  the end of that day, UTC.
- After a good probe driftsniff tries **once** to read the expiry of the credential in use from XO
  (`/users/me/authentication_tokens`). If that works, the date XO reports wins over the entered
  one. A `403`, a `404` or any other failure of that one read is tolerated and the entered date is
  used. NOT VERIFIED: that this endpoint exists and what it returns.
- A date that is in the past, or within **14 days**, sets the source state `token_expiring`. The
  collector factory is to set it and the interface to show it (both not built yet: no warning is
  raised today).
- **To renew:** create a new credential for the same user, replace it in the source (enter the new
  expiry date), check that a run succeeds, then delete the old credential in XO. Do not delete the
  old one first: the next poll would fail.
- If the credential leaked: delete it in XO first, then create a new one and replace it in the
  source.

## What XO hides, and what driftsniff does about it

NOT VERIFIED (test X3 is open): XO is expected to hide the **server credentials** (the password or
token XO uses to reach a host), the **user and password part of a backup remote's address** and the
**plugin secrets**. driftsniff relies on this only for display. It does not trust it for safety:

- Values XO hides are marked in the type table, and the interface says **hidden by XO, changes not
  observable**. A change of a hidden value cannot be reported; do not read "no change" as "the
  secret is unchanged".
- The user and password part of a backup repository address is removed before anything is stored,
  and the rest of the address is scanned like every other value.
- Every value is scanned for things that look like credentials (tokens, keys, addresses that carry
  a user and password). What matches is stored as a **fingerprint** (a keyed hash that shows that the value changed) and
  never as the value. The sign-in methods of a user and the device configuration of a storage
  connection are secret class and handled the same way.
- Free text (VM notes and descriptions, `PV_args`, `otherConfig` maps) is scanned, but a plain word
  that is a password cannot be recognised as one. **Do not keep passwords in notes, descriptions or
  other free text fields in XO.** Stored configuration is sensitive even when redacted.

## What is not collected

- **Excluded collections, never requested:** `tasks`, `alarms`, `messages`, `backup-logs`,
  `restore-logs`, `backup-archives`, `events`, `vm-snapshots`, `vdi-snapshots`, `licenses`, `sms`,
  `pcis`, `pgpus`, `vm-controller` and `xoa`. They are volatile, large or not configuration, and the
  client cannot request a collection that has no type table.
- **Not in CE v1** (NOT VERIFIED that they have no REST collection): plugin configuration, legacy
  ACLs, resource sets, cloud-config templates, custom fields, IP pools and the audit log. They are
  reachable only through JSON-RPC.
- Templates that are built in are dropped; only your own templates are watched. NOT VERIFIED: the
  field that marks a built in template.
- Sizes, usage and statistics of VMs, disks and storage are not configuration and are ignored.

## What is not built yet

| Part | Status |
|---|---|
| Web form to add and edit a source, the field for the expiry date, CA file upload, coverage panel | P10, not built |
| Collector factory: builds the client from a stored source (decrypts the credential, reads the TLS options and the entered expiry) and saves the state `token_expiring` | not built; `serve` starts no scheduler until it exists |
| Storage of the entered expiry date: the source options have no such option yet | not built |
| First admin and login (`create-admin-code` prints "not implemented yet") | P9-T1, not built |
| Vendor reference and lab results (X1 to X4) | open; no XO was used |

## Trying the steps without XO

The tests use a fake XO on localhost (`tests/contract/fake_xo.py`) with one hand written pool
(`tests/fixtures/xo/pool.json`, all 20 collections, placeholder values only). They show the client
flow of steps 5 and 6, expiry and the read-only coverage: `tests/contract/test_xo_client.py`,
`test_xo_volatility.py` and `tests/security/test_xo_canaries.py`; `docs/xo-client.md` and
`docs/xo-volatility.md` describe them. Because the web form and the factory are not built, a person
cannot yet complete steps 4 to 6 in a browser against the fake server; the walk-through by someone
who did not write the code (acceptance check 1 of P8-T5) is pending the Test Engineer's review and is
**not claimed here**.

## If something goes wrong

- Nothing appears for a collection: read its status in step 6.
- Everything shows `403` or the source is refused: the credential expired or was deleted. Renew it.
- `token_expiring` is shown: see "Expiry and renewal".
- A certificate was renewed on a pinned source: update the pin.
- A credential must never be pasted into a ticket, a comment or a chat.
