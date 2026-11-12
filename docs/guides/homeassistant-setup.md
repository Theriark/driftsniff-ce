# Setting up a Home Assistant source

This guide connects driftsniff to Home Assistant so it records changes to its general settings,
integrations, users, automations, scripts, areas, entity registry and dashboards. It is for the
person who runs Home Assistant and the driftsniff admin.

## Read this first

- **No lab Home Assistant has been used.** Commands and fields come from the developer
  documentation and the core source (`docs/vendor-notes/homeassistant.md`, read 2026-11-12).
  Statements about the Home Assistant side are labelled **NOT VERIFIED** where they were not
  checked in those sources.
- The client and the pipeline are tested against a fake Home Assistant on localhost
  (`tests/contract/fake_homeassistant.py`). That shows how driftsniff behaves for the names it
  expects, not that a real Home Assistant answers with them.

## What driftsniff does with Home Assistant

- **It only reads.** It sends list and config commands over the WebSocket API at `/api/websocket`,
  nothing that changes anything. A long-lived token has all the rights of its user, though, and
  Home Assistant has no read-only administrator.
- The token is sent once per check, inside the sign in message on the connection, never in an
  address, a header, a log line or an error. It is **encrypted at rest** and never shown again
  after you save it.
- **It never stores state values** such as sensor readings. Of the states it keeps only which
  automations and scripts exist and whether each automation is on.
- The home location and the triggers, conditions and actions of automations and scripts are
  stored only as keyed fingerprints: a change shows that they changed, not what they are. Names,
  descriptions and modes stay readable.

## Steps

1. **Create a user for driftsniff.** Settings > People > Users > Add user, for example
   `driftsniff`, with **Administrator** on. Without administrator rights the users, automations and
   scripts show 403 and the rest is still read. Turn on *Can only log in from the local network*
   if driftsniff runs on that network. NOT VERIFIED: the menu names on your version.
2. **Create a long-lived access token.** Sign in as that user, open the profile (bottom left) >
   Security > Long-lived access tokens > Create token, and copy it: Home Assistant shows it once.
3. **Add the source in driftsniff.** Sources > Add a source > Home Assistant.
   - Address: `https://home.example.invalid:8123` (no path).
   - Token: the long-lived access token.
   - Many installations serve plain `http://` on the local network. Then tick **Allow a plain http
     address**; the token travels unencrypted, so prefer https.
4. **TLS.** For a self-signed certificate, upload its CA as a CA bundle (mode *ca_file*) or pin its
   fingerprint (mode *pinned*). See `docs/tls.md`.
5. **Test the connection**, then save. The first check stores the current configuration; changes
   appear from the second check on.

Repeated wrong tokens can get the driftsniff address banned when the IP ban of Home Assistant's
`http` integration is on (NOT VERIFIED for the WebSocket sign in).

## What a check reads, and what is high or critical

Critical: a user added or removed, a user made administrator or owner. High: the external URL
changed, a user allowed to sign in from outside the local network, a turned-off account turned on,
a user's groups or sign-in methods changed, the folders integrations may read changed, Google
Assistant allowed to act without its PIN. Medium: an integration added, removed or turned off or
on, an automation or script added, removed or changed, an automation turned off, the internal URL
or the home location changed, an entity turned off by a person or exposed to Alexa or Google, a
dashboard shown to every user. Low: names, descriptions, areas, dashboards, time zone, units and
other general settings. The rule packs are `src/driftsniff/rules/packs/homeassistant/`.

A resource the token may not read shows **403** in the coverage panel and keeps its last state; a
command your version does not have shows **404**. Neither reports anything as removed.
