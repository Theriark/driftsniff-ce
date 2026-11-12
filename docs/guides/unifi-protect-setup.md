# Setting up a UniFi Protect source

This guide connects driftsniff to UniFi Protect on a UniFi OS console so that it records changes to
the NVR, cameras, viewers, live views, chimes, floodlights and sensors.

## Read this first

- **No lab console has been used.** The API paths and fields come from Ubiquiti's published OpenAPI
  document of the Protect integration API, read on 2026-11-12
  (`docs/vendor-notes/unifi_protect.md`). The collector is tested against a fake Protect on
  localhost (`tests/contract/fake_unifi_protect.py`), not a real console.
- driftsniff **only reads**: it sends `GET` requests and nothing else. An integration API key can
  also change settings through the same API, so treat it like an administrator credential.
- The integration API does **not** expose recording settings, motion zones or privacy zones. A
  camera that stops recording or gains a privacy mask is not seen by this source. The removal of a
  camera is seen (high).

## What driftsniff reads

Every path is below `/proxy/protect/integration/v1` on the console.

| Resource | Path | What changes are rated |
|---|---|---|
| `protect-nvr` | `/nvrs` | name, model, doorbell messages |
| `protect-cameras` | `/cameras` | smart detection (an object or sound type removed: high), microphone (switched on: medium), LED, on-screen text, video and HDR mode, name (low), a removed camera (high) |
| `protect-viewers` | `/viewers` | name and the live view shown (low) |
| `protect-liveviews` | `/liveviews` | shared with all users (medium), owner (medium), layout and cameras (low) |
| `protect-chimes` | `/chimes` | doorbells and ring settings (low) |
| `protect-lights` | `/lights` | light mode switched off (medium), device settings (low) |
| `protect-sensors` | `/sensors` | smoke and CO alarm detection switched off (critical), leak, motion or glass break detection switched off (high), arm profiles (medium), thresholds (low), a removed sensor (high) |

States, detections, readings, battery and signal values are not compared, so they never show as a
change. A resource the console does not have (an older Protect) shows coverage `404` and keeps its
previous state; nothing is reported as removed.

## Steps

1. On the console, open **UniFi OS Settings**, then **Control Plane**, then **Integrations**, and
   create an API key (UNVERIFIED menu path; the wording differs between console versions). Copy the
   key: it is shown once.
2. In driftsniff, select **Add source**, choose **UniFi Protect**, and enter a name, the `https://`
   address of the console (for example `https://protect.example.invalid`, with no path), the API
   key, the interval, the resources and the TLS mode. A console usually has a self-signed
   certificate: use the pinned mode rather than turning checks off.
3. Select **Test connection**. It reads the Protect version and each resource once and stores
   nothing.
