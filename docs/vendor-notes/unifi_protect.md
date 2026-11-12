# UniFi Protect vendor notes

driftsniff's own notes on the UniFi Protect integration API that the Protect collector reads
(`src/driftsniff/collectors/unifi_protect/`, type table `src/driftsniff/rules/types/unifi_protect.yaml`).
Nothing here is copied from the vendor; every statement is in our own words, with its source and
the date it was read.

## Status in one paragraph

The statements below were read from Ubiquiti's published OpenAPI document of the UniFi Protect
integration API on **2026-11-12**. **No lab console was used**: nothing here is checked against a
running console, and the contract tests run against `tests/contract/fake_unifi_protect.py`, which
follows these notes. The document declares no security scheme, so the API key header is taken from
the UniFi Network integration API (the same consoles, the same key type) and from a third party
Protect client; it is marked **UNVERIFIED**. The integration API is much smaller than the private
API the Protect web app uses: recording settings, motion zones and privacy zones are not in it, so
driftsniff cannot report them.

## Sources

| Id | Source | Read on |
|---|---|---|
| S1 | https://developer.ui.com/protect/v7.2.105/openapi.json (Ubiquiti's OpenAPI document, title "UniFi Protect API") | 2026-11-12 |
| S2 | https://uiprotect.readthedocs.io/ (third party Python client; shows `X-API-KEY` against `/proxy/protect/integration/v1/cameras`) | 2026-11-12 |
| S3 | `src/driftsniff/collectors/unifi/client.py` and `docs/vendor-notes/unifi.md` (the UniFi Network integration API key header) | 2026-11-12 |

## Statements

| # | Statement | Source | Status |
|---|---|---|---|
| 1 | The local server of the API is `https://{console}/proxy/protect/integration`; paths start with `/v1`. A cloud connector path through `api.ui.com` also exists and is not used. | S1 | vendor doc |
| 2 | The key is sent in the header `X-API-KEY`. S1 declares no security scheme. | S2, S3 | **UNVERIFIED** |
| 3 | `GET /v1/meta/info` answers an object with the required `applicationVersion` (the Protect version). | S1 | vendor doc |
| 4 | `GET /v1/nvrs` answers **one** NVR object: `id`, `modelKey` (`nvr`), `name`, `type`, `guid`, `mac`, `doorbellSettings` (`defaultMessageText`, `defaultMessageResetTimeoutMs`, `customMessages`, `customImages` with `preview` and `sprite`), `armMode` (`status`, `armProfileId`, `armedAt`, `willBeArmedAt`, `breachDetectedAt`, `breachEventCount`, `breachTriggerEventId`, `breachEventId`). | S1 | vendor doc |
| 5 | `GET /v1/cameras` answers an array of cameras: `id`, `modelKey`, `state` (CONNECTED, CONNECTING, DISCONNECTED), `name`, `type`, `guid`, `mac`, `isMicEnabled`, `osdSettings` (`isNameEnabled`, `isDateEnabled`, `isLogoEnabled`, `isDebugEnabled`, `overlayLocation`), `ledSettings` (`isEnabled`, `welcomeLed`, `floodLed`), `lcdMessage`, `micVolume` (0 to 100), `activePatrolSlot`, `videoMode`, `hdrType`, `featureFlags` (capabilities), `smartDetectSettings` (`objectTypes`: person, vehicle, package, licensePlate, face, animal; `audioTypes`: alrmSmoke, alrmCmonx, alrmSiren, alrmBabyCry, alrmSpeak, alrmBark, alrmBurglar, alrmCarHorn, alrmGlassBreak), `hasPackageCamera`. | S1 | vendor doc |
| 6 | The camera schema has **no** recording settings, motion zones, privacy zones, uptime, last motion, statistics or connection details. | S1 | vendor doc (absence) |
| 7 | `GET /v1/viewers`: `id`, `modelKey`, `state`, `name`, `type`, `guid`, `mac`, `liveview` (id or null), `streamLimit`. | S1 | vendor doc |
| 8 | `GET /v1/liveviews`: `id`, `modelKey`, `name`, `isDefault`, `isGlobal` (shared with all users), `owner` (user id), `layout` (1 to 26), `slots` (each `cameras`, `cycleMode` motion or time, `cycleInterval`). | S1 | vendor doc |
| 9 | `GET /v1/chimes`: `id`, `modelKey`, `state`, `name`, `type`, `guid`, `mac`, `cameraIds`, `ringSettings` (each `cameraId`, `repeatTimes`, `ringtoneId`, `volume`). | S1 | vendor doc |
| 10 | `GET /v1/lights`: `id`, `modelKey`, `state`, `name`, `type`, `guid`, `mac`, `lightModeSettings` (`mode` always, motion or off; `enableAt` fulltime or dark), `lightDeviceSettings` (`isIndicatorEnabled`, `pirDuration`, `pirSensitivity`, `ledLevel`), `isDark`, `isLightOn`, `isLightForceEnabled`, `lastMotion`, `isPirMotionDetected`, `camera`. | S1 | vendor doc |
| 11 | `GET /v1/sensors`: `id`, `modelKey`, `state`, `name`, `type`, `guid`, `mac`, `mountType` (door, window, garage, leak, none), `batteryStatus` (deprecated), `featureFlags`, `stats`, `lightSettings`, `humiditySettings`, `temperatureSettings` (each `isEnabled`, `margin`, `lowThreshold`, `highThreshold`), `isOpened`, `openStatusChangedAt`, `isMotionDetected`, `motionDetectedAt`, `motionSettings` and `glassBreakSettings` (each `isEnabled`, `sensitivity`, `sensitivityWhenArmed`), `scheduleMode` (always or when_armed), `armProfileIds`, `hasCustomSensitivityWhenArmed`, `alarmTriggeredAt`, `alarmSettings` (`isEnabled`; described as smoke and carbon monoxide alarm settings), `leakDetectedAt`, `externalLeakDetectedAt`, `leakSettings` (`isInternalEnabled`, `isExternalEnabled`), `tamperingDetectedAt`, `wirelessConnectionState`. | S1 | vendor doc |
| 12 | No list operation has paging parameters; errors use `genericError` (`error`, `name`, optional `cause`) and no specific status codes are documented. | S1 | vendor doc |
| 13 | The document also has sirens, speakers, bridges, relays, fobs, link stations, alarm hubs, arm profiles, users and identity users, plus write operations (PATCH, POST, DELETE) and event streams. | S1 | vendor doc |
| 14 | The document's `info.version` is `0.0.0`; the Protect version is only in the URL (7.2.105). Which Protect versions answer every path is not stated. | S1 | vendor doc |

## What the collector does with them

- Reads statements 3, 4, 5 and 7 to 11 with GET only. Statement 13's other device kinds and users
  are not read: their schemas were not reviewed for this collector (open item).
- Volatile values are ignore class: device `state`, the camera `lcdMessage` and `activePatrolSlot`,
  the NVR `armMode`, light status and last motion, every sensor reading, detection time, battery
  and signal value. Capabilities (`featureFlags`, `streamLimit`, `hasPackageCamera`) are ignore
  class too: they follow the hardware, not the configuration.
- No field is a credential, so none is classed secret. The API key is the only secret, and it
  travels in the header only.

## UNVERIFIED

- The header name `X-API-KEY` (statement 2).
- That every field the document marks required is really returned, and nothing else, by a real
  console; a field that is not in the type table is unclassified and shown as a fingerprint only.
- The status a console returns for a refused key (401 or 403 are both treated as a refusal) and
  for an endpoint an older Protect does not have (404 is treated as `not_available`).
- The minimum Protect version that has the integration API (a third party client names 7.2).
