"""A fake UniFi Protect integration API on localhost for the contract tests, and a simulation model.

It serves the read endpoints the collector uses, with the shapes of Ubiquiti's OpenAPI document of
the Protect integration API (developer.ui.com, Protect 7.2.105, read 2026-11-12; docs/vendor-notes/
unifi_protect.md). The data is synthetic: one NVR, three cameras (one a doorbell), a viewer, two
live views, a chime, a floodlight and two sensors. Names use ``example.invalid``; no address is
served, the API has none.

Surface (GET only, every other method answers 405), below ``/proxy/protect/integration/v1``:

* ``/meta/info`` ``{"applicationVersion"}``;
* ``/nvrs`` one NVR object;
* ``/cameras``, ``/viewers``, ``/liveviews``, ``/chimes``, ``/lights``, ``/sensors`` JSON arrays,
  no paging.

The key travels in ``X-API-KEY``; a missing or unknown one answers 401. Errors use the document's
``genericError`` shape ``{"error", "name"}``. :class:`Scenario` has helpers that change the
configuration so that two reads show a drift (:meth:`Scenario.drift` applies the standard set:
one low, one medium, two high and one critical change) and :meth:`Scenario.tick`, which moves only
volatile values.
"""

import copy
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import urlsplit

API_KEY = "CANARY-upk-0"
BASE = "/proxy/protect/integration/v1"
VERSION = "7.2.105"
LISTS = ("cameras", "viewers", "liveviews", "chimes", "lights", "sensors")


@dataclass(frozen=True, slots=True)
class Request:
    """One request the server received."""

    method: str
    path: str
    query: str
    api_key: str | None
    authorization: str | None
    cookie: str | None


def _camera(
    number: int, name: str, kind: str, objects: list[str], audio: list[str]
) -> dict[str, Any]:
    return {
        "id": f"camera-{number:04d}",
        "modelKey": "camera",
        "state": "CONNECTED",
        "name": name,
        "type": kind,
        "guid": f"00000000-0000-4000-8000-00000000010{number}",
        "mac": f"0A000000010{number}",
        "isMicEnabled": False,
        "osdSettings": {
            "isNameEnabled": True,
            "isDateEnabled": True,
            "isLogoEnabled": False,
            "isDebugEnabled": False,
            "overlayLocation": "topLeft",
        },
        "ledSettings": {"isEnabled": True, "welcomeLed": False, "floodLed": False},
        "lcdMessage": {},
        "micVolume": 50,
        "activePatrolSlot": None,
        "videoMode": "default",
        "hdrType": "auto",
        "featureFlags": {
            "supportFullHdSnapshot": True,
            "hasHdr": True,
            "smartDetectTypes": ["person", "vehicle", "package", "animal"],
            "smartDetectAudioTypes": ["alrmSmoke", "alrmCmonx", "alrmGlassBreak"],
            "videoModes": ["default", "highFps"],
            "hasMic": True,
            "hasLedStatus": True,
            "hasSpeaker": kind == "G4 Doorbell Pro",
        },
        "smartDetectSettings": {"objectTypes": objects, "audioTypes": audio},
        "hasPackageCamera": kind == "G4 Doorbell Pro",
    }


def _sensor_settings(enabled: bool) -> dict[str, Any]:
    return {"isEnabled": enabled, "margin": 1, "lowThreshold": None, "highThreshold": None}


def _sensor(number: int, name: str, mount: str, *, alarm: bool, leak: bool) -> dict[str, Any]:
    return {
        "id": f"sensor-{number:04d}",
        "modelKey": "sensor",
        "state": "CONNECTED",
        "name": name,
        "type": "UP-Sense",
        "guid": f"00000000-0000-4000-8000-00000000030{number}",
        "mac": f"0A000000030{number}",
        "mountType": mount,
        "batteryStatus": {"percentage": 90, "isLow": False},
        "featureFlags": {"temperature": {"channelCount": 1}, "motion": {"channelCount": 1}},
        "stats": {
            "light": {"value": 120, "status": "neutral"},
            "humidity": {"value": 45, "status": "neutral"},
            "temperature": {"value": 21.5, "status": "neutral"},
        },
        "lightSettings": _sensor_settings(False),
        "humiditySettings": _sensor_settings(False),
        "temperatureSettings": {**_sensor_settings(True), "lowThreshold": 5, "highThreshold": 35},
        "isOpened": False if mount in ("door", "window") else None,
        "openStatusChangedAt": None,
        "isMotionDetected": False,
        "motionDetectedAt": None,
        "motionSettings": {"isEnabled": True, "sensitivity": 70, "sensitivityWhenArmed": 80},
        "glassBreakSettings": {"isEnabled": False, "sensitivity": 50, "sensitivityWhenArmed": 50},
        "scheduleMode": "always",
        "armProfileIds": ["arm-profile-0001"],
        "hasCustomSensitivityWhenArmed": False,
        "alarmTriggeredAt": None,
        "alarmSettings": {"isEnabled": alarm},
        "leakDetectedAt": None,
        "externalLeakDetectedAt": None,
        "leakSettings": {"isInternalEnabled": leak, "isExternalEnabled": False},
        "tamperingDetectedAt": None,
        "wirelessConnectionState": {
            "signalState": {"signalQuality": 90, "signalStrength": -55},
            "batteryStatus": {"percentage": 90, "isLow": False},
            "bridge": None,
        },
    }


def default_state() -> dict[str, Any]:
    """The configuration of a small synthetic UniFi Protect installation."""
    return {
        "nvr": {
            "id": "nvr-0001",
            "modelKey": "nvr",
            "name": "protect.example.invalid",
            "type": "UNVR",
            "guid": "00000000-0000-4000-8000-000000000001",
            "mac": "0A0000000001",
            "doorbellSettings": {
                "defaultMessageText": "Welcome",
                "defaultMessageResetTimeoutMs": 60000,
                "customMessages": ["Back in five minutes"],
                "customImages": [],
            },
            "armMode": {
                "status": "disabled",
                "armProfileId": None,
                "armedAt": None,
                "willBeArmedAt": None,
                "breachDetectedAt": None,
                "breachEventCount": 0,
                "breachTriggerEventId": None,
                "breachEventId": None,
            },
        },
        "cameras": [
            _camera(1, "Front door", "G4 Doorbell Pro", ["person", "package"], ["alrmSmoke"]),
            _camera(2, "Driveway", "G5 Bullet", ["person", "vehicle"], []),
            _camera(3, "Garden", "G5 Flex", ["person", "animal"], ["alrmGlassBreak"]),
        ],
        "viewers": [
            {
                "id": "viewer-0001",
                "modelKey": "viewer",
                "state": "CONNECTED",
                "name": "Hall screen",
                "type": "UP Viewport",
                "guid": None,
                "mac": "0A0000000201",
                "liveview": "liveview-0001",
                "streamLimit": 16,
            }
        ],
        "liveviews": [
            {
                "id": "liveview-0001",
                "modelKey": "liveview",
                "name": "All cameras",
                "isDefault": True,
                "isGlobal": True,
                "owner": "user-0001",
                "layout": 4,
                "slots": [
                    {"cameras": ["camera-0001"], "cycleMode": "time", "cycleInterval": 10},
                    {"cameras": ["camera-0002"], "cycleMode": "time", "cycleInterval": 10},
                    {"cameras": ["camera-0003"], "cycleMode": "time", "cycleInterval": 10},
                    {"cameras": [], "cycleMode": "time", "cycleInterval": 10},
                ],
            },
            {
                "id": "liveview-0002",
                "modelKey": "liveview",
                "name": "Outside",
                "isDefault": False,
                "isGlobal": False,
                "owner": "user-0002",
                "layout": 1,
                "slots": [
                    {
                        "cameras": ["camera-0002", "camera-0003"],
                        "cycleMode": "motion",
                        "cycleInterval": 5,
                    }
                ],
            },
        ],
        "chimes": [
            {
                "id": "chime-0001",
                "modelKey": "chime",
                "state": "CONNECTED",
                "name": "Kitchen chime",
                "type": "UP Chime",
                "guid": None,
                "mac": "0A0000000401",
                "cameraIds": ["camera-0001"],
                "ringSettings": [
                    {
                        "cameraId": "camera-0001",
                        "repeatTimes": 2,
                        "ringtoneId": "ringtone-default",
                        "volume": 80,
                    }
                ],
            }
        ],
        "lights": [
            {
                "id": "light-0001",
                "modelKey": "light",
                "state": "CONNECTED",
                "name": "Driveway floodlight",
                "type": "UP FloodLight",
                "guid": None,
                "mac": "0A0000000501",
                "lightModeSettings": {"mode": "motion", "enableAt": "dark"},
                "lightDeviceSettings": {
                    "isIndicatorEnabled": True,
                    "pirDuration": 15000,
                    "pirSensitivity": 60,
                    "ledLevel": 4,
                },
                "isDark": False,
                "isLightOn": False,
                "isLightForceEnabled": False,
                "lastMotion": None,
                "isPirMotionDetected": False,
                "camera": "camera-0002",
            }
        ],
        "sensors": [
            _sensor(1, "Back door", "door", alarm=True, leak=False),
            _sensor(2, "Utility room", "leak", alarm=True, leak=True),
        ],
    }


@dataclass
class Scenario:
    """What the fake serves and how it fails.

    Faults are keyed by the route name: ``info``, ``nvrs`` or a list name such as ``cameras``.
    ``status`` forces an HTTP error, ``raw`` replaces the body of a good answer.
    """

    state: dict[str, Any] = field(default_factory=default_state)
    keys: frozenset[str] = frozenset({API_KEY})
    status: dict[str, int] = field(default_factory=dict)
    raw: dict[str, bytes] = field(default_factory=dict)
    # Serve every list in reverse order (the order must never matter).
    reverse: bool = False
    # Put the received key into the body of error answers (a leaking server).
    echo_key: bool = False

    # -- drift helpers ----------------------------------------------------------------------

    def _find(self, name: str, key: str) -> dict[str, Any]:
        for item in self.state[name]:
            if item["id"] == key:
                return cast("dict[str, Any]", item)
        raise KeyError(f"{name} {key}")

    def rename_camera(self, camera_id: str, name: str) -> None:
        self._find("cameras", camera_id)["name"] = name

    def set_microphone(self, camera_id: str, enabled: bool) -> None:
        self._find("cameras", camera_id)["isMicEnabled"] = enabled

    def drop_smart_detection(self, camera_id: str, object_type: str) -> None:
        settings = self._find("cameras", camera_id)["smartDetectSettings"]
        settings["objectTypes"] = [t for t in settings["objectTypes"] if t != object_type]

    def remove_camera(self, camera_id: str) -> None:
        self.state["cameras"] = [c for c in self.state["cameras"] if c["id"] != camera_id]

    def set_smoke_alarm_detection(self, sensor_id: str, enabled: bool) -> None:
        self._find("sensors", sensor_id)["alarmSettings"]["isEnabled"] = enabled

    def tick(self) -> None:
        """Move only volatile values: states, detections, readings, battery, arm state."""
        nvr = self.state["nvr"]
        nvr["armMode"]["status"] = "armed" if nvr["armMode"]["status"] == "disabled" else "disabled"
        nvr["armMode"]["breachEventCount"] += 1
        for camera in self.state["cameras"]:
            camera["state"] = "CONNECTING" if camera["state"] == "CONNECTED" else "CONNECTED"
            camera["lcdMessage"] = {"type": "DO_NOT_DISTURB", "resetAt": None, "text": ""}
            camera["activePatrolSlot"] = 1
        for viewer in self.state["viewers"]:
            viewer["state"] = "DISCONNECTED"
        for light in self.state["lights"]:
            light["isDark"] = not light["isDark"]
            light["isLightOn"] = not light["isLightOn"]
            light["lastMotion"] = (light["lastMotion"] or 1762900000000) + 60000
            light["isPirMotionDetected"] = not light["isPirMotionDetected"]
        for sensor in self.state["sensors"]:
            sensor["stats"]["temperature"]["value"] += 0.5
            sensor["batteryStatus"]["percentage"] -= 1
            sensor["wirelessConnectionState"]["signalState"]["signalStrength"] -= 1
            sensor["isMotionDetected"] = not sensor["isMotionDetected"]
            sensor["motionDetectedAt"] = 1762900000000
            sensor["tamperingDetectedAt"] = 1762900000000

    def drift(self) -> None:
        """The standard drift: volatile moves plus one change of each severity."""
        self.tick()
        self.rename_camera("camera-0001", "Front porch")  # low
        self.set_microphone("camera-0002", True)  # medium
        self.drop_smart_detection("camera-0001", "package")  # high
        self.remove_camera("camera-0003")  # high (object floor)
        self.set_smoke_alarm_detection("sensor-0002", False)  # critical


# -- serving -----------------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"))

    def _error(self, status: int, message: str) -> None:
        scenario = cast("_Server", self.server).scenario
        name = self.headers.get("X-API-KEY", "") if scenario.echo_key else "Error"
        self._json(status, {"error": message, "name": name})

    def _record(self, method: str) -> str:
        server = cast("_Server", self.server)
        parts = urlsplit(self.path)
        server.requests.append(
            Request(
                method,
                parts.path,
                parts.query,
                self.headers.get("X-API-KEY"),
                self.headers.get("Authorization"),
                self.headers.get("Cookie"),
            )
        )
        return parts.path

    def _refuse(self) -> None:
        self._record(self.command)
        self._error(405, "Method Not Allowed")

    do_POST = do_PUT = do_PATCH = do_DELETE = _refuse

    def do_GET(self) -> None:
        scenario = cast("_Server", self.server).scenario
        path = self._record("GET")
        if (self.headers.get("X-API-KEY") or "") not in scenario.keys:
            self._error(401, "Unauthorized")
            return
        if not path.startswith(BASE + "/"):
            self._error(404, "Not Found")
            return
        route = path.removeprefix(BASE + "/")
        key = "info" if route == "meta/info" else route
        if key not in ("info", "nvrs", *LISTS):
            self._error(404, "Not Found")
            return
        forced = scenario.status.get(key)
        if forced is not None:
            self._error(forced, "Simulated failure")
            return
        if key in scenario.raw:
            self._send(200, scenario.raw[key])
            return
        if key == "info":
            self._json(200, {"applicationVersion": VERSION})
        elif key == "nvrs":
            self._json(200, scenario.state["nvr"])
        else:
            items = copy.deepcopy(scenario.state[key])
            if scenario.reverse:
                items.reverse()
            self._json(200, items)


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.requests: list[Request] = []

    def handle_error(self, request: Any, client_address: Any) -> None:
        return None


class FakeProtect:
    """A running fake UniFi Protect."""

    def __init__(self, server: _Server) -> None:
        self._server = server

    @property
    def url(self) -> str:
        """The base address, plain http on a free local port."""
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    @property
    def scenario(self) -> Scenario:
        """The scenario being served; a test may change it between calls."""
        return self._server.scenario

    @property
    def requests(self) -> list[Request]:
        """Every request received, in order."""
        return self._server.requests


@contextmanager
def fake_protect(scenario: Scenario | None = None) -> Iterator[FakeProtect]:
    """Serve ``scenario`` (the default installation when None) until the block ends."""
    server = _Server(scenario or Scenario())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakeProtect(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
