"""The 3D views: the vendored three.js and the rules their module keeps.

The module (static/scenes.js) runs in a browser, so the drawing itself is checked on a
running copy; these tests pin what can be read from the files: the library is the pinned
release, unmodified, and the module loads nothing from outside, runs no string as code, writes
no markup and no style attribute (the content security policy), and follows only local paths.
"""

import hashlib
import json
import re
from pathlib import Path

STATIC = Path(__file__).resolve().parents[2] / "src" / "driftsniff" / "web" / "static"
THREE = STATIC / "vendor" / "three"
# the add-ons the module loads, and the two the glTF loader imports in turn
LOADED = ("addons/RoundedBoxGeometry.js", "addons/RoomEnvironment.js", "addons/GLTFLoader.js")
ADDONS = (*LOADED, "addons/BufferGeometryUtils.js", "addons/SkeletonUtils.js")
MODELS = STATIC / "models"


def test_three_is_the_pinned_release_unmodified() -> None:
    pinned = json.loads((THREE / "PINNED.json").read_text(encoding="utf-8"))
    assert pinned["version"] == "0.186.1" and pinned["license"] == "MIT"
    for name, expected in pinned["files"].items():
        data = (THREE / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == expected["sha256"], name
        assert len(data) == expected["bytes"], name
    assert "Permission is hereby granted" in (THREE / "LICENSE").read_text(encoding="utf-8")


def test_the_module_imports_only_the_vendored_library_and_keeps_the_policy() -> None:
    code = (STATIC / "scenes.js").read_text(encoding="utf-8")
    assert re.findall(r"import\(([^)]*)\)", code) == ["THREE_URL", "ADDON_URLS[name]"]
    # the add-ons are the vendored ones, nothing else
    urls = re.findall(r'"(/static/vendor/three/addons/[A-Za-z]+\.js)"', code)
    assert sorted(urls) == sorted(f"/static/vendor/three/{name}" for name in LOADED)
    assert 'const THREE_URL = "/static/vendor/three/three.module.js";' in code
    assert "http" not in code
    for refused in (
        "eval(",
        "new Function",
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        ".style.",
        'setAttribute("style"',
    ):
        assert refused not in code, refused
    # a followed link must be a path of this site
    assert "window.location.assign(node.href)" in code
    assert "function localPath(value)" in code


def test_the_scene_waits_for_webgl2_and_hides_without_it() -> None:
    code = (STATIC / "scenes.js").read_text(encoding="utf-8")
    start = code.index("async function start(root)")
    assert code.index("supportsWebGL2()", start) < code.index("import(THREE_URL)", start)
    # a page with no block of a known kind does nothing
    assert 'document.querySelectorAll("[data-scene]").forEach(start);' in code
    assert 'root.classList.add("is-unavailable")' in code
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert "@media (scripting: enabled)" in css and ".scene.is-unavailable" in css


def test_every_scene_kind_on_a_page_has_its_builder() -> None:
    code = (STATIC / "scenes.js").read_text(encoding="utf-8")
    assert "const SCENES = { lab: LAB, replay: REPLAY };" in code
    templates = STATIC.parent / "templates"
    kinds = set()
    for page in templates.rglob("*.html"):
        kinds.update(re.findall(r'data-scene="([a-z]+)"', page.read_text(encoding="utf-8")))
    assert kinds == {"lab", "replay"}
    # the replay scene follows the cursor of the 2D map and stops watching when it is put away;
    # the cards of an earlier day leave the picking list when they leave the scene
    assert 'attributeFilter: ["x"]' in code and "watch.disconnect()" in code
    assert "kit.unpickable(card.group)" in code
    # both scenes draw the same devices
    assert code.count("workshop(kit)") == 3  # the definition and the two scenes


def test_the_addons_are_the_pinned_release_with_only_their_imports_made_relative() -> None:
    pinned = json.loads((THREE / "PINNED.json").read_text(encoding="utf-8"))
    assert sorted(pinned["addons"]) == sorted(ADDONS)
    for name in ADDONS:
        entry = pinned["addons"][name]
        data = (THREE / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"], name
        assert len(data) == entry["bytes"], name
        text = data.decode("utf-8")
        # every import is relative and stays inside the vendored folder
        imports = re.findall(r"^(?:\} from|import .* from) '([^']+)';", text, re.M)
        assert imports, name
        for spec in imports:
            assert spec == "../three.module.js" or spec.removeprefix("./") in {
                Path(other).name for other in ADDONS
            }, (name, spec)


def test_a_source_shows_its_status_on_the_device_and_no_ferret_or_sign() -> None:
    code = (STATIC / "scenes.js").read_text(encoding="utf-8")
    # Design review, November 2026: no floating severity signs, then no ferret at all
    assert "ExtrudeGeometry" not in code and "TorusGeometry" not in code
    assert "const STATUS_LIGHT = {" in code and "function light(device, source)" in code
    assert "ferret" not in code.lower()


def test_the_devices_are_the_credited_models_and_load_only_their_own_files() -> None:
    code = (STATIC / "scenes.js").read_text(encoding="utf-8")
    kinds = re.search(r"const MODEL_OF = \{([^}]*)\}", code)
    assert kinds is not None
    names = set(re.findall(r'"([a-z]+)"', kinds.group(1)))
    assert names == {path.name for path in MODELS.iterdir() if path.is_dir()}
    credits = (MODELS / "CREDITS.txt").read_text(encoding="utf-8")
    assert "CC BY 4.0" in credits
    for name in names:
        folder = MODELS / name
        assert f"{name}/ " in credits, name
        gltf = json.loads((folder / f"{name}.gltf").read_text(encoding="utf-8"))
        # plain glTF: every buffer and image a file beside it (no data: URI, no other site, no
        # extension the page cannot load under its policy)
        uris = [item["uri"] for item in gltf.get("buffers", []) + gltf.get("images", [])]
        assert uris, name
        for uri in uris:
            assert "/" not in uri and ":" not in uri and (folder / uri).is_file(), (name, uri)
        assert set(gltf.get("extensionsRequired", [])) <= {"EXT_texture_webp"}, name
        assert {path.name for path in folder.iterdir()} == {f"{name}.gltf", *uris}, name
    # the monitoring screen draws the product's own picture on the model's Screen surface
    screen = json.loads((MODELS / "screen" / "screen.gltf").read_text(encoding="utf-8"))
    assert "Screen" in [node.get("name") for node in screen["nodes"]]
    assert 'part.name === "Screen"' in code
    # a model is fetched with the build's version, like the page's own scripts
    assert "const VERSION = new URL(import.meta.url).search;" in code
    assert "/static/models/${name}/${name}.gltf${VERSION}" in code
