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
    assert re.findall(r"import\(([^)]*)\)", code) == ["THREE_URL"]
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
    assert "const SCENES = { drift: DRIFT, replay: REPLAY };" in code
    templates = STATIC.parent / "templates"
    kinds = set()
    for page in templates.rglob("*.html"):
        kinds.update(re.findall(r'data-scene="([a-z]+)"', page.read_text(encoding="utf-8")))
    assert kinds == {"drift", "replay"}
    # the replay scene follows the cursor of the 2D map and stops watching when it is put away
    assert 'attributeFilter: ["x"]' in code and "watch.disconnect()" in code
