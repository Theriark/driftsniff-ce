/*
 * The 3D views of the interface (docs/design-direction.md, "The 3D views"). One ES module for
 * every scene; a page carries a block with data-scene="<kind>" and loads this file:
 * - drift: the dashboard's drift lines drawn as a field, one lane per source over 30 days;
 * - replay: the change replay of a source page, a bar per day and resource type, with a pane on
 *   the day the replay controls have chosen.
 *
 * Same origin, no eval, nothing from outside: three.js r186 is vendored in
 * /static/vendor/three (hashes in PINNED.json) and is imported only after the browser has shown
 * it offers WebGL 2, so a browser without it never downloads the library. A scene reads its
 * facts from the page (the data attributes the server drew on the 2D view beside it), so the
 * scene and the page cannot disagree and no request is made. Every word is in the page: nothing
 * is written inside a scene, the canvas is aria-hidden, and the 2D view stays the record and
 * the keyboard path.
 *
 * Without script the block stays hidden; with script the stylesheet keeps its room, and without
 * WebGL 2 (or with nothing to draw) the block goes. Frames are drawn only when something changed,
 * never while the page is hidden or the stage is out of view; nothing moves by itself, and under
 * reduced motion every turn is immediate. Leaving the page disposes every geometry, material and
 * the renderer. The hide button keeps its choice in this browser only (localStorage
 * "ds-scenes", one choice for every scene). Each block offers block.scene with info(), draw(),
 * show() and hide() for a test.
 */

const THREE_URL = "/static/vendor/three/three.module.js";
const HIDE_KEY = "ds-scenes";
const TURN_STEP = Math.PI / 8;
const TWEEN_MS = 300;
const RANK = ["low", "medium", "high", "critical"];
// the severity shapes of the interface as prism cross-sections: circle, triangle, diamond, octagon
const SEGMENTS = { low: 24, medium: 3, high: 4, critical: 8 };

const WORDS = {
  noModule: "The 3D view could not be loaded. Reload the page; the view below shows the same facts.",
  noWebGL: "This browser could not start the 3D view. The view below shows the same facts.",
  lost: "The browser paused the 3D view (the graphics context was lost). It resumes by itself.",
  closed: "The 3D view is off. The view below shows the same facts.",
};

function supportsWebGL2() {
  try {
    const context = document.createElement("canvas").getContext("webgl2");
    if (!context) {
      return false;
    }
    const lose = context.getExtension("WEBGL_lose_context");
    if (lose) {
      lose.loseContext();
    }
    return true;
  } catch (error) {
    return false;
  }
}

function hiddenByChoice() {
  try {
    return window.localStorage.getItem(HIDE_KEY) === "off";
  } catch (error) {
    return false;
  }
}

function rememberChoice(off) {
  try {
    if (off) {
      window.localStorage.setItem(HIDE_KEY, "off");
    } else {
      window.localStorage.removeItem(HIDE_KEY);
    }
  } catch (error) {
    // a browser that refuses storage keeps the choice for this page only
  }
}

// Only a path of this site is followed: the attributes come from the server, this is a guard.
function localPath(value) {
  return typeof value === "string" && /^\/(?![/\\])[\x21-\x7e]*$/.test(value) ? value : "";
}

function token(name, fallback) {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return /^#[0-9a-f]{6}$/i.test(value) ? parseInt(value.slice(1), 16) : fallback;
}

// The colours of a scene are the tokens of the stylesheet, so it follows the theme.
function colours() {
  return {
    backdrop: token("--surface", 0xffffff),
    ground: token("--paper", 0xf5f5f0),
    lane: token("--surface-2", 0xebebe3),
    tick: token("--slate", 0x6b7280),
    ink: token("--ink", 0x1e1e24),
    none: token("--border", 0xd3d3cb),
    low: token("--sev-low", 0x4a6283),
    medium: token("--sev-medium", 0x8a5f00),
    high: token("--sev-high", 0xa8441b),
    critical: token("--sev-critical", 0xc8342b),
  };
}

// Height grows with the log of a count, so one change and a thousand both read.
function height(count) {
  return 0.35 + 0.55 * Math.log2(1 + Math.max(0, count));
}

// --- the stage: renderer, camera, turning, picking, drawing on demand ----------------------

// `spec.build(kit)` adds the meshes of a scene to kit.scene and returns
// { extent: {wide, deep, tall, x}, home: {yaw, pitch}, hint, info?, sync? }. A pickable mesh is
// registered with kit.pickable(mesh, {label, href, element}); `element` is the node of the 2D
// view it stands for, so pointing at that node lights the mesh.
function buildStage(THREE, root, spec, data, options) {
  const stage = root.querySelector(".scene__stage");
  const canvas = document.createElement("canvas");
  canvas.className = "scene__canvas";
  canvas.setAttribute("aria-hidden", "true");
  stage.appendChild(canvas);
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(32, 2, 0.1, 400);
  const sky = new THREE.HemisphereLight(0xffffff, 0x888888, 1.6);
  const sun = new THREE.DirectionalLight(0xffffff, 1.4);
  sun.position.set(-6, 14, 8);
  scene.add(sky, sun);

  let palette = colours();
  renderer.setClearColor(palette.backdrop, 1);
  const geometries = new Map();
  const materials = new Map();
  const picks = [];

  function geometry(key, make) {
    if (!geometries.has(key)) {
      geometries.set(key, make());
    }
    return geometries.get(key);
  }

  // A material per palette name; "pale-<name>" is the same colour at 32 % opacity.
  function material(name) {
    if (!materials.has(name)) {
      const pale = name.startsWith("pale-");
      const colour = palette[pale ? name.slice(5) : name];
      materials.set(name, new THREE.MeshLambertMaterial(pale ? { color: colour, transparent: true, opacity: 0.32 } : { color: colour }));
    }
    return materials.get(name);
  }

  function prism(severity, size, tall) {
    const segments = SEGMENTS[severity] || 24;
    // a diamond stands on a corner, the others on a flat side facing the viewer
    const turn = severity === "high" ? 0 : severity === "medium" ? Math.PI / 6 : Math.PI / segments;
    const shape = geometry(`prism-${segments}-${size}`, () =>
      new THREE.CylinderGeometry(size, size, 1, segments).rotateY(turn).translate(0, 0.5, 0)
    );
    const mesh = new THREE.Mesh(shape);
    mesh.scale.y = tall;
    return mesh;
  }

  function box(key, x, y, z) {
    return new THREE.Mesh(geometry(key, () => new THREE.BoxGeometry(x, y, z).translate(0, y / 2, 0)));
  }

  function pickable(mesh, node) {
    node.mesh = mesh;
    mesh.userData.node = node;
    picks.push(mesh);
  }

  // the drawing state comes first: a scene may ask for a frame while it is built
  let tween = null;
  let rafId = 0;
  let inView = true;
  let lost = false;
  let hovered = null;
  const kit = { THREE, scene, material, prism, box, pickable, data, invalidate: () => invalidate() };
  const built = spec.build(kit);
  const { extent } = built;
  const floor = new THREE.Mesh(new THREE.PlaneGeometry(extent.wide + 2, extent.deep + 1.2), material("ground"));
  floor.rotation.x = -Math.PI / 2;
  floor.position.set(extent.x, 0, 0);
  scene.add(floor);
  const center = new THREE.Vector3(extent.x, extent.tall / 3, 0);

  const view = { yaw: built.home.yaw, pitch: built.home.pitch };

  // The distance that fits the whole field for the current turn and size.
  function place() {
    const across = Math.abs(extent.wide * Math.cos(view.yaw)) + Math.abs(extent.deep * Math.sin(view.yaw));
    const along = Math.abs(extent.wide * Math.sin(view.yaw)) + Math.abs(extent.deep * Math.cos(view.yaw));
    const tall = along * Math.sin(view.pitch) + extent.tall * Math.cos(view.pitch);
    const half = Math.tan((camera.fov * Math.PI) / 360);
    const distance = 1.08 * Math.max(across / 2 / (half * camera.aspect), tall / 2 / half) + along / 2;
    camera.position.set(
      center.x + distance * Math.cos(view.pitch) * Math.sin(view.yaw),
      center.y + distance * Math.sin(view.pitch),
      distance * Math.cos(view.pitch) * Math.cos(view.yaw)
    );
    camera.lookAt(center);
  }

  function draw() {
    place();
    renderer.render(scene, camera);
  }

  function frame(now) {
    rafId = 0;
    if (tween) {
      const t = Math.min(1, (now - tween.start) / TWEEN_MS);
      view.yaw = tween.from + (tween.to - tween.from) * (1 - (1 - t) * (1 - t));
      if (t < 1) {
        invalidate();
      } else {
        tween = null;
      }
    }
    draw();
  }

  function invalidate() {
    if (!rafId && inView && !document.hidden && !lost) {
      rafId = window.requestAnimationFrame(frame);
    }
  }

  function turnTo(yaw) {
    if (options.reducedMotion()) {
      view.yaw = yaw;
      tween = null;
    } else {
      tween = { from: view.yaw, to: yaw, start: performance.now() };
    }
    invalidate();
  }

  function resize() {
    const width = stage.clientWidth;
    const tall = stage.clientHeight;
    if (!width || !tall) {
      return;
    }
    renderer.setSize(width, tall, false);
    camera.aspect = width / tall;
    camera.updateProjectionMatrix();
    invalidate();
  }

  function highlight(node) {
    if (hovered === node) {
      return;
    }
    // a node may stand on several meshes (the stacked segments of a bar)
    (hovered ? hovered.parts || [hovered.mesh] : []).forEach((mesh) => {
      mesh.scale.x = mesh.scale.z = 1;
    });
    hovered = node;
    (node ? node.parts || [node.mesh] : []).forEach((mesh) => {
      mesh.scale.x = mesh.scale.z = 1.35;
    });
    options.say(node ? node.label : built.hint);
    canvas.classList.toggle("is-pointing", Boolean(node && node.href));
    invalidate();
  }

  const ray = new THREE.Raycaster();
  const pointer = new THREE.Vector2();
  function pick(event) {
    const area = canvas.getBoundingClientRect();
    pointer.set(((event.clientX - area.left) / area.width) * 2 - 1, -((event.clientY - area.top) / area.height) * 2 + 1);
    ray.setFromCamera(pointer, camera);
    const hit = ray.intersectObjects(picks, false)[0];
    return hit ? hit.object.userData.node : null;
  }

  const controller = new AbortController();
  const signal = controller.signal;
  let drag = null;
  canvas.addEventListener(
    "pointerdown",
    (event) => {
      drag = { x: event.clientX, yaw: view.yaw, moved: false };
    },
    { signal }
  );
  canvas.addEventListener(
    "pointermove",
    (event) => {
      if (drag && event.buttons) {
        const dx = event.clientX - drag.x;
        if (Math.abs(dx) > 4) {
          drag.moved = true;
          tween = null;
          view.yaw = drag.yaw - dx * 0.008;
          invalidate();
        }
        return;
      }
      highlight(pick(event));
    },
    { signal }
  );
  canvas.addEventListener("pointerleave", () => highlight(null), { signal });
  canvas.addEventListener(
    "pointerup",
    (event) => {
      const moved = drag && drag.moved;
      drag = null;
      if (moved) {
        return;
      }
      const node = pick(event);
      if (node && node.href) {
        window.location.assign(node.href);
      }
    },
    { signal }
  );
  // Pointing at a part of the 2D view lights the mesh that stands for it.
  if (options.view) {
    options.view.addEventListener(
      "pointerover",
      (event) => {
        const element = spec.elementOf(event.target);
        const mesh = element ? picks.find((item) => item.userData.node.element === element) : null;
        highlight(mesh ? mesh.userData.node : null);
      },
      { signal }
    );
    options.view.addEventListener("pointerleave", () => highlight(null), { signal });
  }

  canvas.addEventListener(
    "webglcontextlost",
    (event) => {
      event.preventDefault();
      lost = true;
      options.say(WORDS.lost);
    },
    { signal }
  );
  canvas.addEventListener(
    "webglcontextrestored",
    () => {
      lost = false;
      options.say(built.hint);
      invalidate();
    },
    { signal }
  );
  document.addEventListener("visibilitychange", invalidate, { signal });
  const watcher = new IntersectionObserver((records) => {
    inView = records.some((record) => record.isIntersecting);
    invalidate();
  });
  watcher.observe(stage);
  const sizer = new ResizeObserver(resize);
  sizer.observe(stage);

  // A change of colour scheme recolours the scene in place.
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener(
    "change",
    () => {
      palette = colours();
      renderer.setClearColor(palette.backdrop, 1);
      materials.forEach((item, name) => item.color.setHex(palette[name.replace(/^pale-/, "")]));
      invalidate();
    },
    { signal }
  );

  resize();
  options.say(built.hint);
  invalidate();

  return {
    draw,
    turn: (step) => turnTo(view.yaw + step),
    reset: () => turnTo(built.home.yaw),
    info: () => ({
      ...(built.info ? built.info() : {}),
      pickable: picks.length,
      geometries: renderer.info.memory.geometries,
      programs: renderer.info.programs ? renderer.info.programs.length : 0,
    }),
    dispose() {
      controller.abort();
      watcher.disconnect();
      sizer.disconnect();
      if (built.dispose) {
        built.dispose();
      }
      if (rafId) {
        window.cancelAnimationFrame(rafId);
      }
      geometries.forEach((item) => item.dispose());
      materials.forEach((item) => item.dispose());
      floor.geometry.dispose();
      scene.clear();
      renderer.dispose();
      renderer.forceContextLoss();
      canvas.remove();
    },
  };
}

// --- the drift field of the dashboard ---------------------------------------------------------

const DRIFT_DAYS = 30;
const LANE_LENGTH = 18;
const LANE_GAP = 1.3;
// changes hours apart would stand in one spot; the drift line keeps the exact times
const COLUMN_GAP = 0.6;

const DRIFT = {
  // the lanes, from the drift lines of the page
  read(root) {
    const list = document.querySelector(".driftlines");
    const lanes = [];
    if (!list) {
      return null;
    }
    list.querySelectorAll(".driftline").forEach((row) => {
      const name = row.querySelector(".driftline__name");
      const meta = row.querySelector(".driftline__meta");
      const lane = {
        label: [name ? name.textContent.trim() : "", meta ? meta.textContent.trim() : ""].filter(Boolean).join(", "),
        href: name ? localPath(name.getAttribute("href")) : "",
        element: row,
        checks: [],
      };
      row.querySelectorAll("[data-age]").forEach((mark) => {
        const age = Number(mark.getAttribute("data-age"));
        if (!Number.isFinite(age)) {
          return;
        }
        const kind = mark.getAttribute("data-kind") || "ok";
        const check = { kind, age, element: mark };
        if (kind === "change") {
          const severity = mark.getAttribute("data-severity");
          check.severity = RANK.includes(severity) ? severity : "low";
          check.items = Math.max(1, Number(mark.getAttribute("data-items")) || 1);
          check.open = mark.getAttribute("data-status") === "open";
          check.href = localPath(mark.getAttribute("href"));
          check.label = mark.getAttribute("aria-label") || "";
        }
        lane.checks.push(check);
      });
      const changes = lane.checks.filter((check) => check.kind === "change");
      lane.items = changes.reduce((sum, check) => sum + check.items, 0);
      const open = changes.filter((check) => check.open).map((check) => RANK.indexOf(check.severity));
      lane.worst = open.length ? RANK[Math.max(...open)] : "";
      lanes.push(lane);
    });
    return lanes.length ? { lanes, view: list } : null;
  },

  // a mark or the name of a drift line stands for its column or block
  elementOf(target) {
    const found = target.closest ? target.closest(".driftline [data-age], .driftline__name") : null;
    return found && found.classList.contains("driftline__name") ? found.closest(".driftline") : found;
  },

  build(kit) {
    const { scene, material, prism, box, pickable } = kit;
    const lanes = kit.data.lanes;
    let tallest = 1;
    lanes.forEach((lane, index) => {
      const z = (index - (lanes.length - 1) / 2) * LANE_GAP;
      const strip = box("strip", LANE_LENGTH, 0.02, 0.7);
      strip.material = material("lane");
      scene.add(strip);
      strip.position.set(0, 0, z);
      let next = Infinity;
      const placed = lane.checks
        .map((check) => ({ check, x: LANE_LENGTH / 2 - (Math.min(DRIFT_DAYS, Math.max(0, check.age)) / DRIFT_DAYS) * LANE_LENGTH }))
        .sort((a, b) => b.x - a.x);
      placed.forEach((item) => {
        if (item.check.kind === "change") {
          item.x = Math.min(item.x, next - COLUMN_GAP);
          next = item.x;
        }
      });
      placed.forEach(({ check, x }) => {
        let mesh;
        if (check.kind === "change") {
          const tall = height(check.items);
          tallest = Math.max(tallest, tall);
          mesh = prism(check.severity, 0.26, tall);
          mesh.material = material(check.open ? check.severity : "pale-" + check.severity);
          pickable(mesh, { label: check.label, href: check.href, element: check.element });
        } else if (check.kind === "failed") {
          mesh = box("stub", 0.12, 0.12, 0.42);
          mesh.material = material("ink");
        } else {
          mesh = box("tick", 0.05, 0.2, 0.42);
          mesh.material = material("tick");
        }
        mesh.position.set(x, 0.02, z);
        scene.add(mesh);
      });
      // the source: all its items, shape and colour of its worst open change
      const tall = height(lane.items);
      tallest = Math.max(tallest, tall);
      const block = lane.worst ? prism(lane.worst, 0.5, tall) : box("block-none", 0.8, 1, 0.8);
      block.scale.y = tall;
      block.material = material(lane.worst || "none");
      block.position.set(LANE_LENGTH / 2 + 1.3, 0.02, z);
      pickable(block, { label: lane.label, href: lane.href, element: lane.element });
      scene.add(block);
    });
    return {
      extent: { wide: LANE_LENGTH + 3, deep: lanes.length * LANE_GAP, tall: tallest, x: 0.6 },
      home: { yaw: -0.5, pitch: 0.62 },
      hint: "Point at a column or a block to read it; select it to open the change or the source.",
      info: () => ({ lanes: lanes.length }),
    };
  },
};

// --- the change replay of a source page --------------------------------------------------------

const REPLAY_PITCH = 0.42;
const REPLAY_ROW = 0.9;
const BAR = 0.34;

const REPLAY = {
  // the cells of the heat map, its days and rows, and the day cursor the replay moves
  read(root) {
    const section = root.closest("[data-replay]");
    const map = section ? section.querySelector("[data-replay-map]") : null;
    const cursor = section ? section.querySelector("[data-replay-cursor]") : null;
    const days = section ? Number(section.getAttribute("data-days")) : 0;
    const pitch = section ? Number(section.getAttribute("data-pitch")) : 0;
    if (!map || !cursor || !(days > 0) || !(pitch > 0)) {
      return null;
    }
    const cells = [];
    let rows = section.querySelectorAll(".replay-track").length;
    section.querySelectorAll(".replay-cell").forEach((cell) => {
      const day = Number(cell.getAttribute("data-day-index"));
      const row = Number(cell.getAttribute("data-row"));
      const counts = (cell.getAttribute("data-counts") || "").split(" ").map(Number);
      if (!Number.isInteger(day) || !Number.isInteger(row) || counts.length !== 4 || counts.some((n) => !(n >= 0))) {
        return;
      }
      rows = Math.max(rows, row + 1);
      const title = cell.querySelector("title");
      cells.push({
        day,
        row,
        counts,
        element: cell,
        href: localPath(cell.getAttribute("href")),
        label: title ? title.textContent.trim() : cell.getAttribute("data-label") || "",
      });
    });
    return cells.length ? { cells, days, rows, pitch, cursor, view: map } : null;
  },

  elementOf(target) {
    return target.closest ? target.closest(".replay-cell") : null;
  },

  // A bar per cell, stacked by severity from critical at the foot to low on top, its height from
  // the log of all its items; a pane stands on the day of the cursor and the days after it fade,
  // as on the heat map. The scene follows the cursor through its x attribute.
  build(kit) {
    const { THREE, scene, material, box, pickable, data } = kit;
    const wide = data.days * REPLAY_PITCH;
    const deep = data.rows * REPLAY_ROW;
    const xOf = (day) => -wide / 2 + (day + 0.5) * REPLAY_PITCH;
    const zOf = (row) => -deep / 2 + (row + 0.5) * REPLAY_ROW;
    const segments = [];
    let tallest = 1;
    for (let row = 0; row < data.rows; row += 1) {
      const track = box("track", wide, 0.02, REPLAY_ROW * 0.7);
      track.material = material("lane");
      track.position.set(0, 0, zOf(row));
      scene.add(track);
    }
    data.cells.forEach((cell) => {
      const total = cell.counts.reduce((a, b) => a + b, 0);
      if (!total) {
        return;
      }
      const tall = height(total);
      tallest = Math.max(tallest, tall);
      let base = 0.02;
      const node = { label: cell.label, href: cell.href, element: cell.element, parts: [] };
      // one picked part per cell: the lowest segment carries the node, the others point to it
      for (let s = RANK.length - 1; s >= 0; s -= 1) {
        if (!cell.counts[s]) {
          continue;
        }
        const part = box("bar", BAR, 1, BAR);
        part.scale.y = (tall * cell.counts[s]) / total;
        part.position.set(xOf(cell.day), base, zOf(cell.row));
        base += part.scale.y;
        part.userData.severity = RANK[s];
        part.userData.day = cell.day;
        segments.push(part);
        node.parts.push(part);
        scene.add(part);
        if (!node.mesh) {
          pickable(part, node);
        } else {
          part.userData.node = node;
        }
      }
    });
    // the day of the cursor: a thin pane across every row
    const pane = new THREE.Mesh(
      new THREE.BoxGeometry(REPLAY_PITCH * 0.92, 1, deep + 0.4).translate(0, 0.5, 0),
      new THREE.MeshBasicMaterial({ color: 0x000000, transparent: true, opacity: 0.12, depthWrite: false })
    );
    pane.scale.y = tallest + 0.3;
    scene.add(pane);
    let shown = -1;

    function follow() {
      const x = Number(data.cursor.getAttribute("x"));
      const day = Math.max(0, Math.min(data.days - 1, Math.round(x / data.pitch)));
      shown = day;
      pane.position.set(xOf(day), 0, 0);
      pane.material.color.setHex(token("--ink", 0x1e1e24));
      segments.forEach((part) => {
        part.material = material(part.userData.day > day ? "pale-" + part.userData.severity : part.userData.severity);
      });
      kit.invalidate();
    }
    const watch = new MutationObserver(follow);
    watch.observe(data.cursor, { attributes: true, attributeFilter: ["x"] });
    follow();

    return {
      extent: { wide, deep, tall: tallest, x: 0 },
      home: { yaw: -0.42, pitch: 0.72 },
      hint: "Point at a bar to read its day and resource type; select it to open those changes. The pane is the day of the replay.",
      info: () => ({ cells: data.cells.length, days: data.days, rows: data.rows, day: shown }),
      dispose() {
        watch.disconnect();
        pane.geometry.dispose();
        pane.material.dispose();
      },
    };
  },
};

const SCENES = { drift: DRIFT, replay: REPLAY };

// --- the page: each block, its hide button and the three buttons under it ----------------------

let library = null;

async function start(root) {
  const spec = SCENES[root.getAttribute("data-scene")];
  const data = spec && supportsWebGL2() ? spec.read(root) : null;
  if (!data) {
    root.classList.add("is-unavailable");
    return;
  }
  const detail = root.querySelector(".scene__detail");
  const toggle = root.querySelector(".scene__toggle");
  const tools = root.querySelector(".scene__tools");
  const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const say = (text) => {
    detail.textContent = text;
  };
  const options = { say, view: data.view, reducedMotion: () => motion.matches };
  let built = null;
  root.hidden = false;
  toggle.hidden = false;

  async function show() {
    root.classList.remove("is-closed");
    toggle.textContent = "Hide the 3D view";
    if (!library) {
      try {
        library = await import(THREE_URL);
      } catch (error) {
        say(WORDS.noModule);
        return;
      }
    }
    try {
      built = buildStage(library, root, spec, data, options);
    } catch (error) {
      root.querySelectorAll(".scene__stage canvas").forEach((canvas) => canvas.remove());
      built = null;
      say(WORDS.noWebGL);
      return;
    }
    tools.hidden = false;
    root.setAttribute("data-scene-state", "ready");
  }

  function hide() {
    if (built) {
      built.dispose();
      built = null;
    }
    root.classList.add("is-closed");
    root.setAttribute("data-scene-state", "closed");
    tools.hidden = true;
    toggle.textContent = "Show the 3D view";
    say(WORDS.closed);
  }

  toggle.addEventListener("click", () => {
    if (built) {
      rememberChoice(true);
      hide();
    } else {
      rememberChoice(false);
      show();
    }
  });
  root.querySelector(".scene__turn-left").addEventListener("click", () => built && built.turn(-TURN_STEP));
  root.querySelector(".scene__turn-right").addEventListener("click", () => built && built.turn(TURN_STEP));
  root.querySelector(".scene__reset").addEventListener("click", () => built && built.reset());
  window.addEventListener("pagehide", () => built && hide());
  window.addEventListener("pageshow", (event) => {
    if (event.persisted && !built && !hiddenByChoice()) {
      show();
    }
  });
  root.scene = {
    info: () => (built ? built.info() : null),
    draw: () => built && built.draw(),
    show,
    hide,
  };
  if (hiddenByChoice()) {
    hide();
  } else {
    await show();
  }
}

document.querySelectorAll("[data-scene]").forEach(start);
