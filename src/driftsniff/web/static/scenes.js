/*
 * The 3D views of the interface (docs/design-direction.md, "The 3D views"). One ES module for
 * every scene; a page carries a block with data-scene="<kind>" and loads this file:
 * - lab: the dashboard's sources as devices on a desk, the severity shape of each source's worst
 *   open change on its status lights;
 * - replay: the change replay of a source page, the source's own device with the resource types
 *   that changed on the replay's day rising out of it as cards.
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
// the light theme's severity colours, as in app.css (the replay cards' stripes)
const SEVERITY_LIGHT = { low: 0x4a6283, medium: 0x8a5f00, high: 0xa8441b, critical: 0xc8342b };
// the add-ons a scene may ask for (spec.addons), vendored beside three.js, same release
const ADDON_URLS = {
  RoundedBoxGeometry: "/static/vendor/three/addons/RoundedBoxGeometry.js",
  RoomEnvironment: "/static/vendor/three/addons/RoomEnvironment.js",
  GLTFLoader: "/static/vendor/three/addons/GLTFLoader.js",
};
// The build's version (the `v` query the page put on this script's own address): the models are
// fetched with it, so a new build is never drawn with models a browser or a cache kept from an
// older one. three.js and its add-ons keep their plain addresses: they are pinned files, and
// one address per module keeps them one module instance.
const VERSION = new URL(import.meta.url).search;
const modelUrl = (name) => `/static/models/${name}/${name}.gltf${VERSION}`;

const WORDS = {
  noModule: "The 3D view could not be loaded. Reload the page; the view below shows the same facts.",
  noWebGL: "This browser could not start the 3D view. The view below shows the same facts.",
  lost: "The browser paused the 3D view (the graphics context was lost). It resumes by itself.",
  closed: "The 3D view is off. The view below shows the same facts.",
};

// Dark when the user chose it on the Account page (data-theme on the html element), or when the
// theme is "system" and the device is dark: the same rule as the stylesheet.
function prefersDark() {
  const chosen = document.documentElement.getAttribute("data-theme");
  return chosen ? chosen === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
}

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

function number(value) {
  return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
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

// --- the stage: renderer, camera, turning, picking, drawing on demand ----------------------

// `spec.build(kit)` adds the meshes of a scene to kit.scene and returns
// { extent: {wide, deep, tall, x}, home: {yaw, pitch}, hint, info?, sync? }. A pickable mesh is
// registered with kit.pickable(mesh, {label, href, element}); `element` is the node of the 2D
// view it stands for, so pointing at that node lights the mesh.
function buildStage(THREE, root, spec, data, options) {
  const addons = options.addons || {};
  const stage = root.querySelector(".scene__stage");
  const canvas = document.createElement("canvas");
  canvas.className = "scene__canvas";
  canvas.setAttribute("aria-hidden", "true");
  stage.appendChild(canvas);
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(spec.fov || 32, 2, 0.05, 400);
  // a scene with spec.studio gets soft studio light: a room environment for the materials,
  // filmic tone mapping and one shadow-casting key light; the others keep the flat chart light
  let sky;
  let sun;
  if (spec.studio && addons.RoomEnvironment) {
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.shadowMap.enabled = true;
    renderer.shadowMap.type = THREE.PCFShadowMap;
    const pmrem = new THREE.PMREMGenerator(renderer);
    scene.environment = pmrem.fromScene(new addons.RoomEnvironment(), 0.04).texture;
    pmrem.dispose();
    sky = new THREE.HemisphereLight(0xffffff, 0x404048, 0.45);
    sun = new THREE.DirectionalLight(0xffffff, 2.4);
    sun.position.set(-4, 7, 5);
    sun.castShadow = true;
    sun.shadow.mapSize.set(2048, 2048);
    sun.shadow.radius = 4;
    sun.shadow.bias = -0.0004;
  } else {
    sky = new THREE.HemisphereLight(0xffffff, 0x888888, 1.6);
    sun = new THREE.DirectionalLight(0xffffff, 1.4);
    sun.position.set(-6, 14, 8);
  }
  scene.add(sky, sun);

  let palette = colours();
  renderer.setClearColor(palette.backdrop, 1);
  const materials = new Map();
  const picks = [];

  // A material per palette name; "pale-<name>" is the same colour at 32 % opacity.
  function material(name) {
    if (!materials.has(name)) {
      const pale = name.startsWith("pale-");
      const colour = palette[pale ? name.slice(5) : name];
      materials.set(name, new THREE.MeshLambertMaterial(pale ? { color: colour, transparent: true, opacity: 0.32 } : { color: colour }));
    }
    return materials.get(name);
  }



  // a pickable may be a mesh or a group; a pick anywhere inside it finds its node
  function pickable(mesh, node) {
    node.mesh = mesh;
    mesh.userData.node = node;
    picks.push(mesh);
  }

  // meshes that turn to face the viewer as the scene turns (the replay's deck of cards)
  const billboards = [];
  // per-frame updates (the replay's cards rising): while one returns true, frames keep coming, but only
  // while the stage is in view, the page is shown and reduced motion is off
  const animators = [];

  // the drawing state comes first: a scene may ask for a frame while it is built
  let tween = null;
  let rafId = 0;
  let inView = true;
  let lost = false;
  let hovered = null;
  let lastTick = 0;
  const kit = {
    THREE, scene, material, pickable, data, addons, colours,
    models: options.models,
    invalidate: () => invalidate(),
    billboard: (mesh) => billboards.push(mesh),
    // a pickable that left the scene (a card of an earlier day) is picked no more
    unpickable: (mesh) => {
      const at = picks.indexOf(mesh);
      if (at >= 0) {
        picks.splice(at, 1);
      }
      if (hovered && hovered.mesh === mesh) {
        hovered = null;
      }
    },
    animate: (update) => {
      animators.push(update);
      invalidate();
    },
    reducedMotion: () => options.reducedMotion(),
  };
  const built = spec.build(kit);
  const { extent } = built;
  if (built.floor !== false) {
    const floor = new THREE.Mesh(new THREE.PlaneGeometry(extent.wide + 2, extent.deep + 1.2), material("ground"));
    floor.rotation.x = -Math.PI / 2;
    floor.position.set(extent.x, 0, 0);
    scene.add(floor);
  }
  if (spec.studio) {
    const reach = Math.max(extent.wide, extent.deep) * 0.7 + 1;
    Object.assign(sun.shadow.camera, { left: -reach, right: reach, top: reach, bottom: -reach });
  }
  const center = new THREE.Vector3(extent.x, extent.y !== undefined ? extent.y : extent.tall / 3, extent.z || 0);

  const view = { yaw: built.home.yaw, pitch: built.home.pitch };

  // The distance that fits the whole field for the current turn and size.
  function place() {
    const across = Math.abs(extent.wide * Math.cos(view.yaw)) + Math.abs(extent.deep * Math.sin(view.yaw));
    const along = Math.abs(extent.wide * Math.sin(view.yaw)) + Math.abs(extent.deep * Math.cos(view.yaw));
    const tall = along * Math.sin(view.pitch) + extent.tall * Math.cos(view.pitch);
    const half = Math.tan((camera.fov * Math.PI) / 360);
    const distance = Math.max((1.12 * across) / 2 / (half * camera.aspect), (1.2 * tall) / 2 / half) + along * 0.22;
    camera.position.set(
      center.x + distance * Math.cos(view.pitch) * Math.sin(view.yaw),
      center.y + distance * Math.sin(view.pitch),
      center.z + distance * Math.cos(view.pitch) * Math.cos(view.yaw)
    );
    camera.lookAt(center);
    billboards.forEach((mesh) => {
      mesh.rotation.y = view.yaw;
    });
  }

  function draw() {
    place();
    renderer.render(scene, camera);
  }

  function frame(now) {
    rafId = 0;
    const step = lastTick ? Math.min(0.1, (now - lastTick) / 1000) : 0;
    lastTick = now;
    // an animator returns true while it needs more frames (the replay's cards rising)
    const busy = !options.reducedMotion() && animators.map((update) => update(step)).some(Boolean);
    if (busy) {
      invalidate();
    } else {
      lastTick = 0;
    }
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
    // a node may light itself (node.hover); otherwise its meshes widen (the segments of a bar)
    const light = (item, on) => {
      if (item.hover) {
        item.hover(on);
        return;
      }
      (item.parts || [item.mesh]).forEach((mesh) => {
        mesh.scale.x = mesh.scale.z = on ? 1.35 : 1;
      });
    };
    if (hovered) {
      light(hovered, false);
    }
    hovered = node;
    if (node) {
      light(node, true);
    }
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
    const hit = ray.intersectObjects(picks, true)[0];
    for (let item = hit ? hit.object : null; item; item = item.parent) {
      if (item.userData.node) {
        return item.userData.node;
      }
    }
    return null;
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
      if (built.recolour) {
        built.recolour(palette);
      }
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
      // everything the scene holds, shared or not (dispose is safe to repeat)
      scene.traverse((item) => {
        if (item.geometry) {
          item.geometry.dispose();
        }
        (Array.isArray(item.material) ? item.material : item.material ? [item.material] : []).forEach((m) => {
          Object.values(m).forEach((value) => value && value.isTexture && value.dispose());
          m.dispose();
        });
      });
      materials.forEach((item) => item.dispose());
      if (scene.environment) {
        scene.environment.dispose();
      }
      scene.clear();
      renderer.dispose();
      renderer.forceContextLoss();
      canvas.remove();
    },
  };
}

// --- the lab of the dashboard --------------------------------------------------------------------

// The colours of a device's status lights: the worst open change, as status LEDs show it on real
// kit; green when nothing is open; dark grey for a source that is failing, stale or not checked.
const STATUS_LIGHT = { low: 0x5f8fd6, medium: 0xe8b02a, high: 0xf07a2a, critical: 0xe5392f };
const STATUS_OFF = 0x3a3d45;
// The severity colours of the replay cards' stripes. In the dark theme the page's severity tokens are light
// tints made for text on charcoal; lit in 3D they wash out to pink, so the lab uses deeper ones.
const TOKEN_DARK = { low: 0x5f86c8, medium: 0xd9a52a, high: 0xe0702a, critical: 0xd8352b };
// What a source type is in the lab: a server rack, a NAS, the gateway, a camera, a monitoring
// screen, a Raspberry Pi (Home Assistant), a small PC (Portainer, and anything else).
const KIND_OF = {
  proxmox: "rack", xo: "rack", truenas: "rack", redfish: "rack",
  synology: "nas", qnap: "nas",
  unifi: "gateway", unifi_protect: "camera",
  grafana: "screen", checkmk: "screen", zabbix: "screen", prometheus: "screen",
  homeassistant: "pi", portainer: "nuc",
};
const kindOf = (type) => KIND_OF[type] || "nuc";
// The model of each kind (static/models/<name>/<name>.gltf, real models: CC BY 4.0, and the
// NAS made for driftsniff with Meshy; see static/models/CREDITS.txt).
const MODEL_OF = { rack: "rack", nas: "nas", gateway: "gateway", camera: "camera", screen: "screen", pi: "pi", nuc: "nuc" };
// The room a kind takes in its row (metres) and the row it stands in.
const FOOTPRINT = { rack: 0.72, nas: 0.36, screen: 0.56, camera: 0.36, gateway: 0.4, pi: 0.36, nuc: 0.36 };
const BACK_ROW = new Set(["rack", "nas", "screen"]);
// the line colour of a screen's little dashboard, per monitoring product
const SCREEN_LINE = { grafana: "#f2a33a", checkmk: "#5fbf6e", zabbix: "#d9534f", prometheus: "#e6522c" };
const ROW_WIDTH = 4.6; // a row of devices wraps to the next one past this width (metres)
const UNHEALTHY = new Set(["failing", "partial", "stale", "unsupported"]);

// --- the workshop: the devices, their status lights and the desk of the 3D views ----------------

// Everything a studio scene draws with (the lab of the dashboard, the replay of a source page).
function workshop(kit) {
  const { THREE, scene, addons } = kit;
  const RoundedBox = addons.RoundedBoxGeometry;
  const isDark = () => prefersDark();
  const tokenColour = (severity) => (isDark() ? TOKEN_DARK : SEVERITY_LIGHT)[severity];
  const m = (options) => new THREE.MeshStandardMaterial(options);
  const mat = {
    black: m({ color: 0x1b1c20, roughness: 0.45, metalness: 0.3 }),
    graphite: m({ color: 0x2c2e34, roughness: 0.5, metalness: 0.5 }),
    steel: m({ color: 0x9aa0a8, roughness: 0.35, metalness: 0.85 }),
    white: m({ color: 0xeeeeea, roughness: 0.35 }),
    silver: m({ color: 0xc4c7cc, roughness: 0.3, metalness: 0.7 }),
    glass: m({ color: 0x0b0c10, roughness: 0.1, metalness: 0.2 }),
    port: m({ color: 0x0c0c0e, roughness: 0.9 }),
    desk: m({ roughness: 0.85 }),
    deskEdge: m({ roughness: 0.8 }),
    off: m({ color: 0x3a3b42, roughness: 0.6 }),
  };
  const glowCache = new Map();
  const glow = (hex, strength = 2.2) => {
    const key = hex + ":" + strength;
    if (!glowCache.has(key)) {
      glowCache.set(key, m({ color: hex, emissive: hex, emissiveIntensity: strength, roughness: 0.4 }));
    }
    return glowCache.get(key);
  };
  const OK = 0x57c27a;

  // the desk follows the theme (called again when the colour scheme changes)
  function paint() {
    const dark = isDark();
    const p = kit.colours();
    mat.desk.color.setHex(dark ? p.lane : 0xd8d2c3);
    mat.deskEdge.color.setHex(dark ? p.none : 0xcfc9ba);
    scene.environmentIntensity = dark ? 0.55 : 0.8;
  }

  const rbox = (w, h, d, r, material) => new THREE.Mesh(new RoundedBox(w, h, d, 3, r), material);
  const block = (w, h, d, material) => new THREE.Mesh(new THREE.BoxGeometry(w, h, d), material);
  function leds(group, x0, y, z, count, gap, colour) {
    for (let i = 0; i < count; i += 1) {
      const led = block(0.018, 0.012, 0.004, glow(colour, 3));
      led.position.set(x0 + i * gap, y, z);
      led.userData.led = true;
      group.add(led);
    }
  }

  // ---- the devices: clones of the real models ----
  // A device is a clone of its kind's model with materials of its own (its lights are tinted
  // per source), a status LED where the model has no lit part of its own, the monitoring
  // screen's picture on the model's Screen surface, and the camera on a short mast.
  function fallbackBox() {
    const g = new THREE.Group();
    const body = rbox(0.24, 0.07, 0.2, 0.02, mat.black);
    body.position.y = 0.035;
    g.add(body);
    return g;
  }
  function screenTexture(colour, seed) {
    const canvas = document.createElement("canvas");
    canvas.width = 256;
    canvas.height = 160;
    const x = canvas.getContext("2d");
    x.fillStyle = "#121318";
    x.fillRect(0, 0, 256, 160);
    x.strokeStyle = "#2a2d36";
    for (let i = 1; i < 5; i += 1) {
      x.beginPath();
      x.moveTo(0, i * 32);
      x.lineTo(256, i * 32);
      x.stroke();
    }
    x.strokeStyle = colour;
    x.lineWidth = 3;
    x.beginPath();
    for (let i = 0; i <= 32; i += 1) {
      const v = 90 + Math.sin(i * 0.6 + seed) * 22 + Math.sin(i * 1.7 + seed * 2) * 10;
      if (i) {
        x.lineTo(i * 8, v);
      } else {
        x.moveTo(0, v);
      }
    }
    x.stroke();
    for (let i = 0; i < 6; i += 1) {
      x.fillStyle = i % 3 ? "#3b6ea8" : colour;
      x.fillRect(12 + i * 40, 130, 28, 18);
    }
    const texture = new THREE.CanvasTexture(canvas);
    texture.colorSpace = THREE.SRGBColorSpace;
    return texture;
  }
  // ---- the status of a device: its own lights, no sign over it ----
  // The status lights take the colour of the worst open change (as on real kit: red, orange,
  // amber, blue); green when nothing is open; dark when the source is failing, stale or not
  // checked yet. A device with open changes also casts a faint glow of that colour on the desk.
  function statusColour(source) {
    if (source.worst) {
      return STATUS_LIGHT[source.worst];
    }
    return UNHEALTHY.has(source.health) || source.health === "open" ? STATUS_OFF : OK;
  }
  function light(device, source) {
    const colour = statusColour(source);
    const off = colour === STATUS_OFF;
    device.traverse((part) => {
      if (part.isMesh && part.userData.led) {
        part.material = glow(colour, off ? 0.15 : 3);
      } else if (part.isMesh && part.userData.lit) {
        // the model's own lit parts (the router's LEDs, the camera's glass) take the colour
        part.material.emissive.setHex(colour);
        part.material.emissiveIntensity = off ? 0.05 : 1.4;
      }
    });
  }

  // The device of one source: its kind's model, cloned. `kit.models` holds the loaded models
  // (start() loads the ones the page needs); a kind whose model failed to load gets a plain box.
  function deviceFor(source) {
    const kind = kindOf(source.type);
    const proto = kit.models && kit.models.get(MODEL_OF[kind]);
    if (!proto) {
      const box = fallbackBox();
      leds(box, 0.09, 0.04, 0.101, 1, 0, OK);
      return box;
    }
    const g = new THREE.Group();
    const body = proto.clone(true);
    body.traverse((part) => {
      if (!part.isMesh) {
        return;
      }
      part.material = part.material.clone();
      if (part.name === "Screen") {
        const picture = screenTexture(SCREEN_LINE[source.type] || "#7fb0ff", (source.index || 0) + 1);
        part.material = m({ map: picture, emissive: 0xffffff, emissiveMap: picture, emissiveIntensity: 0.75, roughness: 0.3 });
      } else if (part.material.emissiveMap) {
        part.userData.lit = true;
      }
    });
    if (kind === "camera") {
      // the camera on a short mast, looking a little down
      const mast = new THREE.Mesh(new THREE.CylinderGeometry(0.012, 0.016, 0.36, 16), mat.steel);
      mast.position.y = 0.18;
      const foot = rbox(0.09, 0.012, 0.09, 0.004, mat.graphite);
      foot.position.y = 0.006;
      body.position.y = 0.3;
      body.rotation.x = 0.12;
      g.add(mast, foot);
    }
    g.add(body);
    // a status LED where the model has no lit part of its own: the rack's door, the bezel of
    // the screen, the front of the Pi and of the small PC
    g.updateMatrixWorld(true);
    const box = new THREE.Box3().setFromObject(g);
    if (kind === "rack") {
      const strip = block(0.012, 0.22, 0.006, glow(OK, 3));
      strip.position.set(box.max.x - 0.06, box.max.y * 0.62, box.max.z + 0.004);
      strip.userData.led = true;
      g.add(strip);
    } else if (kind === "screen") {
      leds(g, box.max.x - 0.04, box.max.y * 0.43, box.max.z * 0.3, 1, 0, OK);
    } else if (kind === "nas") {
      // at the head of the NAS's own column of lights, beside the drive trays
      leds(g, box.max.x - 0.03, box.max.y * 0.8, box.max.z + 0.002, 1, 0, OK);
    } else if (kind !== "camera" && kind !== "gateway") {
      leds(g, box.max.x - 0.04, box.max.y + 0.004, box.max.z - 0.02, 1, 0, OK);
    }
    return g;
  }

  // the desk, centred on x 0 and on `z`; it receives the shadows
  function makeDesk(width, depth, z) {
    const desk = rbox(width, 0.12, depth, 0.04, mat.desk);
    desk.position.set(0, -0.06, z);
    desk.receiveShadow = true;
    const lip = rbox(width + 0.04, 0.04, depth + 0.04, 0.02, mat.deskEdge);
    lip.position.set(0, -0.1, z);
    scene.add(desk, lip);
    return [desk, lip];
  }

  // every mesh but the desk casts and receives shadows
  function shade(except) {
    scene.traverse((part) => {
      if (part.isMesh && !except.includes(part)) {
        part.castShadow = true;
        part.receiveShadow = true;
      }
    });
  }

  return { m, mat, glow, rbox, block, OK, light, tokenColour, paint, deviceFor, makeDesk, shade };
}

const LAB = {
  studio: true,
  fov: 30,
  addons: ["RoundedBoxGeometry", "RoomEnvironment", "GLTFLoader"],
  // the models of the kinds on this page
  models: (data) => [...new Set(data.sources.map((s) => MODEL_OF[kindOf(s.type)]))],

  // the sources, from the drift lines of the page and their data attributes
  read() {
    const list = document.querySelector(".driftlines");
    if (!list) {
      return null;
    }
    const sources = [];
    list.querySelectorAll(".driftline").forEach((row, index) => {
      const name = row.querySelector(".driftline__name");
      const worst = row.getAttribute("data-worst-open") || "";
      sources.push({
        index,
        name: name ? name.textContent.trim() : "",
        href: name ? localPath(name.getAttribute("href")) : "",
        type: row.getAttribute("data-source-type") || "",
        items: Math.max(0, Number(row.getAttribute("data-open-items")) || 0),
        worst: RANK.includes(worst) ? worst : "",
        health: row.getAttribute("data-health") || "",
        element: row,
      });
    });
    return sources.length ? { sources, view: list } : null;
  },

  // a drift line, or anything inside it, stands for its device
  elementOf(target) {
    return target.closest ? target.closest(".driftline") : null;
  },

  build(kit) {
    const { THREE, scene, pickable } = kit;
    const { light, paint, deviceFor, makeDesk, shade } = workshop(kit);

    // ---- the layout: a back row of racks, NAS units and screens, a front row of the rest ----
    const sources = kit.data.sources;
    const back = [];
    const front = [];
    sources.forEach((source) => {
      const kind = kindOf(source.type);
      (BACK_ROW.has(kind) ? back : front).push({ kind, source, width: FOOTPRINT[kind] });
    });
    // like stands with like: racks, NAS units and screens at the back; camera, gateway, hub,
    // container host and small boxes at the front; by name within a kind
    const ORDER = ["rack", "nas", "screen", "camera", "gateway", "pi", "nuc"];
    const byKind = (a, b) => ORDER.indexOf(a.kind) - ORDER.indexOf(b.kind) || (a.source ? a.source.index : 0) - (b.source ? b.source.index : 0);
    back.sort(byKind);
    front.sort(byKind);
    // a long row wraps: back rows step away from the viewer, front rows towards
    function rows(items) {
      const result = [[]];
      let width = 0;
      items.forEach((item) => {
        if (width + item.width > ROW_WIDTH && result[result.length - 1].length) {
          result.push([]);
          width = 0;
        }
        result[result.length - 1].push(item);
        width += item.width;
      });
      return result.filter((row) => row.length);
    }
    const backRows = rows(back);
    const frontRows = rows(front);
    const widest = Math.max(...backRows.concat(frontRows).map((row) => row.reduce((sum, item) => sum + item.width, 0)), 1.6);
    const zOfBack = (i) => -0.45 - i * 0.75;
    const zOfFront = (i) => 0.3 + i * 0.5;
    const nodes = new Map();
    let tallest = 0.6;

    function place(row, z, depthTilt) {
      const total = row.reduce((sum, item) => sum + item.width, 0);
      let x = -total / 2;
      row.forEach((item) => {
        const centre = x + item.width / 2;
        x += item.width;
        const s = item.source;
        const device = deviceFor(s);
        device.position.set(centre, 0, z);
        device.rotation.y = depthTilt * (centre / Math.max(1, widest / 2));
        scene.add(device);
        nodes.set(s, device);
        light(device, s);
        device.updateMatrixWorld(true);
        tallest = Math.max(tallest, new THREE.Box3().setFromObject(device).max.y);
      });
    }
    backRows.forEach((row, i) => place(row, zOfBack(i), -0.22));
    frontRows.forEach((row, i) => place(row, zOfFront(i), -0.12));

    // ---- the desk ----
    const deskWidth = widest + 0.9;
    const zMin = zOfBack(backRows.length - 1) - 0.45;
    const zMax = zOfFront(Math.max(0, frontRows.length - 1)) + 0.4;
    const deskDepth = zMax - zMin;
    shade(makeDesk(deskWidth, deskDepth, (zMin + zMax) / 2));
    paint();

    // ---- pointing and choosing ----
    sources.forEach((source) => {
      const device = nodes.get(source);
      if (!device) {
        return;
      }
      const state = source.worst
        ? `${number(source.items)} open change ${source.items === 1 ? "item" : "items"}, worst ${source.worst}`
        : UNHEALTHY.has(source.health)
          ? `nothing open; the source is ${source.health}`
          : source.health === "open"
            ? "no check yet"
            : "nothing open";
      const rest = device.position.y;
      pickable(device, {
        label: `${source.name}: ${state}. Select it to open the source.`,
        href: source.href,
        element: source.element,
        hover(on) {
          device.position.y = on ? rest + 0.03 : rest;
        },
      });
    });

    return {
      floor: false,
      // the camera fits the devices, not the whole desk (its edge may leave the frame)
      extent: { wide: widest + 0.3, deep: deskDepth * 0.8, tall: tallest, x: 0, y: 0.2, z: (zMin + zMax) / 2 },
      home: { yaw: -0.08, pitch: 0.42 },
      hint: "Point at a device to read its source; select it to open the source.",
      info: () => ({ sources: sources.length, devices: nodes.size, lit: sources.filter((s) => s.worst).length }),
      recolour: paint,
    };
  },
};

// --- the change replay of a source page --------------------------------------------------------

// The source's own device on a desk; the resource types that changed on the replay's day rise out
// of it as cards with a stripe in the colour of their worst item, and the device's status lights
// show the day's worst change. The scene follows the heat map's day cursor through its x
// attribute, so the replay's controls move it with no other wiring.
const CARD_RISE_MS = 380;

const REPLAY = {
  studio: true,
  fov: 30,
  addons: ["RoundedBoxGeometry", "RoomEnvironment", "GLTFLoader"],
  models: (data) => [MODEL_OF[kindOf(data.type)]],

  // the cells of the heat map, the day cursor, and the source the page is about
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
    section.querySelectorAll(".replay-cell").forEach((cell) => {
      const day = Number(cell.getAttribute("data-day-index"));
      const counts = (cell.getAttribute("data-counts") || "").split(" ").map(Number);
      if (!Number.isInteger(day) || counts.length !== 4 || counts.some((n) => !(n >= 0))) {
        return;
      }
      const total = counts.reduce((a, b) => a + b, 0);
      if (!total) {
        return;
      }
      const title = cell.querySelector("title");
      let worst = "";
      counts.forEach((n, s) => {
        if (n) {
          worst = RANK[s];
        }
      });
      cells.push({
        day,
        row: Number(cell.getAttribute("data-row")) || 0,
        total,
        worst,
        element: cell,
        href: localPath(cell.getAttribute("href")),
        label: title ? title.textContent.trim() : cell.getAttribute("data-label") || "",
      });
    });
    return {
      cells,
      days,
      pitch,
      cursor,
      type: section.getAttribute("data-source-type") || "",
      view: map,
    };
  },

  elementOf(target) {
    return target.closest ? target.closest(".replay-cell") : null;
  },

  build(kit) {
    const { THREE, scene, pickable, data } = kit;
    const w = workshop(kit);
    const { mat, rbox, block, m } = w;

    // the device, lit as busy while the shown day has changes
    const device = w.deviceFor({ type: data.type, worst: "", items: 0, index: 0 });
    // a close-up: every kind of device stands at about the same size (a Pi as large as a rack)
    const size = new THREE.Box3().setFromObject(device).getSize(new THREE.Vector3());
    device.scale.setScalar(0.7 / Math.max(size.x, size.y, size.z));
    scene.add(device);
    const deviceBox = new THREE.Box3().setFromObject(device);
    const deviceTop = deviceBox.max.y;
    // Where the cards' lines end: the middle of the device's top front edge, a fixed point of the
    // room. At the top's centre they seemed to meet in the air above a deep rack, whose dark top
    // hides behind its front edge (Ruben, 15 November 2026, on DELTA).
    const anchor = new THREE.Vector3(0, deviceTop + 0.003, deviceBox.max.z - 0.01);
    w.shade(w.makeDesk(2.8, 1.7, 0.05));
    w.paint();
    const rest = device.position.y;
    pickable(device, {
      label: "",
      href: "",
      element: null,
      hover(on) {
        device.position.y = on ? rest + 0.02 : rest;
      },
    });
    const deviceNode = device.userData.node;

    // the cards of the shown day, in a deck that turns to the viewer as a whole
    const deck = new THREE.Group();
    scene.add(deck);
    kit.billboard(deck);
    const cardFace = m({ roughness: 0.55 });
    const cardLine = m({ roughness: 0.8 });
    function paintCards() {
      const dark = prefersDark();
      cardFace.color.setHex(dark ? 0x2a2b33 : 0xffffff);
      cardLine.color.setHex(dark ? 0x6b6f7a : 0xb8bcc4);
    }
    paintCards();
    let cards = [];
    let rise = null;
    let shown = -1;

    // the distance between two cards' centres: a card and its shape, closer when there are many
    function cardStep(n) {
      return n > 1 ? Math.min(0.42, 2.4 / (n - 1)) : 0;
    }

    function clearDeck() {
      cards.forEach((card) => {
        kit.unpickable(card.group);
        card.group.traverse((part) => {
          if (part.geometry) {
            part.geometry.dispose();
          }
          if (part.material && part.material !== cardFace && part.material !== cardLine && !Object.values(mat).includes(part.material)) {
            part.material.dispose();
          }
        });
        deck.remove(card.group);
      });
      cards = [];
    }

    function card(cell, x, y, size) {
      const g = new THREE.Group();
      const width = 0.3 * size;
      const height = 0.18 * size;
      const face = rbox(width, height, 0.012, 0.01, cardFace);
      const colour = w.tokenColour(cell.worst);
      const stripe = block(width * 0.92, 0.012 * size, 0.014, m({ color: colour, emissive: colour, emissiveIntensity: 0.25 }));
      stripe.position.set(0, height / 2 - 0.022 * size, 0.002);
      g.add(face, stripe);
      for (let i = 0; i < 3; i += 1) {
        const bar = block(width * (i ? 0.45 : 0.62), 0.01 * size, 0.014, cardLine);
        bar.position.set(-width * 0.12 + (i ? -0.04 * size : 0), height / 2 - 0.06 * size - i * 0.032 * size, 0.002);
        g.add(bar);
      }
      // a dashed line down to the device; its lower end is set before every frame, in the card's
      // own frame, from the fixed anchor: the deck turns with the view and the cards rise and grow
      const line = new THREE.Line(
        new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0, -height / 2, 0), new THREE.Vector3(-x, deviceTop - y, 0)]),
        new THREE.LineDashedMaterial({ color: colour, dashSize: 0.012, gapSize: 0.01 })
      );
      line.computeLineDistances();
      line.frustumCulled = false;
      const start = new THREE.Vector3(0, -height / 2, 0);
      const end = new THREE.Vector3();
      line.onBeforeRender = () => {
        g.worldToLocal(end.copy(anchor));
        const points = line.geometry.attributes.position;
        if (points.getX(1) !== end.x || points.getY(1) !== end.y || points.getZ(1) !== end.z) {
          points.setXYZ(1, end.x, end.y, end.z);
          points.needsUpdate = true;
          // the dash pattern runs along the line's new length (in place: no new buffer a frame)
          const distances = line.geometry.attributes.lineDistance;
          distances.setX(1, start.distanceTo(end));
          distances.needsUpdate = true;
        }
      };
      g.add(line);
      g.position.set(x, y, 0);
      deck.add(g);
      const lift = g.position.y;
      pickable(g, {
        label: cell.label + ". Select it to open those changes.",
        href: cell.href,
        element: cell.element,
        hover(on) {
          g.position.y = on ? lift + 0.02 : lift;
        },
      });
      g.traverse((part) => {
        if (part.isMesh) {
          part.castShadow = true;
        }
      });
      return { group: g, x, y };
    }

    // The day's cards in an arc over the device, the worst first in the middle, a little larger
    // with more items.
    function showDay(day) {
      clearDeck();
      shown = day;
      const ofDay = data.cells
        .filter((cell) => cell.day === day)
        .sort((a, b) => RANK.indexOf(b.worst) - RANK.indexOf(a.worst) || b.total - a.total);
      const n = ofDay.length;
      // side by side, a card and its shape apart (closer when many), the worst in the middle
      const step = cardStep(n);
      const places = Array.from({ length: n }, (_, k) => (k - (n - 1) / 2) * step).sort((a, b) => Math.abs(a) - Math.abs(b) || a - b);
      const outer = Math.max(step, ((n - 1) / 2) * step);
      ofDay.forEach((cell, i) => {
        const x = places[i];
        const y = deviceTop + 0.32 + 0.18 * (1 - Math.abs(x) / outer) + (i % 2) * 0.05;
        const size = 0.85 + Math.min(0.45, Math.log2(1 + cell.total) * 0.08);
        cards.push(card(cell, x, y, size));
      });
      // the device's lights show the day's worst change, green on a quiet day
      w.light(device, { worst: ofDay.length ? ofDay[0].worst : "", health: "ok" });
      // the device's own words for the day
      const items = ofDay.reduce((sum, cell) => sum + cell.total, 0);
      deviceNode.label = items
        ? `This source on the replay's day: ${number(items)} change ${items === 1 ? "item" : "items"} in ${n} resource ${n === 1 ? "type" : "types"}.`
        : "This source on the replay's day: no change items.";
      // the cards rise out of the device, unless motion is reduced
      if (!kit.reducedMotion() && cards.length) {
        rise = { start: performance.now() };
        cards.forEach((c) => {
          c.group.position.y = deviceTop;
          c.group.scale.setScalar(0.2);
        });
      } else {
        rise = null;
      }
      kit.invalidate();
    }

    kit.animate(() => {
      if (!rise) {
        return false;
      }
      const t = Math.min(1, (performance.now() - rise.start) / CARD_RISE_MS);
      const e = 1 - (1 - t) * (1 - t);
      cards.forEach((c) => {
        c.group.position.y = deviceTop + (c.y - deviceTop) * e;
        c.group.scale.setScalar(0.2 + 0.8 * e);
      });
      if (t >= 1) {
        rise = null;
      }
      return true;
    });

    const perDay = new Map();
    data.cells.forEach((cell) => perDay.set(cell.day, (perDay.get(cell.day) || 0) + 1));
    const most = Math.max(1, ...perDay.values());
    const widestDeck = Math.max(1.0, (most - 1) * cardStep(most) + 0.75);

    function follow() {
      const x = Number(data.cursor.getAttribute("x"));
      const day = Math.max(0, Math.min(data.days - 1, Math.round(x / data.pitch)));
      if (day !== shown) {
        showDay(day);
      }
    }
    const watch = new MutationObserver(follow);
    watch.observe(data.cursor, { attributes: true, attributeFilter: ["x"] });
    follow();

    return {
      floor: false,
      // the camera fits the widest day's cards and the device
      extent: { wide: widestDeck + 0.5, deep: 0.8, tall: deviceTop + 0.75, x: 0, y: deviceTop * 0.5 + 0.28, z: 0 },
      home: { yaw: -0.18, pitch: 0.3 },
      hint: "The cards are the resource types that changed on the day of the replay. Point at one to read it; select it to open those changes.",
      info: () => ({ cells: data.cells.length, days: data.days, day: shown, cards: cards.length, type: data.type }),
      recolour() {
        w.paint();
        paintCards();
      },
      dispose() {
        watch.disconnect();
        clearDeck();
      },
    };
  },
};

const SCENES = { lab: LAB, replay: REPLAY };

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
    if (!library || !options.addons) {
      try {
        library = library || (await import(THREE_URL));
        // each add-on module exports the class of its name
        const names = spec.addons || [];
        const modules = await Promise.all(names.map((name) => import(ADDON_URLS[name])));
        options.addons = Object.fromEntries(names.map((name, i) => [name, modules[i][name]]));
      } catch (error) {
        say(WORDS.noModule);
        return;
      }
    }
    if (!options.models && spec.models) {
      // the models of the devices on this page; one that fails to load stands as a plain box
      const loader = new options.addons.GLTFLoader();
      const names = spec.models(data);
      const loaded = await Promise.all(names.map((name) => loader.loadAsync(modelUrl(name)).catch(() => null)));
      options.models = new Map(names.map((name, i) => [name, loaded[i] && loaded[i].scene]).filter(([, model]) => model));
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
