/* The Change Replay controls of the source page (UI revision WP4c, THE-1197).

   The page works without this file: the heat map, its links, the day panel and the table are
   drawn by the server (sources/_replay.html). This file adds the replay on top: it shows the
   controls, moves the day cursor (play, pause, previous and next day, the slider), dims the
   days after the cursor, rewrites the day panel from the cells of the chosen day and keeps one
   tab stop in the map, with the arrow keys moving between cells. It reads only the data
   attributes of the drawing, fetches nothing and writes no style attribute (the content security
   policy blocks them): the cursor moves through its x attribute.

   Motion: the cursor jumps, it never slides. Play advances one day every 700 ms and stops on the
   last day; with prefers-reduced-motion it is not offered, and the replay moves only on a step.
   It pauses when the map leaves the screen or the tab is hidden, and on any other control. */
(function () {
  "use strict";

  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  var STEP_MS = 700;
  var SEVERITIES = ["low", "medium", "high", "critical"];

  function formatNumber(value) {
    return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }

  function itemsText(count) {
    return formatNumber(count) + " change " + (count === 1 ? "item" : "items");
  }

  function dayOf(first, index) {
    var parts = first.split("-");
    return new Date(Date.UTC(Number(parts[0]), Number(parts[1]) - 1, Number(parts[2]) + index));
  }

  function isoDay(day) {
    return day.toISOString().slice(0, 10);
  }

  function shortLabel(day) {
    return day.getUTCDate() + " " + MONTHS[day.getUTCMonth()];
  }

  function longLabel(day) {
    return shortLabel(day) + " " + day.getUTCFullYear();
  }

  function start(section) {
    var first = section.getAttribute("data-first-day");
    var days = Number(section.getAttribute("data-days"));
    var pitch = Number(section.getAttribute("data-pitch"));
    var labelWidth = Number(section.getAttribute("data-label-width"));
    var source = section.getAttribute("data-source");
    var cursor = Number(section.getAttribute("data-cursor"));
    if (!first || !(days > 0) || !(pitch > 0)) {
      return;
    }
    var controls = section.querySelector("[data-replay-controls]");
    var keys = section.querySelector("[data-replay-keys]");
    var play = section.querySelector("[data-replay-play]");
    var scrub = section.querySelector("[data-replay-scrub]");
    var out = section.querySelector("[data-replay-out]");
    var reducedNote = section.querySelector("[data-replay-reduced]");
    var marker = section.querySelector("[data-replay-cursor]");
    var map = section.querySelector("[data-replay-map]");
    var panel = section.querySelector("#replay-day");
    var badges = section.querySelector("[data-replay-badges]");
    var cells = Array.prototype.slice.call(section.querySelectorAll(".replay-cell"));
    if (!controls || !play || !scrub || !marker || !map || !panel) {
      return;
    }

    // the cells of each row in day order, for the arrow keys
    var rows = [];
    cells.forEach(function (cell) {
      var row = Number(cell.getAttribute("data-row"));
      (rows[row] = rows[row] || []).push(cell);
    });
    rows = rows.filter(Boolean);
    rows.forEach(function (list) {
      list.sort(function (a, b) {
        return Number(a.getAttribute("data-day-index")) - Number(b.getAttribute("data-day-index"));
      });
    });

    var timer = null;
    var reduced = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
    var current = null; // the cell that holds the tab stop of the map

    function dayIndex(cell) {
      return Number(cell.getAttribute("data-day-index"));
    }

    function badge(severity, count) {
      var template = badges && badges.content.querySelector('[data-severity="' + severity + '"]');
      if (!template) {
        var plain = document.createElement("span");
        plain.textContent = formatNumber(count) + " " + severity;
        return plain;
      }
      var node = template.cloneNode(true);
      node.removeAttribute("data-severity");
      node.querySelector(".num").textContent = formatNumber(count);
      return node;
    }

    function renderPanel(index) {
      var day = dayOf(first, index);
      var title = panel.querySelector("[data-replay-day-title]");
      var total = panel.querySelector("[data-replay-day-total]");
      var list = panel.querySelector("[data-replay-day-list]");
      var link = panel.querySelector("[data-replay-day-link]");
      var ofDay = cells.filter(function (cell) {
        return dayIndex(cell) === index;
      });
      var sum = 0;
      list.textContent = "";
      ofDay.forEach(function (cell) {
        var counts = cell.getAttribute("data-counts").split(" ").map(Number);
        var count = counts.reduce(function (a, b) {
          return a + b;
        }, 0);
        sum += count;
        var item = document.createElement("li");
        var name = document.createElement("span");
        name.className = "replay-day__res";
        name.textContent = cell.getAttribute("data-label");
        var sevs = document.createElement("span");
        sevs.className = "replay-day__sevs";
        for (var s = SEVERITIES.length - 1; s >= 0; s -= 1) {
          if (counts[s]) {
            sevs.appendChild(badge(SEVERITIES[s], counts[s]));
          }
        }
        var n = document.createElement("span");
        n.className = "replay-day__n num";
        n.textContent = formatNumber(count);
        item.appendChild(name);
        item.appendChild(sevs);
        item.appendChild(n);
        list.appendChild(item);
      });
      title.textContent = longLabel(day);
      total.textContent = sum
        ? itemsText(sum) + " in " + ofDay.length + " resource " + (ofDay.length === 1 ? "type" : "types")
        : "No change items on this day.";
      var iso = isoDay(day);
      var query = new URLSearchParams({ source: source, sort: "oldest", from: iso, to: iso, muted: "1" });
      link.setAttribute("href", "/changes?" + query.toString());
      link.textContent = "Open the changes of " + shortLabel(day);
    }

    function setCursor(index) {
      var next = Math.max(0, Math.min(days - 1, index));
      cursor = next;
      var day = dayOf(first, next);
      marker.setAttribute("x", String(labelWidth + next * pitch));
      scrub.value = String(next);
      scrub.setAttribute("aria-valuetext", longLabel(day));
      if (out) {
        out.textContent = shortLabel(day);
      }
      cells.forEach(function (cell) {
        cell.classList.toggle("is-after", dayIndex(cell) > next);
      });
      renderPanel(next);
    }

    function playing() {
      return timer !== null;
    }

    function pause() {
      if (timer !== null) {
        window.clearInterval(timer);
        timer = null;
      }
      play.setAttribute("aria-pressed", "false");
      play.textContent = "Play";
      panel.setAttribute("aria-live", "polite");
    }

    function resume() {
      if (reduced && reduced.matches) {
        return;
      }
      if (cursor >= days - 1) {
        setCursor(0);
      }
      // while the days run, the panel is not read out on every step; it is again on pause
      panel.setAttribute("aria-live", "off");
      play.setAttribute("aria-pressed", "true");
      play.textContent = "Pause";
      timer = window.setInterval(function () {
        if (cursor >= days - 1) {
          pause();
          return;
        }
        setCursor(cursor + 1);
        if (cursor >= days - 1) {
          pause();
        }
      }, STEP_MS);
    }

    function applyMotion() {
      var still = !!(reduced && reduced.matches);
      if (still) {
        pause();
      }
      play.hidden = still;
      if (reducedNote) {
        reducedNote.hidden = !still;
      }
    }

    // ---- the one tab stop of the map ----------------------------------------------------
    function holdStop(cell) {
      if (current && current !== cell) {
        current.setAttribute("tabindex", "-1");
      }
      current = cell;
      cell.setAttribute("tabindex", "0");
    }

    function nearest(list, index) {
      var best = list[0];
      list.forEach(function (cell) {
        if (Math.abs(dayIndex(cell) - index) < Math.abs(dayIndex(best) - index)) {
          best = cell;
        }
      });
      return best;
    }

    function moveFrom(cell, key) {
      var rowIndex = -1;
      rows.forEach(function (list, i) {
        if (list.indexOf(cell) !== -1) {
          rowIndex = i;
        }
      });
      if (rowIndex === -1) {
        return null;
      }
      var row = rows[rowIndex];
      var at = row.indexOf(cell);
      switch (key) {
        case "ArrowLeft":
          return row[at - 1] || null;
        case "ArrowRight":
          return row[at + 1] || null;
        case "Home":
          return row[0];
        case "End":
          return row[row.length - 1];
        case "ArrowUp":
          return rowIndex > 0 ? nearest(rows[rowIndex - 1], dayIndex(cell)) : null;
        case "ArrowDown":
          return rowIndex < rows.length - 1 ? nearest(rows[rowIndex + 1], dayIndex(cell)) : null;
        default:
          return null;
      }
    }

    cells.forEach(function (cell) {
      cell.setAttribute("tabindex", "-1");
      cell.addEventListener("focus", function () {
        pause();
        holdStop(cell);
        // the focused cell names its day and counts itself; the panel follows without speaking
        panel.setAttribute("aria-live", "off");
        setCursor(dayIndex(cell));
        window.setTimeout(function () {
          if (!playing()) {
            panel.setAttribute("aria-live", "polite");
          }
        }, 100);
      });
      cell.addEventListener("keydown", function (event) {
        var target = moveFrom(cell, event.key);
        if (event.key.indexOf("Arrow") === 0 || event.key === "Home" || event.key === "End") {
          event.preventDefault();
        }
        if (target) {
          target.focus();
        }
      });
    });
    var startCell = cells.filter(function (cell) {
      return dayIndex(cell) === cursor;
    })[0] || cells[0];
    if (startCell) {
      holdStop(startCell);
    }

    // ---- controls -----------------------------------------------------------------------
    play.addEventListener("click", function () {
      if (playing()) {
        pause();
      } else {
        resume();
      }
    });
    Array.prototype.forEach.call(section.querySelectorAll("[data-replay-step]"), function (button) {
      button.addEventListener("click", function () {
        pause();
        setCursor(cursor + Number(button.getAttribute("data-replay-step")));
      });
    });
    scrub.addEventListener("input", function () {
      pause();
      setCursor(Number(scrub.value));
    });
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        pause();
      }
    });
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) {
            pause();
          }
        });
      }).observe(map);
    }
    if (reduced) {
      if (reduced.addEventListener) {
        reduced.addEventListener("change", applyMotion);
      } else if (reduced.addListener) {
        reduced.addListener(applyMotion);
      }
    }

    // the server drew the cursor, the slider value and the panel of this same day
    applyMotion();
    controls.hidden = false;
    if (keys) {
      keys.hidden = false;
    }
  }

  function init() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-replay]"), start);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
