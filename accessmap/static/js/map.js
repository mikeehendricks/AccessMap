/* AccessMap threat map — self-hosted Leaflet + built-in Natural Earth world map.
   Renders a FortiGuard-style dark vector world map out of the box (no external
   CDN or tile server required), optional online CARTO/OSM basemaps, curved
   source -> destination threat arcs, live stats, and the recent-visits table. */
(function () {
  "use strict";

  var THREAT_COLORS = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#facc15",
    low: "#38bdf8",
    unknown: "#94a3b8"
  };
  var POLL_MS = 15000;

  var map = L.map("map", {
    worldCopyJump: true,
    minZoom: 1.5,
    maxZoom: 18,
    maxBounds: [[-85, -195], [85, 195]],
    maxBoundsViscosity: 0.85
  }).setView([18, 15], 2);

  // Explicit panes keep graticule < world land < tiles/arcs < markers.
  map.createPane("graticulePane");
  map.getPane("graticulePane").style.zIndex = "205";
  map.getPane("graticulePane").style.pointerEvents = "none";

  map.createPane("worldPane");
  map.getPane("worldPane").style.zIndex = "215";

  map.createPane("threatArcs");
  map.getPane("threatArcs").style.zIndex = "450";

  map.createPane("threatMarkers");
  map.getPane("threatMarkers").style.zIndex = "460";

  // --- Built-in SOC vector world map (works 100% offline & online) ---
  var socWorldGroup = L.layerGroup();

  function buildGraticule() {
    var lines = L.layerGroup();
    for (var lon = -180; lon <= 180; lon += 30) {
      L.polyline([[-85, lon], [85, lon]], {
        pane: "graticulePane",
        color: lon === 0 ? "#182c4d" : "#101f38",
        weight: 1,
        interactive: false
      }).addTo(lines);
    }
    for (var lat = -60; lat <= 60; lat += 30) {
      L.polyline([[lat, -180], [lat, 180]], {
        pane: "graticulePane",
        color: lat === 0 ? "#1b3358" : "#101f38",
        weight: lat === 0 ? 1.2 : 1,
        dashArray: lat === 0 ? "4 4" : null,
        interactive: false
      }).addTo(lines);
    }
    return lines;
  }

  var graticuleLayer = buildGraticule();
  graticuleLayer.addTo(socWorldGroup);

  var countryStyle = {
    pane: "worldPane",
    fillColor: "#172946",
    fillOpacity: 0.96,
    color: "#2f4d7d",
    weight: 0.9,
    opacity: 0.95
  };

  fetch("/static/vendor/world-countries.geojson")
    .then(function (r) { return r.json(); })
    .then(function (geojson) {
      var geoLayer = L.geoJSON(geojson, {
        pane: "worldPane",
        style: function () { return countryStyle; },
        onEachFeature: function (feature, layer) {
          var name = feature.properties && feature.properties.name;
          if (name) {
            layer.bindTooltip(name, {
              sticky: true,
              direction: "top",
              className: "country-tooltip"
            });
          }
          layer.on("mouseover", function () {
            layer.setStyle({ fillColor: "#213b66", color: "#4b74b2", weight: 1.2 });
          });
          layer.on("mouseout", function () {
            geoLayer.resetStyle(layer);
          });
        }
      });
      geoLayer.addTo(socWorldGroup);
    })
    .catch(function () {
      /* Even if GeoJSON fetch fails, graticule + optional tiles remain active */
    });

  socWorldGroup.addTo(map);

  // Optional online raster tile layers (user-selectable via top-right control).
  var cartoDark = L.tileLayer(
    "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
    {
      attribution: "&copy; OpenStreetMap contributors &copy; CARTO",
      subdomains: "abcd",
      maxZoom: 18
    }
  );
  var osmStreets = L.tileLayer(
    "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
    {
      attribution: "&copy; OpenStreetMap contributors",
      maxZoom: 18
    }
  );

  L.control.layers(
    {
      "SOC Vector World (Built-in)": socWorldGroup,
      "CARTO Dark Matter (Online)": cartoDark,
      "OpenStreetMap (Online)": osmStreets
    },
    null,
    { position: "topright" }
  ).addTo(map);

  var arcLayer = L.layerGroup().addTo(map);
  var markerLayer = L.layerGroup().addTo(map);
  var searchLayer = L.layerGroup().addTo(map);

  function text(value) {
    return document.createTextNode(value == null ? "" : String(value));
  }

  function el(tag, className, content) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (content !== undefined) {
      node.textContent = content == null ? "" : String(content);
    }
    return node;
  }

  function safeThreat(threat) {
    var key = threat == null ? "" : String(threat);
    return Object.prototype.hasOwnProperty.call(THREAT_COLORS, key) ? key : "unknown";
  }

  function colorFor(threat) {
    return THREAT_COLORS[safeThreat(threat)];
  }

  function popupFor(e) {
    var level = safeThreat(e.threat);
    var wrap = document.createElement("div");
    wrap.appendChild(el("b", null, e.dst_domain || e.dst_ip));
    wrap.appendChild(document.createElement("br"));
    wrap.appendChild(text(
      (e.src_ip || "") + " (" + (e.src_city || "") + ", " + (e.src_country || "") + ") → " +
      (e.dst_ip || "") + " (" + (e.dst_city || "") + ", " + (e.dst_country || "") + ")"
    ));
    wrap.appendChild(document.createElement("br"));
    wrap.appendChild(text(
      "Port " + (e.dst_port == null ? "" : e.dst_port) + " · " + (e.action || "—") + " · threat: "
    ));
    wrap.appendChild(el("b", null, level));
    wrap.appendChild(text(" (" + (e.threat_score == null ? 0 : e.threat_score) + ")"));
    return wrap;
  }

  function sourcePopupFor(e) {
    var wrap = document.createElement("div");
    wrap.appendChild(el("b", null, "Source"));
    wrap.appendChild(document.createElement("br"));
    wrap.appendChild(text(e.src_ip));
    wrap.appendChild(document.createElement("br"));
    wrap.appendChild(text((e.src_city || "") + ", " + (e.src_country || "")));
    return wrap;
  }

  function destPopupFor(e) {
    var wrap = document.createElement("div");
    wrap.appendChild(el("b", null, "Destination"));
    wrap.appendChild(document.createElement("br"));
    wrap.appendChild(text(e.dst_domain || e.dst_ip));
    wrap.appendChild(document.createElement("br"));
    wrap.appendChild(text(
      (e.dst_ip || "") + " · " + (e.dst_city || "") + ", " + (e.dst_country || "")
    ));
    return wrap;
  }

  function geoPopupFor(g) {
    var wrap = document.createElement("div");
    wrap.appendChild(el("b", null, g.ip));
    wrap.appendChild(document.createElement("br"));
    wrap.appendChild(text((g.city || "") + ", " + (g.country || "")));
    wrap.appendChild(document.createElement("br"));
    wrap.appendChild(el("span", "muted", (g.isp || "") + " · via " + (g.source || "")));
    return wrap;
  }

  function buildCurvedArc(src, dst) {
    var lat1 = src[0], lon1 = src[1];
    var lat2 = dst[0], lon2 = dst[1];
    var dLon = lon2 - lon1;
    var dLat = lat2 - lat1;
    var span = Math.sqrt(dLon * dLon + dLat * dLat);
    if (span < 0.5) {
      return [src, dst];
    }
    var lift = Math.min(28, Math.max(6, span * 0.22));
    var midLat = Math.min(82, (lat1 + lat2) / 2 + lift);
    var midLon = (lon1 + lon2) / 2;
    var pts = [];
    var steps = 36;
    for (var i = 0; i <= steps; i++) {
      var t = i / steps;
      var u = 1 - t;
      var lat = u * u * lat1 + 2 * u * t * midLat + t * t * lat2;
      var lon = u * u * lon1 + 2 * u * t * midLon + t * t * lon2;
      pts.push([lat, lon]);
    }
    return pts;
  }

  function drawEvents(events) {
    arcLayer.clearLayers();
    markerLayer.clearLayers();
    events.forEach(function (e) {
      if (e.src_lat == null || e.src_lon == null || e.dst_lat == null || e.dst_lon == null) {
        return;
      }
      var src = [Number(e.src_lat), Number(e.src_lon)];
      var dst = [Number(e.dst_lat), Number(e.dst_lon)];
      var level = safeThreat(e.threat);
      var color = colorFor(level);
      var isHigh = level === "critical" || level === "high";
      var curve = buildCurvedArc(src, dst);

      // Subtle outer glow + crisp inner trajectory arc
      L.polyline(curve, {
        pane: "threatArcs",
        color: color,
        weight: isHigh ? 6 : 4.5,
        opacity: 0.18,
        interactive: false
      }).addTo(arcLayer);

      L.polyline(curve, {
        pane: "threatArcs",
        color: color,
        weight: isHigh ? 2.6 : 1.9,
        opacity: 0.88
      }).addTo(arcLayer).bindPopup(function () { return popupFor(e); });

      L.circleMarker(src, {
        pane: "threatMarkers",
        radius: 4,
        color: "#e6edf7",
        weight: 1.2,
        fillColor: color,
        fillOpacity: 0.9
      }).addTo(markerLayer).bindPopup(function () { return sourcePopupFor(e); });

      L.circleMarker(dst, {
        pane: "threatMarkers",
        radius: isHigh ? 6 : 5,
        color: color,
        weight: 2,
        fillColor: color,
        fillOpacity: 0.92
      }).addTo(markerLayer).bindPopup(function () { return destPopupFor(e); });
    });
    renderTable(events);
  }

  function buildHostCell(ip, city, country) {
    var td = document.createElement("td");
    td.appendChild(text(ip));
    td.appendChild(document.createElement("br"));
    td.appendChild(el("span", "muted", (city || "") + ", " + (country || "")));
    return td;
  }

  function renderTable(events) {
    var tbody = document.querySelector("#events-table tbody");
    if (!events.length) {
      var emptyRow = document.createElement("tr");
      var emptyCell = el("td", "muted", "No events yet. Enroll a firewall or run the demo seeder.");
      emptyCell.colSpan = 7;
      emptyRow.appendChild(emptyCell);
      tbody.replaceChildren(emptyRow);
      return;
    }
    var rows = events.slice(0, 25).map(function (e) {
      var tr = document.createElement("tr");
      var level = safeThreat(e.threat);
      tr.appendChild(el("td", null, e.ts));
      tr.appendChild(buildHostCell(e.src_ip, e.src_city, e.src_country));
      tr.appendChild(buildHostCell(e.dst_ip, e.dst_city, e.dst_country));
      tr.appendChild(el("td", null, e.dst_domain || "—"));
      tr.appendChild(el("td", null, e.dst_port));
      tr.appendChild(el("td", null, e.action || "—"));
      var badgeTd = document.createElement("td");
      badgeTd.appendChild(el("span", "badge badge-" + level, level));
      tr.appendChild(badgeTd);
      return tr;
    });
    tbody.replaceChildren.apply(tbody, rows);
  }

  function loadStats() {
    return fetch("/api/stats").then(function (r) { return r.json(); }).then(function (s) {
      document.getElementById("stat-events").textContent = s.total_events;
      document.getElementById("stat-threats").textContent = s.threat_events;
      document.getElementById("stat-countries").textContent = s.destination_countries;
      document.getElementById("stat-firewalls").textContent = s.firewalls;
    }).catch(function () { /* offline: keep last values */ });
  }

  function loadFirewalls() {
    return fetch("/api/firewalls").then(function (r) { return r.json(); }).then(function (list) {
      var select = document.getElementById("filter-firewall");
      var current = select.value;
      var options = [new Option("All firewalls", "")].concat(list.map(function (f) {
        return new Option(
          String(f.name == null ? "" : f.name) + " (" + String(f.vendor == null ? "" : f.vendor) + ")",
          String(f.id == null ? "" : f.id)
        );
      }));
      select.replaceChildren.apply(select, options);
      select.value = current;
    }).catch(function () { /* offline */ });
  }

  function loadEvents() {
    var params = new URLSearchParams({ limit: "100" });
    var fw = document.getElementById("filter-firewall").value;
    var threat = document.getElementById("filter-threat").value;
    if (fw) params.set("firewall_id", fw);
    if (threat) params.set("threat", threat);
    return fetch("/api/events?" + params.toString())
      .then(function (r) { return r.json(); })
      .then(function (events) {
        drawEvents(events);
        document.getElementById("last-updated").textContent =
          "Updated " + new Date().toLocaleTimeString();
      })
      .catch(function () {
        document.getElementById("last-updated").textContent = "Could not reach the API.";
      });
  }

  function refreshAll() {
    return loadFirewalls().then(loadEvents).then(loadStats);
  }

  document.getElementById("refresh-btn").addEventListener("click", refreshAll);
  document.getElementById("filter-firewall").addEventListener("change", loadEvents);
  document.getElementById("filter-threat").addEventListener("change", loadEvents);
  document.getElementById("ip-search-btn").addEventListener("click", function () {
    var ip = document.getElementById("ip-search").value.trim();
    if (!ip) return;
    fetch("/api/geo?ip=" + encodeURIComponent(ip))
      .then(function (r) { return r.json(); })
      .then(function (g) {
        if (g.lat != null && g.lon != null) {
          searchLayer.clearLayers();
          map.setView([g.lat, g.lon], 4);
          L.circleMarker([g.lat, g.lon], {
            pane: "threatMarkers",
            radius: 8,
            color: "#38bdf8",
            weight: 2,
            fillColor: "#38bdf8",
            fillOpacity: 0.85
          }).addTo(searchLayer)
            .bindPopup(function () { return geoPopupFor(g); })
            .openPopup();
        }
      })
      .catch(function () { /* offline */ });
  });

  refreshAll();
  setInterval(refreshAll, POLL_MS);
})();
