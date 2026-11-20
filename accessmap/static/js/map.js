/* AccessMap threat map — Leaflet + /api/events.
   Draws source -> destination arcs coloured by threat level,
   renders the recent-visits table, and polls for live updates. */
(function () {
  "use strict";

  var THREAT_COLORS = {
    critical: "#ef4444", high: "#f97316", medium: "#facc15",
    low: "#38bdf8", unknown: "#94a3b8"
  };
  var POLL_MS = 15000;

  var map = L.map("map", { worldCopyJump: true }).setView([20, 10], 2);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "&copy; OpenStreetMap contributors",
    maxZoom: 18
  }).addTo(map);

  var arcLayer = L.layerGroup().addTo(map);
  var markerLayer = L.layerGroup().addTo(map);

  function esc(value) {
    var div = document.createElement("div");
    div.textContent = value == null ? "" : String(value);
    return div.innerHTML;
  }

  function colorFor(threat) {
    return THREAT_COLORS[threat] || THREAT_COLORS.unknown;
  }

  function popupFor(e) {
    return "<b>" + esc(e.dst_domain || e.dst_ip) + "</b><br>" +
      esc(e.src_ip) + " (" + esc(e.src_city) + ", " + esc(e.src_country) + ") → " +
      esc(e.dst_ip) + " (" + esc(e.dst_city) + ", " + esc(e.dst_country) + ")<br>" +
      "Port " + esc(e.dst_port) + " · " + esc(e.action || "—") +
      " · threat: <b>" + esc(e.threat) + "</b> (" + esc(e.threat_score) + ")";
  }

  function drawEvents(events) {
    arcLayer.clearLayers();
    markerLayer.clearLayers();
    events.forEach(function (e) {
      if (!e.src_lat || !e.dst_lat) return;
      var src = [e.src_lat, e.src_lon];
      var dst = [e.dst_lat, e.dst_lon];
      var color = colorFor(e.threat);
      L.polyline([src, dst], {
        color: color, weight: e.threat === "critical" || e.threat === "high" ? 3 : 2,
        opacity: 0.75
      }).addTo(arcLayer).bindPopup(popupFor(e));
      L.circleMarker(src, { radius: 4, color: color, fillColor: color, fillOpacity: 0.9 })
        .addTo(markerLayer).bindPopup("<b>Source</b><br>" + esc(e.src_ip) + "<br>" +
          esc(e.src_city) + ", " + esc(e.src_country));
      L.circleMarker(dst, { radius: 5, color: color, fillColor: color, fillOpacity: 0.9 })
        .addTo(markerLayer).bindPopup("<b>Destination</b><br>" + esc(e.dst_ip) + "<br>" +
          esc(e.dst_city) + ", " + esc(e.dst_country));
    });
    renderTable(events);
  }

  function renderTable(events) {
    var tbody = document.querySelector("#events-table tbody");
    if (!events.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="muted">No events yet. Enroll a firewall or run the demo seeder.</td></tr>';
      return;
    }
    tbody.innerHTML = events.slice(0, 25).map(function (e) {
      return "<tr><td>" + esc(e.ts) + "</td>" +
        "<td>" + esc(e.src_ip) + "<br><span class='muted'>" + esc(e.src_city) + ", " + esc(e.src_country) + "</span></td>" +
        "<td>" + esc(e.dst_ip) + "<br><span class='muted'>" + esc(e.dst_city) + ", " + esc(e.dst_country) + "</span></td>" +
        "<td>" + esc(e.dst_domain || "—") + "</td>" +
        "<td>" + esc(e.dst_port) + "</td>" +
        "<td>" + esc(e.action || "—") + "</td>" +
        "<td><span class='badge badge-" + esc(e.threat) + "'>" + esc(e.threat) + "</span></td></tr>";
    }).join("");
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
      select.innerHTML = '<option value="">All firewalls</option>' + list.map(function (f) {
        return '<option value="' + f.id + '">' + esc(f.name) + " (" + esc(f.vendor) + ")</option>";
      }).join("");
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
        if (g.lat || g.lon) {
          map.setView([g.lat, g.lon], 4);
          L.marker([g.lat, g.lon]).addTo(map)
            .bindPopup("<b>" + esc(g.ip) + "</b><br>" + esc(g.city) + ", " + esc(g.country) +
              "<br><span class='muted'>" + esc(g.isp) + " · via " + esc(g.source) + "</span>")
            .openPopup();
        }
      })
      .catch(function () { /* offline */ });
  });

  refreshAll();
  setInterval(refreshAll, POLL_MS);
})();
