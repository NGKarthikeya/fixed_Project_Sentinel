/**
 * GeoTraceIntel Dashboard Application (Features 3.2 & 3.5)
 * Handles Leaflet.js map rendering, WebSocket live updates, REST API calls,
 * campaign cluster overlays, relay hop polylines, and dual-mode Rough Overview / Map Location navigation.
 */

document.addEventListener("DOMContentLoaded", () => {
    // Application State
    let map = null;
    let hopMarkersLayerGroup = null;
    let hopPolylineLayerGroup = null;
    let clusterLayerGroup = null;
    let markerByHopIndex = {};
    let currentTraceData = null;
    let socket = null;
    let emails = [];
    let currentEmailId = null;
    let showClusters = true;
    let currentView = "rough"; // Default: Rough view first

    // Core Stage Elements
    const tabRoughView = document.getElementById("tabRoughView");
    const tabMapView = document.getElementById("tabMapView");
    const roughOverviewContainer = document.getElementById("roughOverviewContainer");
    const leafletMapContainer = document.getElementById("leafletMapContainer");
    const hopQuickNav = document.getElementById("hopQuickNav");

    // Sidebar & Feed DOM Elements
    const emailListEl = document.getElementById("emailList");
    const emailCountEl = document.getElementById("emailCount");
    const feedLogEl = document.getElementById("feedLog");
    const wsStatusEl = document.getElementById("wsStatus");
    const chkShowClusters = document.getElementById("chkShowClusters");
    const btnFitMap = document.getElementById("btnFitMap");

    // Header Overlay DOM Elements
    const activeEmailIdEl = document.getElementById("activeEmailId");
    const activeSubjectEl = document.getElementById("activeSubject");
    const activeSenderEl = document.getElementById("activeSender");
    const activeCoordsTagEl = document.getElementById("activeCoordsTag");

    // Rough Overview DOM Elements
    const roughOriginIp = document.getElementById("roughOriginIp");
    const roughOriginLoc = document.getElementById("roughOriginLoc");
    const roughOriginLat = document.getElementById("roughOriginLat");
    const roughOriginLon = document.getElementById("roughOriginLon");
    const roughOriginBadge = document.getElementById("roughOriginBadge");
    const roughOriginIsp = document.getElementById("roughOriginIsp");
    const roughOriginAsn = document.getElementById("roughOriginAsn");
    const roughThreatFlags = document.getElementById("roughThreatFlags");
    const roughConfidencePill = document.getElementById("roughConfidencePill");
    const roughConfidenceBar = document.getElementById("roughConfidenceBar");
    const roughTotalHops = document.getElementById("roughTotalHops");
    const roughCampaignCluster = document.getElementById("roughCampaignCluster");
    const roughHopsTableBody = document.getElementById("roughHopsTableBody");
    const btnRoughViewOriginMap = document.getElementById("btnRoughViewOriginMap");

    // Right Inspector DOM Elements
    const confidencePillEl = document.getElementById("confidencePill");
    const originIpEl = document.getElementById("originIp");
    const originLocationEl = document.getElementById("originLocation");
    const originCoordsDisplayEl = document.getElementById("originCoordsDisplay");
    const btnLocateOriginInspector = document.getElementById("btnLocateOriginInspector");
    const originIspEl = document.getElementById("originIsp");
    const threatFlagsEl = document.getElementById("threatFlags");
    const timelineContainerEl = document.getElementById("timelineContainer");

    // Modal DOM Elements
    const modalAnalyze = document.getElementById("modalAnalyze");
    const btnAnalyzeModal = document.getElementById("btnAnalyzeModal");
    const btnCloseModal = document.getElementById("btnCloseModal");
    const btnCancelModal = document.getElementById("btnCancelModal");
    const btnSubmitAnalyze = document.getElementById("btnSubmitAnalyze");
    const inputSubject = document.getElementById("inputSubject");
    const inputSender = document.getElementById("inputSender");
    const inputRelayChain = document.getElementById("inputRelayChain");

    // Initialize Application
    initMap();
    initWebSocket();
    loadEmailList();
    setupEventListeners();

    /**
     * Initializes Leaflet.js Map with CartoDB Dark Matter tiles
     */
    function initMap() {
        map = L.map("leafletMap", {
            zoomControl: false,
            attributionControl: false
        }).setView([30.0, 10.0], 2);

        // Add Leaflet zoom control on bottom right
        L.control.zoom({ position: 'bottomright' }).addTo(map);

        // Esri Dark Gray Canvas - Clean, professional dark tiles with NO API key requirement or watermark
        L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}", {
            maxZoom: 16,
            attribution: "Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ"
        }).addTo(map);

        // Esri Dark Gray Reference (Labels, borders & city names)
        L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}", {
            maxZoom: 16
        }).addTo(map);

        // Layer Groups
        hopPolylineLayerGroup = L.layerGroup().addTo(map);
        hopMarkersLayerGroup = L.layerGroup().addTo(map);
        clusterLayerGroup = L.layerGroup().addTo(map);
    }

    /**
     * Switch between Stage 1 (Rough Info Overview) and Stage 2 (Leaflet Map)
     */
    function switchView(mode) {
        currentView = mode;
        if (mode === "map") {
            tabMapView.classList.add("active");
            tabRoughView.classList.remove("active");
            leafletMapContainer.classList.remove("hidden");
            roughOverviewContainer.classList.add("hidden");
            // Invalidate size immediately and after transition so Leaflet renders tiles accurately
            setTimeout(() => {
                if (map) map.invalidateSize();
            }, 60);
        } else {
            tabRoughView.classList.add("active");
            tabMapView.classList.remove("active");
            roughOverviewContainer.classList.remove("hidden");
            leafletMapContainer.classList.add("hidden");
        }
    }

    /**
     * Smoothly focuses the Leaflet Map to a specific Latitude & Longitude,
     * switches to Map View, highlights the marker, and opens its interactive popup.
     */
    function focusLocationOnMap(lat, lon, hopIndex = null, zoom = 8) {
        if (!lat || !lon || (lat === 0.0 && lon === 0.0)) {
            alert("No geographic coordinates available for this internal / private relay hop.");
            return;
        }

        // Switch to map view tab
        switchView("map");

        setTimeout(() => {
            if (map) {
                map.invalidateSize();
                map.flyTo([lat, lon], zoom, {
                    duration: 1.2,
                    easeLinearity: 0.25
                });

                // Open marker popup if available
                if (hopIndex !== null && markerByHopIndex[hopIndex]) {
                    setTimeout(() => {
                        markerByHopIndex[hopIndex].openPopup();
                    }, 600);
                }

                // Update quick-hop buttons active state
                document.querySelectorAll(".quick-hop-btn").forEach(btn => {
                    if (hopIndex !== null && btn.dataset.hop == hopIndex) {
                        btn.classList.add("active");
                    } else {
                        btn.classList.remove("active");
                    }
                });
            }
        }, 80);
    }

    /**
     * Establishes real-time WebSocket connection to /ws endpoint
     */
    async function initWebSocket() {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const ticketResponse = await fetch("/ws-ticket", { method: "POST", headers: getAuthHeaders() });
        if (!ticketResponse.ok) {
            setTimeout(initWebSocket, 3000);
            return;
        }
        const ticketData = await ticketResponse.json();
        const wsUrl = `${protocol}//${window.location.host}/ws?ticket=${encodeURIComponent(ticketData.ticket)}`;

        updateWsStatus("connecting", "WebSocket: Connecting...");
        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
            updateWsStatus("connected", "WebSocket: Live Stream Active");
            addFeedLog("system", "Connected to Geolocation Trace Live Stream");
        };

        socket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.msg_type === "email_trace") {
                    addFeedLog("event", `[NEW TRACE] ${data.email_id}: ${data.subject}`);
                    // Refresh email list and focus newly analyzed trace
                    loadEmailList(data.email_id);
                } else if (data.msg_type === "system_status") {
                    addFeedLog("system", data.message);
                }
            } catch (err) {
                console.error("Failed to parse WebSocket message:", err);
            }
        };

        socket.onerror = () => {
            updateWsStatus("connecting", "WebSocket: Error / Retrying");
        };

        socket.onclose = () => {
            updateWsStatus("disconnected", "WebSocket: Disconnected");
            addFeedLog("system", "WebSocket connection closed. Reconnecting in 3s...");
            setTimeout(initWebSocket, 3000);
        };
    }

    function updateWsStatus(state, text) {
        const dot = wsStatusEl.querySelector(".status-dot");
        const txt = wsStatusEl.querySelector(".status-text");

        dot.className = "status-dot";
        if (state === "connected") {
            dot.classList.add("connected");
        } else {
            dot.classList.add("pulsing");
        }
        txt.textContent = text;
    }

    function addFeedLog(type, text) {
        const item = document.createElement("div");
        item.className = `feed-item ${type}`;
        const now = new Date();
        const timeStr = now.toTimeString().split(" ")[0];
        item.innerHTML = `<span class="time">${timeStr}</span><span class="text">${escapeHtml(text)}</span>`;
        feedLogEl.prepend(item);

        while (feedLogEl.children.length > 30) {
            feedLogEl.removeChild(feedLogEl.lastChild);
        }
    }

    /**
     * Helper to retrieve auth headers for REST requests
     */
    function getAuthHeaders() {
        const apiKey = window.sessionStorage.getItem("swarmsentinel_api_key") ||
                       window.localStorage.getItem("swarmsentinel_api_key") ||
                       "";
        const headers = {};
        if (apiKey) {
            headers["x-api-key"] = apiKey;
        }
        return headers;
    }

    /**
     * Loads list of emails from backend GET /emails
     */
    async function loadEmailList(autoSelectId = null) {
        try {
            const res = await fetch("/emails", { headers: getAuthHeaders() });
            if (res.status === 401 || res.status === 403) {
                const key = prompt("API Key required to access Sentinel Geolocation Trace:");
                if (key) {
                    window.sessionStorage.setItem("swarmsentinel_api_key", key.trim());
                    return loadEmailList(autoSelectId);
                }
            }
            if (!res.ok) throw new Error("Failed to fetch emails");
            emails = await res.json();

            emailCountEl.textContent = `${emails.length} Available`;
            renderEmailList();

            if (autoSelectId) {
                selectEmail(autoSelectId);
            } else if (emails.length > 0 && !currentEmailId) {
                selectEmail(emails[0].email_id);
            }
        } catch (err) {
            console.error("Error loading email list:", err);
        }
    }

    function renderEmailList() {
        emailListEl.innerHTML = "";
        emails.forEach(email => {
            const card = document.createElement("div");
            card.className = `email-card ${email.email_id === currentEmailId ? 'active' : ''}`;
            card.dataset.id = email.email_id;

            let threatBadgeClass = "clean";
            let threatBadgeText = "CLEAN / REGULAR";
            if (email.is_tor) {
                threatBadgeClass = "tor";
                threatBadgeText = "TOR EXIT NODE";
            } else if (email.is_vpn) {
                threatBadgeClass = "vpn";
                threatBadgeText = "VPN PROXY";
            } else if (email.is_hosting) {
                threatBadgeClass = "vpn";
                threatBadgeText = "DATACENTER";
            }

            const latStr = (email.latitude && email.latitude !== 0.0) ? email.latitude.toFixed(2) : "--";
            const lonStr = (email.longitude && email.longitude !== 0.0) ? email.longitude.toFixed(2) : "--";

            card.innerHTML = `
                <div class="card-top">
                    <span class="card-id">${escapeHtml(email.email_id)}</span>
                    <span class="threat-pill ${threatBadgeClass}">${threatBadgeText}</span>
                </div>
                <div class="card-subject">${escapeHtml(email.subject)}</div>
                <div class="card-meta">
                    <span>${escapeHtml(email.origin_country)} (${escapeHtml(email.origin_ip)})</span>
                    <span>${Math.round(email.confidence * 100)}% Conf</span>
                </div>
                <div style="font-family: var(--font-mono); font-size: 10px; color: var(--accent-cyan); margin-top: 4px;">
                    <i class="fa-solid fa-location-crosshairs"></i> Lat: ${latStr}, Lon: ${lonStr}
                </div>
            `;

            card.addEventListener("click", () => selectEmail(email.email_id));
            emailListEl.appendChild(card);
        });
    }

    /**
     * Selects and renders detailed trace for specified email ID
     */
    async function selectEmail(emailId) {
        currentEmailId = emailId;
        renderEmailList();

        try {
            const res = await fetch(`/emails/${emailId}/trace`, { headers: getAuthHeaders() });
            if (!res.ok) throw new Error("Failed to fetch email trace");
            const traceData = await res.json();
            currentTraceData = traceData;

            renderHeaderInfo(traceData);
            renderRoughOverview(traceData);
            renderInspectorPanel(traceData);
            renderMapTrace(traceData);
        } catch (err) {
            console.error(`Error selecting email ${emailId}:`, err);
        }
    }

    function renderHeaderInfo(data) {
        const trace = data.origin_trace;
        activeEmailIdEl.textContent = data.email_id;
        activeSubjectEl.textContent = data.subject;
        activeSenderEl.textContent = `From: ${data.sender}`;
        activeCoordsTagEl.innerHTML = `<i class="fa-solid fa-location-crosshairs"></i> Lat: ${trace.latitude.toFixed(4)}, Lon: ${trace.longitude.toFixed(4)}`;
    }

    /**
     * Renders Stage 1: Rough Info Overview (Loaded First)
     * Shows high-level threat intelligence, origin coordinates, and complete hops matrix.
     */
    function renderRoughOverview(data) {
        const trace = data.origin_trace;
        const confPercent = Math.round(trace.confidence * 100);

        // 1. Origin Card
        roughOriginIp.textContent = trace.ip;
        roughOriginLoc.textContent = `${trace.city}, ${trace.country}`;
        
        // Precise Latitude & Longitude
        const latDirection = trace.latitude >= 0 ? "N" : "S";
        const lonDirection = trace.longitude >= 0 ? "E" : "W";
        roughOriginLat.textContent = `${Math.abs(trace.latitude).toFixed(4)}° ${latDirection}`;
        roughOriginLon.textContent = `${Math.abs(trace.longitude).toFixed(4)}° ${lonDirection}`;

        if (trace.is_tor) {
            roughOriginBadge.textContent = "TOR EXIT NODE";
            roughOriginBadge.className = "badge origin-badge";
        } else if (trace.is_vpn) {
            roughOriginBadge.textContent = "VPN PROXY";
            roughOriginBadge.className = "badge origin-badge";
            roughOriginBadge.style.color = "var(--accent-orange)";
            roughOriginBadge.style.borderColor = "var(--accent-orange)";
        } else if (trace.is_hosting) {
            roughOriginBadge.textContent = "DATACENTER";
            roughOriginBadge.className = "badge origin-badge";
            roughOriginBadge.style.color = "var(--accent-purple)";
            roughOriginBadge.style.borderColor = "var(--accent-purple)";
        } else {
            roughOriginBadge.textContent = "PUBLIC RESIDENTIAL";
            roughOriginBadge.className = "badge origin-badge";
            roughOriginBadge.style.color = "var(--accent-cyan)";
            roughOriginBadge.style.borderColor = "var(--accent-cyan)";
        }

        // 2. Infrastructure & Flags
        roughOriginIsp.textContent = trace.isp;
        roughOriginAsn.textContent = `ASN: ${trace.asn}`;
        roughThreatFlags.innerHTML = `
            <span class="rough-flag ${trace.is_tor ? 'tor' : ''}" style="${!trace.is_tor ? 'opacity: 0.3; background:#1e293b; color:#94a3b8;' : ''}">
                <i class="fa-solid fa-user-ninja"></i> TOR Node
            </span>
            <span class="rough-flag ${trace.is_vpn ? 'vpn' : ''}" style="${!trace.is_vpn ? 'opacity: 0.3; background:#1e293b; color:#94a3b8;' : ''}">
                <i class="fa-solid fa-shield-virus"></i> VPN Proxy
            </span>
            <span class="rough-flag ${trace.is_hosting ? 'hosting' : ''}" style="${!trace.is_hosting ? 'opacity: 0.3; background:#1e293b; color:#94a3b8;' : ''}">
                <i class="fa-solid fa-server"></i> Datacenter
            </span>
        `;

        // 3. Confidence & Routing Metrics
        roughConfidencePill.textContent = `${confPercent}% Confidence`;
        roughConfidenceBar.style.width = `${confPercent}%`;
        roughTotalHops.textContent = `${data.hops.length} Sequential Hops`;
        roughCampaignCluster.textContent = data.campaign_id || "CAMP-GENERIC";

        // Click on Origin "See Map Location" button
        btnRoughViewOriginMap.onclick = () => {
            const originHop = data.hops.find(h => h.ip === trace.ip) || data.hops[0];
            focusLocationOnMap(trace.latitude, trace.longitude, originHop ? originHop.hop_index : 1, 9);
        };

        // 4. Populate Ordered Relay Hops Table
        roughHopsTableBody.innerHTML = "";
        data.hops.forEach(hop => {
            const isOrigin = hop.ip === trace.ip;
            const isCoordsValid = hop.latitude !== 0.0 || hop.longitude !== 0.0;
            const tr = document.createElement("tr");
            if (isOrigin) tr.className = "origin-row";

            let classTag = `<span class="mini-tag">Relay</span>`;
            if (isOrigin) {
                classTag = `<span class="mini-tag" style="background: rgba(239, 68, 68, 0.2); color: var(--accent-red); font-weight:700;">Probable Origin</span>`;
            } else if (hop.is_trusted) {
                classTag = `<span class="mini-tag trusted">Trusted MTA</span>`;
            } else if (hop.is_private) {
                classTag = `<span class="mini-tag private">Private RFC1918</span>`;
            }

            const latCell = isCoordsValid 
                ? `<span class="coord-pill"><i class="fa-solid fa-location-crosshairs"></i> ${hop.latitude.toFixed(4)}</span>` 
                : `<span class="coord-pill private">Private Net</span>`;

            const lonCell = isCoordsValid 
                ? `<span class="coord-pill"><i class="fa-solid fa-location-crosshairs"></i> ${hop.longitude.toFixed(4)}</span>` 
                : `<span class="coord-pill private">Internal</span>`;

            const actionBtn = isCoordsValid 
                ? `<button class="btn-locate-map" data-lat="${hop.latitude}" data-lon="${hop.longitude}" data-hop="${hop.hop_index}">
                     <i class="fa-solid fa-map-location-dot"></i> See Map Location
                   </button>`
                : `<button class="btn-locate-map disabled" title="Internal private network (no public GPS)">
                     <i class="fa-solid fa-ban"></i> Internal Hop
                   </button>`;

            tr.innerHTML = `
                <td>
                    <span class="hop-index-badge ${isOrigin ? 'origin' : ''}">#${hop.hop_index}</span>
                </td>
                <td class="hop-ip-cell">${escapeHtml(hop.ip)}</td>
                <td style="color: var(--text-muted); font-size: 11px;">${escapeHtml(hop.domain)}</td>
                <td>
                    <i class="fa-solid fa-location-dot" style="color: var(--accent-cyan); margin-right: 4px;"></i>
                    ${escapeHtml(hop.city)}, ${escapeHtml(hop.country)}
                </td>
                <td>${latCell}</td>
                <td>${lonCell}</td>
                <td style="color: var(--text-muted); font-size: 11px;">${escapeHtml(hop.isp)}</td>
                <td>${classTag}</td>
                <td>${actionBtn}</td>
            `;

            // Row click button handler
            const locateBtn = tr.querySelector(".btn-locate-map:not(.disabled)");
            if (locateBtn) {
                locateBtn.addEventListener("click", (e) => {
                    e.stopPropagation();
                    focusLocationOnMap(hop.latitude, hop.longitude, hop.hop_index, 9);
                });
            }

            // Clicking the row directly also navigates to the map location if coordinates exist
            tr.addEventListener("click", () => {
                if (isCoordsValid) {
                    focusLocationOnMap(hop.latitude, hop.longitude, hop.hop_index, 9);
                }
            });

            roughHopsTableBody.appendChild(tr);
        });
    }

    /**
     * Renders Inspector Panel (Feature 3.2 details on Right Sidebar)
     */
    function renderInspectorPanel(data) {
        const trace = data.origin_trace;

        // Confidence score
        const confPercent = Math.round(trace.confidence * 100);
        confidencePillEl.textContent = `${confPercent}% Confidence`;
        if (confPercent >= 80) {
            confidencePillEl.style.borderColor = "var(--accent-green)";
            confidencePillEl.style.color = "var(--accent-green)";
        } else {
            confidencePillEl.style.borderColor = "var(--accent-orange)";
            confidencePillEl.style.color = "var(--accent-orange)";
        }

        // Origin details
        originIpEl.textContent = trace.ip;
        originLocationEl.textContent = `${trace.city}, ${trace.country}`;
        originCoordsDisplayEl.textContent = `Lat: ${trace.latitude.toFixed(4)}, Lon: ${trace.longitude.toFixed(4)}`;
        originIspEl.textContent = `${trace.isp} (${trace.asn})`;

        btnLocateOriginInspector.onclick = () => {
            const originHop = data.hops.find(h => h.ip === trace.ip) || data.hops[0];
            focusLocationOnMap(trace.latitude, trace.longitude, originHop ? originHop.hop_index : 1, 9);
        };

        // Threat flags
        threatFlagsEl.innerHTML = `
            <div class="flag-badge ${trace.is_tor ? 'active tor' : 'inactive'}">
                <i class="fa-solid fa-user-ninja"></i> TOR Exit Node
            </div>
            <div class="flag-badge ${trace.is_vpn ? 'active vpn' : 'inactive'}">
                <i class="fa-solid fa-shield-virus"></i> VPN Proxy
            </div>
            <div class="flag-badge ${trace.is_hosting ? 'active hosting' : 'inactive'}">
                <i class="fa-solid fa-server"></i> Datacenter / Hosting
            </div>
        `;

        // Timeline Hops
        timelineContainerEl.innerHTML = "";
        data.hops.forEach(hop => {
            const isOrigin = hop.ip === trace.ip;
            const isCoordsValid = hop.latitude !== 0.0 || hop.longitude !== 0.0;
            const hopItem = document.createElement("div");
            hopItem.className = `timeline-hop ${isOrigin ? 'origin-hop' : ''} ${hop.is_trusted ? 'trusted-hop' : ''}`;

            let tagsHtml = "";
            if (hop.is_private) tagsHtml += `<span class="mini-tag private">Private</span>`;
            if (hop.is_trusted) tagsHtml += `<span class="mini-tag trusted">Trusted</span>`;
            if (isOrigin) tagsHtml += `<span class="mini-tag" style="background: rgba(239, 68, 68, 0.2); color: var(--accent-red);">Origin</span>`;

            const coordsText = isCoordsValid 
                ? `<span>Lat: ${hop.latitude.toFixed(4)}, Lon: ${hop.longitude.toFixed(4)}</span>`
                : `<span>Internal RFC1918</span>`;

            hopItem.innerHTML = `
                <div class="hop-header">
                    <span class="hop-number">Hop #${hop.hop_index}</span>
                    <span class="hop-ip">${escapeHtml(hop.ip)}</span>
                </div>
                <div class="hop-domain">${escapeHtml(hop.domain)}</div>
                <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px;">
                    ${escapeHtml(hop.city)}, ${escapeHtml(hop.country)} • ${escapeHtml(hop.isp)}
                </div>
                <div class="timeline-coords-row">
                    ${coordsText}
                    ${isCoordsValid ? '<span style="font-size: 9px; color: var(--accent-blue);"><i class="fa-solid fa-crosshairs"></i> Click to map</span>' : ''}
                </div>
                ${tagsHtml ? `<div class="hop-tags">${tagsHtml}</div>` : ''}
            `;

            if (isCoordsValid) {
                hopItem.addEventListener("click", () => {
                    focusLocationOnMap(hop.latitude, hop.longitude, hop.hop_index, 9);
                });
            }

            timelineContainerEl.appendChild(hopItem);
        });
    }

    /**
     * Renders Leaflet.js Map Trace (Feature 3.5 visualization)
     */
    function renderMapTrace(data) {
        hopMarkersLayerGroup.clearLayers();
        hopPolylineLayerGroup.clearLayers();
        clusterLayerGroup.clearLayers();
        markerByHopIndex = {};

        const trace = data.origin_trace;
        const validHops = data.hops.filter(h => h.latitude !== 0.0 || h.longitude !== 0.0);

        // Render Quick-Hop Navigator Bar
        hopQuickNav.innerHTML = "";
        data.hops.forEach(hop => {
            const isOrigin = hop.ip === trace.ip;
            const isCoordsValid = hop.latitude !== 0.0 || hop.longitude !== 0.0;
            const btn = document.createElement("button");
            btn.className = `quick-hop-btn ${isOrigin ? 'origin' : ''}`;
            btn.dataset.hop = hop.hop_index;

            const icon = isOrigin ? '<i class="fa-solid fa-radiation"></i>' : '<i class="fa-solid fa-server"></i>';
            btn.innerHTML = `${icon} Hop #${hop.hop_index}: ${escapeHtml(hop.city || "Internal")}`;

            if (isCoordsValid) {
                btn.addEventListener("click", () => {
                    focusLocationOnMap(hop.latitude, hop.longitude, hop.hop_index, 9);
                });
            } else {
                btn.style.opacity = "0.5";
                btn.title = "Internal private hop";
            }
            hopQuickNav.appendChild(btn);
        });

        if (validHops.length === 0) return;

        const latLngs = [];

        // 1. Draw Hop Markers
        validHops.forEach((hop) => {
            const isOrigin = hop.ip === trace.ip;
            const latLng = [hop.latitude, hop.longitude];
            latLngs.push(latLng);

            // Marker styling
            let markerClass = "hop-relay";
            let pulseClass = "";
            if (isOrigin) {
                markerClass = trace.is_tor || trace.is_vpn ? "origin-tor" : "origin-normal";
                pulseClass = "pulsing-marker";
            } else if (hop.is_trusted || hop.is_private) {
                markerClass = "mta-internal";
            }

            const iconHtml = `
                <div class="custom-map-pin ${markerClass} ${pulseClass}">
                    <span class="pin-index">${hop.hop_index}</span>
                </div>
            `;

            const customIcon = L.divIcon({
                html: iconHtml,
                className: "leaflet-div-icon-wrapper",
                iconSize: [28, 28],
                iconAnchor: [14, 14]
            });

            const marker = L.marker(latLng, { icon: customIcon });
            markerByHopIndex[hop.hop_index] = marker;

            // Interactive Popup with Latitude and Longitude
            const popupContent = `
                <div class="map-popup-card">
                    <div class="popup-title">
                        <span>Hop #${hop.hop_index}</span>
                        ${isOrigin ? '<span class="popup-origin-tag">PROBABLE ORIGIN</span>' : ''}
                    </div>
                    <div class="popup-ip">${escapeHtml(hop.ip)}</div>
                    <div class="popup-domain">${escapeHtml(hop.domain)}</div>
                    <div class="popup-detail"><i class="fa-solid fa-location-dot"></i> ${escapeHtml(hop.city)}, ${escapeHtml(hop.country)}</div>
                    <div class="popup-detail" style="color: var(--accent-cyan); font-family: var(--font-mono); font-size: 11px;">
                        <i class="fa-solid fa-location-crosshairs"></i> Lat: ${hop.latitude.toFixed(4)}, Lon: ${hop.longitude.toFixed(4)}
                    </div>
                    <div class="popup-detail"><i class="fa-solid fa-network-wired"></i> ${escapeHtml(hop.isp)}</div>
                </div>
            `;
            marker.bindPopup(popupContent);
            hopMarkersLayerGroup.addLayer(marker);
        });

        // 2. Draw Sequential Hop Polyline (Path)
        if (latLngs.length > 1) {
            const polyline = L.polyline(latLngs, {
                color: "#06b6d4",
                weight: 3,
                opacity: 0.8,
                dashArray: "6, 8"
            });
            hopPolylineLayerGroup.addLayer(polyline);
        }

        // 3. Render Campaign Clusters Overlay
        if (showClusters && data.campaign_clusters) {
            data.campaign_clusters.forEach(cluster => {
                const isHigh = cluster.threat_level === "HIGH";
                const clusterMarker = L.circleMarker([cluster.center_lat, cluster.center_lon], {
                    radius: 20,
                    color: isHigh ? "#ef4444" : "#10b981",
                    fillColor: isHigh ? "#ef4444" : "#10b981",
                    fillOpacity: 0.2,
                    weight: 2
                });

                clusterMarker.bindPopup(`
                    <div class="map-popup-card">
                        <div class="popup-title" style="color: ${isHigh ? '#ef4444' : '#10b981'}; font-weight:700;">
                            <i class="fa-solid fa-layer-group"></i> ${escapeHtml(cluster.cluster_name)}
                        </div>
                        <div style="font-size: 11px; margin-top: 4px;">Cluster ID: ${escapeHtml(cluster.cluster_id)}</div>
                        <div style="font-size: 11px;">Origin ASN: ${escapeHtml(cluster.origin_asn)}</div>
                        <div style="font-size: 11px; font-family: var(--font-mono); color: var(--accent-cyan);">
                            Center: ${cluster.center_lat.toFixed(2)}, ${cluster.center_lon.toFixed(2)}
                        </div>
                        <div style="font-size: 11px; font-weight: 700; color: var(--accent-cyan); margin-top: 4px;">
                            ${cluster.total_emails} Correlated Emails
                        </div>
                    </div>
                `);

                clusterLayerGroup.addLayer(clusterMarker);
            });
        }

        // Fit Map bounds if map tab is currently visible
        if (latLngs.length > 0) {
            const bounds = L.latLngBounds(latLngs);
            map.fitBounds(bounds, { padding: [60, 60], maxZoom: 6 });
        }
    }

    /**
     * Setup UI Event Listeners
     */
    function setupEventListeners() {
        // Stage View Tabs
        tabRoughView.addEventListener("click", () => switchView("rough"));
        tabMapView.addEventListener("click", () => switchView("map"));

        // Toggle campaign clusters
        chkShowClusters.addEventListener("change", (e) => {
            showClusters = e.target.checked;
            if (showClusters) {
                map.addLayer(clusterLayerGroup);
            } else {
                map.removeLayer(clusterLayerGroup);
            }
        });

        // Fit Map button
        btnFitMap.addEventListener("click", () => {
            switchView("map");
            if (currentEmailId) {
                selectEmail(currentEmailId);
            }
        });

        // Modal triggers
        btnAnalyzeModal.addEventListener("click", () => {
            modalAnalyze.classList.add("active");
        });
        btnCloseModal.addEventListener("click", closeModal);
        btnCancelModal.addEventListener("click", closeModal);

        // Submit custom raw relay header
        btnSubmitAnalyze.addEventListener("click", async () => {
            const subject = inputSubject.value.trim();
            const sender = inputSender.value.trim();
            let relayChain = [];

            try {
                relayChain = JSON.parse(inputRelayChain.value.trim());
            } catch (err) {
                alert("Invalid JSON format in Relay Chain field.");
                return;
            }

            btnSubmitAnalyze.disabled = true;
            btnSubmitAnalyze.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Processing...`;

            try {
                const res = await fetch("/emails/analyze", {
                    method: "POST",
                    headers: { "Content-Type": "application/json", ...getAuthHeaders() },
                    body: JSON.stringify({
                        subject: subject,
                        sender: sender,
                        recipient: "target@company.com",
                        relay_chain: relayChain
                    })
                });

                if (!res.ok) throw new Error("Failed to analyze relay chain");
                const result = await res.json();

                closeModal();
                btnSubmitAnalyze.disabled = false;
                btnSubmitAnalyze.innerHTML = `<i class="fa-solid fa-paper-plane"></i> Process & Broadcast Trace`;

                // Select and inspect the new email trace
                loadEmailList(result.email_id);
            } catch (err) {
                alert(`Error analyzing header: ${err.message}`);
                btnSubmitAnalyze.disabled = false;
                btnSubmitAnalyze.innerHTML = `<i class="fa-solid fa-paper-plane"></i> Process & Broadcast Trace`;
            }
        });
    }

    function closeModal() {
        modalAnalyze.classList.remove("active");
    }

    function escapeHtml(str) {
        if (str === null || str === undefined) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});

