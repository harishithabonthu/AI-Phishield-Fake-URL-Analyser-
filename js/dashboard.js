/**
 * PhishShield Interactive Telemetry & Dashboard Logic
 * Generates security stat charts, populates counter matrices, and manages the live attack signal feed.
 */

class PhishShieldDashboard {
  constructor(appInstance) {
    this.app = appInstance;
    this.counters = {
      total: 14209,
      blocked: 3844,
      safe: 8932,
      suspicious: 1433
    };
    this.feedTimer = null;
    this.chartTimer = null;
  }

  /**
   * Initialize all dashboard elements
   */
  init() {
    this.loadCachedCounters();
    this.updateCounterUI();
    this.renderTelemetryCharts();
    this.startLiveActivityFeed();
  }

  /**
   * Cache counters in localStorage for continuity
   */
  loadCachedCounters() {
    const cached = localStorage.getItem("phishshield_counters");
    if (cached) {
      this.counters = JSON.parse(cached);
    } else {
      this.saveCounters();
    }
  }

  saveCounters() {
    localStorage.setItem("phishshield_counters", JSON.stringify(this.counters));
  }

  /**
   * Increase count dynamically on scan result
   */
  incrementCounters(status) {
    this.counters.total++;
    if (status === "Safe") {
      this.counters.safe++;
    } else if (status === "Suspicious") {
      this.counters.suspicious++;
    } else {
      // Dangerous or Critical
      this.counters.blocked++;
    }
    this.saveCounters();
    this.updateCounterUI();
    this.renderTelemetryCharts(); // Redraw chart triggers
  }

  /**
   * Update visual labels in DOM
   */
  updateCounterUI() {
    const totalEl = document.getElementById("dash-stat-total");
    const blockedEl = document.getElementById("dash-stat-blocked");
    const safeEl = document.getElementById("dash-stat-safe");
    const suspEl = document.getElementById("dash-stat-suspicious");

    if (totalEl) totalEl.innerText = this.counters.total.toLocaleString();
    if (blockedEl) blockedEl.innerText = this.counters.blocked.toLocaleString();
    if (safeEl) safeEl.innerText = this.counters.safe.toLocaleString();
    if (suspEl) suspEl.innerText = this.counters.suspicious.toLocaleString();

    // Update auto-block toggle count indicators as well
    const shieldStats = document.getElementById("shield-status-indicator");
    if (shieldStats) {
      shieldStats.innerHTML = `<span class="glow-emerald">&#x25CF;</span> Active - Protecting ${this.counters.blocked.toLocaleString()} entry nodes`;
    }
  }

  /**
   * Draw high-fidelity responsive SVG Charts (threat analytics)
   */
  renderTelemetryCharts() {
    // Render Line Chart: Threats Over 24 Hours
    this.drawThreatTimelineChart();

    // Render Ring Chart: Attack Vectors
    this.drawAttackVectorsRing();
  }

  /**
   * Draws a beautiful glassmorphic multi-point SVG line chart
   */
  drawThreatTimelineChart() {
    const container = document.getElementById("timeline-chart-container");
    if (!container) return;

    const width = container.clientWidth || 500;
    const height = 180;
    
    // Simulating values based on counter totals to keep it alive
    const baseMult = (this.counters.blocked % 100) + 15;
    const dataPoints = [
      baseMult * 0.8, baseMult * 1.2, baseMult * 1.5, baseMult * 0.9,
      baseMult * 1.1, baseMult * 1.9, baseMult * 2.2, baseMult * 1.4,
      baseMult * 1.6, baseMult * 1.3, baseMult * 2.5, baseMult * 1.8
    ];

    const padding = 25;
    const chartWidth = width - padding * 2;
    const chartHeight = height - padding * 2;

    const maxVal = Math.max(...dataPoints) * 1.15;
    const xStep = chartWidth / (dataPoints.length - 1);

    // Calculate coordinates
    const points = dataPoints.map((val, idx) => {
      const x = padding + idx * xStep;
      const y = padding + (chartHeight - (val / maxVal) * chartHeight);
      return { x, y, val };
    });

    let pathD = `M ${points[0].x} ${points[0].y}`;
    for (let i = 1; i < points.length; i++) {
      // Create smooth bezier coordinates
      const cpX1 = points[i - 1].x + xStep / 2;
      const cpY1 = points[i - 1].y;
      const cpX2 = points[i].x - xStep / 2;
      const cpY2 = points[i].y;
      pathD += ` C ${cpX1} ${cpY1}, ${cpX2} ${cpY2}, ${points[i].x} ${points[i].y}`;
    }

    // Shadow filled area path
    const fillD = `${pathD} L ${points[points.length - 1].x} ${height - padding} L ${points[0].x} ${height - padding} Z`;

    const labelsX = ["24h ago", "20h ago", "16h ago", "12h ago", "8h ago", "4h ago", "Now"];
    const labelsSvg = labelsX.map((lbl, idx) => {
      const x = padding + (idx * (chartWidth / (labelsX.length - 1)));
      return `<text x="${x}" y="${height - 5}" fill="rgba(125,145,185,0.7)" font-size="10" text-anchor="middle">${lbl}</text>`;
    }).join("");

    const gridLines = Array.from({ length: 4 }).map((_, idx) => {
      const y = padding + (idx * (chartHeight / 3));
      const valLabel = Math.round(maxVal - (idx * (maxVal / 3)));
      return `
        <line x1="${padding}" y1="${y}" x2="${width - padding}" y2="${y}" stroke="rgba(255,255,255,0.06)" stroke-dasharray="4" />
        <text x="${padding - 5}" y="${y + 3}" fill="rgba(125,145,185,0.5)" font-size="9" text-anchor="end">${valLabel}</text>
      `;
    }).join("");

    container.innerHTML = `
      <svg width="100%" height="${height}" viewBox="0 0 ${width} ${height}" style="overflow: visible;">
        <defs>
          <linearGradient id="chartGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="rgba(0, 229, 255, 0.4)"/>
            <stop offset="100%" stop-color="rgba(0, 229, 255, 0.0)"/>
          </linearGradient>
          <linearGradient id="lineGrad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stop-color="#00e5ff"/>
            <stop offset="50%" stop-color="#00e676"/>
            <stop offset="100%" stop-color="#ff1744"/>
          </linearGradient>
        </defs>
        ${gridLines}
        <path d="${fillD}" fill="url(#chartGrad)" />
        <path d="${pathD}" fill="none" stroke="url(#lineGrad)" stroke-width="2.5" stroke-linecap="round" />
        ${points.map((p, idx) => `
          <circle cx="${p.x}" cy="${p.y}" r="4" fill="#060814" stroke="#00e5ff" stroke-width="2" class="chart-pulse" style="animation-delay: ${idx * 0.1}s">
            <title>Scan events: ${Math.round(p.val)}</title>
          </circle>
        `).join("")}
        ${labelsSvg}
      </svg>
    `;
  }

  /**
   * Draws a beautiful concentric ring / donut chart
   */
  drawAttackVectorsRing() {
    const container = document.getElementById("vectors-chart-container");
    if (!container) return;

    // Relative percentages of block categories
    const phish = 45;
    const malware = 30;
    const adware = 15;
    const spoofing = 10;

    const width = 180;
    const height = 180;
    const cx = width / 2;
    const cy = height / 2;
    const r = 60;
    const circ = 2 * Math.PI * r;

    // Calculate strokes
    const strokePhish = (phish / 100) * circ;
    const strokeMalware = (malware / 100) * circ;
    const strokeAdware = (adware / 100) * circ;
    const strokeSpoof = (spoofing / 100) * circ;

    const offsetPhish = 0;
    const offsetMalware = strokePhish;
    const offsetAdware = strokePhish + strokeMalware;
    const offsetSpoof = strokePhish + strokeMalware + strokeAdware;

    container.innerHTML = `
      <svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
        <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="rgba(255,255,255,0.03)" stroke-width="20" />
        
        <!-- Phishing Segment (Crimson) -->
        <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#ff1744" stroke-width="20" 
          stroke-dasharray="${strokePhish} ${circ}" 
          stroke-dashoffset="-${offsetPhish}" 
          transform="rotate(-90 ${cx} ${cy})" 
          stroke-linecap="round" />

        <!-- Malware Segment (Cyan) -->
        <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#00e5ff" stroke-width="20" 
          stroke-dasharray="${strokeMalware} ${circ}" 
          stroke-dashoffset="-${offsetMalware}" 
          transform="rotate(-90 ${cx} ${cy})" />

        <!-- Adware Segment (Amber) -->
        <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#ff9100" stroke-width="20" 
          stroke-dasharray="${strokeAdware} ${circ}" 
          stroke-dashoffset="-${offsetAdware}" 
          transform="rotate(-90 ${cx} ${cy})" />

        <!-- Brand Spoofing Segment (Emerald) -->
        <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#00e676" stroke-width="20" 
          stroke-dasharray="${strokeSpoof} ${circ}" 
          stroke-dashoffset="-${offsetSpoof}" 
          transform="rotate(-90 ${cx} ${cy})" />

        <text x="${cx}" y="${cy - 5}" fill="#ffffff" font-size="16" font-weight="bold" text-anchor="middle" font-family="'Orbitron', sans-serif">
          ${phish}%
        </text>
        <text x="${cx}" y="${cy + 15}" fill="rgba(125,145,185,0.6)" font-size="10" text-anchor="middle">
          Phishing
        </text>
      </svg>
    `;
  }

  /**
   * Spawns security logs dynamically into a futuristic console
   */
  startLiveActivityFeed() {
    const feedBody = document.getElementById("live-activity-feed-body");
    if (!feedBody) return;

    // Prepopulate with a few rows
    feedBody.innerHTML = "";
    for (let i = 0; i < 6; i++) {
      this.injectFeedRow(feedBody, true);
    }

    // Run dynamic loop every 3 to 6 seconds
    if (this.feedTimer) clearInterval(this.feedTimer);
    this.feedTimer = setInterval(() => {
      this.injectFeedRow(feedBody, false);
    }, 3800);
  }

  injectFeedRow(container, instant = false) {
    const randomIP = `${100 + Math.floor(Math.random() * 120)}.${10 + Math.floor(Math.random() * 200)}.${Math.floor(Math.random() * 254)}.${1 + Math.floor(Math.random() * 254)}`;
    
    // Select country
    const country = COUNTRIES[Math.floor(Math.random() * COUNTRIES.length)];
    
    // Select threat type
    const template = THREAT_FEED_TEMPLATES[Math.floor(Math.random() * THREAT_FEED_TEMPLATES.length)];
    
    // Select a random domain name structure
    const fraudSubdomains = ["secure-login", "billing-recover", "update-bank-access", "netflix-trial", "walmart-freebies", "steam-promo-keys"];
    const baseNames = ["direct-redirect", "domaincheck-net", "cloud-storage-cdn", "web-hosting-vps", "secure-gateway"];
    const randomDomain = `${fraudSubdomains[Math.floor(Math.random() * fraudSubdomains.length)]}-${baseNames[Math.floor(Math.random() * baseNames.length)]}${template.path}`;

    // Status matching
    const isCritical = Math.random() > 0.4;
    const statusColor = isCritical ? "glow-red" : "glow-orange";
    const statusLabel = isCritical ? "BLOCKED (CRIT)" : "ALERT (SUSP)";
    const shieldStatus = isCritical ? "Access Denied by Firewall" : "Heuristic Flag Raised";

    const timestamp = new Date().toLocaleTimeString();

    const tr = document.createElement("tr");
    tr.className = instant ? "feed-row" : "feed-row new-entry";
    tr.innerHTML = `
      <td><span class="cyber-terminal-text">${timestamp}</span></td>
      <td>
        <div class="flex-align">
          <span class="flag-icon flag-${country.code.toLowerCase()}"></span>
          <span>${randomIP}</span>
          <span class="txt-muted text-xs">(${country.code})</span>
        </div>
      </td>
      <td class="font-mono text-truncate text-cyan" style="max-width: 190px;" title="${randomDomain}">${randomDomain}</td>
      <td class="text-xs font-semibold"><span class="${statusColor}">${template.type}</span></td>
      <td><span class="badge ${isCritical ? 'badge-danger' : 'badge-warning'}">${statusLabel}</span></td>
      <td class="txt-muted text-xs font-mono text-end">${shieldStatus}</td>
    `;

    if (instant) {
      container.appendChild(tr);
    } else {
      container.insertBefore(tr, container.firstChild);
      // Prune past 12 logs to prevent DOM overload
      if (container.children.length > 12) {
        container.removeChild(container.lastChild);
      }
    }
  }

  /**
   * Stop feed loops
   */
  destroy() {
    if (this.feedTimer) clearInterval(this.feedTimer);
  }
}
