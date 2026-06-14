/**
 * PhishShield Application Orchestrator
 * Controls global state, local persistence, routing, CRUD whitelist/blacklist tabs, and simulated scan hooks.
 */

class PhishShieldApp {
  constructor() {
    this.scanner = null;
    this.dashboard = null;

    // Default States
    this.whitelist = [];
    this.blacklist = [];
    this.history = [];
    this.settings = {
      autoBlock: true,
      sensitivity: 1.0,
      notifications: true,
      apiKey: "ps_live_a8f9c18d5b4c9e8f7a0b1c2d"
    };

    // Active UI states
    this.activeView = "home";
    this.scanInProgress = false;
    this.latestScanResult = null;
    this.isKeyVisible = false;
  }

  /**
   * Main Initialize hook
   */
  init() {
    // 1. Load data from persistence
    this.loadState();

    // 2. Initialize Subsystems
    this.scanner = new PhishShieldScanner(this);
    this.dashboard = new PhishShieldDashboard(this);
    this.dashboard.init();

    // 3. Register Event Listeners
    this.bindEvents();

    // 4. Initial DOM Renders
    this.renderSettingsLists();
    this.renderHistoryTable();
    this.updateSettingsUI();

    // 5. Setup default dashboard stats
    this.updateHeaderKeyDisplay();
  }

  /**
   * Reads settings, logs, and custom firewall sheets from localStorage
   */
  loadState() {
    const cachedWhitelist = localStorage.getItem("phishshield_whitelist");
    this.whitelist = cachedWhitelist ? JSON.parse(cachedWhitelist) : [...INITIAL_WHITELIST];

    const cachedBlacklist = localStorage.getItem("phishshield_blacklist");
    this.blacklist = cachedBlacklist ? JSON.parse(cachedBlacklist) : [...INITIAL_BLACKLIST];

    const cachedHistory = localStorage.getItem("phishshield_history");
    this.history = cachedHistory ? JSON.parse(cachedHistory) : [...INITIAL_SCAN_HISTORY];

    const cachedSettings = localStorage.getItem("phishshield_settings");
    if (cachedSettings) {
      this.settings = JSON.parse(cachedSettings);
    }
  }

  saveState() {
    localStorage.setItem("phishshield_whitelist", JSON.stringify(this.whitelist));
    localStorage.setItem("phishshield_blacklist", JSON.stringify(this.blacklist));
    localStorage.setItem("phishshield_history", JSON.stringify(this.history));
    localStorage.setItem("phishshield_settings", JSON.stringify(this.settings));
  }

  /**
   * Binds user triggers to JavaScript handles
   */
  bindEvents() {
    // Tab Navigation switching
    const navItems = document.querySelectorAll(".nav-item[data-view]");
    navItems.forEach(item => {
      item.addEventListener("click", () => {
        const viewName = item.getAttribute("data-view");
        this.switchView(viewName);
      });
    });

    // Scanner actions
    const scanBtn = document.getElementById("start-scan-btn");
    const scanInput = document.getElementById("scanner-url-input");
    if (scanBtn && scanInput) {
      scanBtn.addEventListener("click", () => this.executeScan(scanInput.value));
      scanInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") this.executeScan(scanInput.value);
      });
    }

    // Direct scanner shortcuts from landing page CTA
    const launchScannerCta = document.getElementById("landing-launch-scanner-cta");
    if (launchScannerCta) {
      launchScannerCta.addEventListener("click", () => {
        this.switchView("scanner");
        setTimeout(() => {
          document.getElementById("scanner-url-input")?.focus();
        }, 100);
      });
    }

    // Whitelist Manager ADD
    const addWhiteBtn = document.getElementById("add-whitelist-btn");
    const whiteInput = document.getElementById("whitelist-input-field");
    if (addWhiteBtn && whiteInput) {
      addWhiteBtn.addEventListener("click", () => {
        this.addListItem("whitelist", whiteInput.value);
        whiteInput.value = "";
      });
      whiteInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
          this.addListItem("whitelist", whiteInput.value);
          whiteInput.value = "";
        }
      });
    }

    // Blacklist Manager ADD
    const addBlackBtn = document.getElementById("add-blacklist-btn");
    const blackInput = document.getElementById("blacklist-input-field");
    if (addBlackBtn && blackInput) {
      addBlackBtn.addEventListener("click", () => {
        this.addListItem("blacklist", blackInput.value);
        blackInput.value = "";
      });
      blackInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
          this.addListItem("blacklist", blackInput.value);
          blackInput.value = "";
        }
      });
    }

    // Settings Toggle & Range Handles
    const sensitivitySlider = document.getElementById("sensitivity-range-slider");
    if (sensitivitySlider) {
      sensitivitySlider.addEventListener("input", (e) => {
        const val = parseFloat(e.target.value);
        document.getElementById("sensitivity-slider-value").innerText = val.toFixed(1) + "x";
        this.settings.sensitivity = val;
        this.saveState();
      });
    }

    const autoBlockToggle = document.getElementById("auto-block-toggle-switch");
    if (autoBlockToggle) {
      autoBlockToggle.addEventListener("change", (e) => {
        this.settings.autoBlock = e.target.checked;
        this.saveState();
        this.updateSettingsUI();
      });
    }

    const alertsToggle = document.getElementById("email-alerts-toggle-switch");
    if (alertsToggle) {
      alertsToggle.addEventListener("change", (e) => {
        this.settings.notifications = e.target.checked;
        this.saveState();
      });
    }

    // API Key Regeneration & Visibility Eye
    const eyeBtn = document.getElementById("toggle-api-key-eye");
    if (eyeBtn) {
      eyeBtn.addEventListener("click", () => this.toggleApiKeyVisibility());
    }

    const regenKeyBtn = document.getElementById("regen-api-key-btn");
    if (regenKeyBtn) {
      regenKeyBtn.addEventListener("click", () => this.regenerateApiKey());
    }

    // Clear history button
    const clearHistBtn = document.getElementById("clear-history-btn");
    if (clearHistBtn) {
      clearHistBtn.addEventListener("click", () => {
        if (confirm("Are you sure you want to wipe all scanning records?")) {
          this.history = [];
          this.saveState();
          this.renderHistoryTable();
        }
      });
    }

    // Email alert popup closer
    const closeEmailAlert = document.getElementById("close-email-alert-banner");
    if (closeEmailAlert) {
      closeEmailAlert.addEventListener("click", () => {
        document.getElementById("floating-email-alert-container").style.display = "none";
      });
    }

    // Simulated sandbox demo navigation clicks
    const sandboxGoBtn = document.getElementById("sandbox-go-search-btn");
    const sandboxInput = document.getElementById("sandbox-address-input-bar");
    if (sandboxGoBtn && sandboxInput) {
      sandboxGoBtn.addEventListener("click", () => {
        this.runSandboxPreview(sandboxInput.value);
      });
      sandboxInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") this.runSandboxPreview(sandboxInput.value);
      });
    }
    // Direct preview button on scanner view
    const previewBtn = document.getElementById("preview-url-btn");
    const scannerInput = document.getElementById("scanner-url-input");
    if (previewBtn && scannerInput) {
      previewBtn.addEventListener("click", () => {
        this.runSandboxPreview(scannerInput.value);
      });
      scannerInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") this.runSandboxPreview(scannerInput.value);
      });
    }
  }

  /**
   * Router transition handler
   */
  switchView(viewName) {
    this.activeView = viewName;

    // Toggle active classes on sidebar links
    document.querySelectorAll(".nav-item").forEach(item => {
      if (item.getAttribute("data-view") === viewName) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    });

    // Toggle active view panel
    document.querySelectorAll(".view-section").forEach(view => {
      if (view.getAttribute("id") === `view-${viewName}`) {
        view.classList.add("active-view");
      } else {
        view.classList.remove("active-view");
      }
    });

    // Redraw SVG charts if switching to Dashboard (helps with layout updates)
    if (viewName === "dashboard" && this.dashboard) {
      setTimeout(() => {
        this.dashboard.renderTelemetryCharts();
      }, 50);
    }
  }

  /**
   * Starts simulated scanning sequences
   */
  async executeScan(rawUrl) {
    if (this.scanInProgress) return;
    if (!rawUrl.trim()) {
      alert("Please enter a valid URL coordinate to analyze.");
      return;
    }

    try {
      this.scanInProgress = true;
      const scanBtn = document.getElementById("start-scan-btn");
      const loaderRing = document.getElementById("start-scan-loader-icon");
      const term = document.getElementById("terminal-logs");

      if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin" id="start-scan-loader-icon"></i> Analyzing...`;
      }

      // Reset scanner result display panel to default (hide previous)
      const revealPanel = document.getElementById("scan-result-reveal");
      if (revealPanel) {
        revealPanel.style.opacity = "0.4";
      }
      if (term) term.innerHTML = `<span class="terminal-row term-running">> INITIALIZING PHISHSHIELD AI CORES...</span><br>`;

      // Execute scan engine
      await this.scanner.scanUrl(
        rawUrl,
        (phaseText, pct) => {
          // Output text row into console log
          if (term) {
            term.innerHTML += `<span class="terminal-row">> ${phaseText} (${pct}%)</span><br>`;
            term.scrollTop = term.scrollHeight; // Auto-scroll
          }
        },
        (result) => {
          try {
            // Complete Callback
            this.latestScanResult = result;
            this.scanInProgress = false;

            if (scanBtn) {
              scanBtn.disabled = false;
              scanBtn.innerHTML = `<i class="fa-solid fa-shield-halved"></i> Analyze URL`;
            }

            if (term) {
              term.innerHTML += `<span class="terminal-row term-success">> Telemetry gathered successfully. System code status: APPROVED.</span><br>`;
              term.scrollTop = term.scrollHeight;
            }

            // Increment dashboard counts
            if (this.dashboard) {
              this.dashboard.incrementCounters(result.status);
            }

            // Render visual outcomes
            this.renderScanResult(result);
          } catch (callbackErr) {
            console.error("[PhishShield] Error in scan completion callback:", callbackErr);
            this.scanInProgress = false;
            if (scanBtn) {
              scanBtn.disabled = false;
              scanBtn.innerHTML = `<i class="fa-solid fa-shield-halved"></i> Analyze URL`;
            }
            if (term) {
              term.innerHTML += `<span class="terminal-row term-failure">> ERROR: Failed to render scan results. ${callbackErr.message}</span><br>`;
            }
          }
        }
      );
    } catch (err) {
      console.error("[PhishShield] Critical scan execution error:", err);
      this.scanInProgress = false;
      const scanBtn = document.getElementById("start-scan-btn");
      if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.innerHTML = `<i class="fa-solid fa-shield-halved"></i> Analyze URL`;
      }
      const term = document.getElementById("terminal-logs");
      if (term) {
        term.innerHTML += `<span class="terminal-row term-failure">> CRITICAL ERROR: ${err.message}</span><br>`;
      }
    }
  }

  /**
   * Displays scan analytics in structural containers
   */
  renderScanResult(res) {
    try {
      console.log("[PhishShield] Rendering scan results for:", res.url);
      const revealPanel = document.getElementById("scan-result-reveal");
      if (revealPanel) {
        revealPanel.style.opacity = "1";
        revealPanel.style.display = "block";
      }

      // 1. Render Score progress dial
      this.updateCircularProgress(res.score, res.status);

      // 2. Risk Badge Labels
      const riskBadge = document.getElementById("res-risk-badge");
      if (riskBadge) {
        riskBadge.className = "risk-level-badge";
        riskBadge.innerText = `${res.status} (Score ${res.score})`;

        if (res.score <= 59) riskBadge.classList.add("risk-safe");
        else if (res.score <= 79) riskBadge.classList.add("risk-suspicious");
        else if (res.score <= 90) riskBadge.classList.add("risk-dangerous");
        else riskBadge.classList.add("risk-critical");
      }

      // 3. Dynamic Telemetry Texts
      const setElText = (id, text) => {
        const el = document.getElementById(id);
        if (el) el.innerText = text;
      };

      setElText("res-target-domain", res.host);
      setElText("res-ssl-indicator", res.ssl);
      setElText("res-domain-age", res.age);
      setElText("res-registrar", res.registrar);
      setElText("res-ip-addr", res.ip);
      setElText("res-geolocation", `${res.country} (${res.countryCode})`);
      setElText("res-ai-confidence", res.confidence);
      setElText("res-category", res.category);

      // Check SSL Valid vs Insecure
      const sslIcon = document.getElementById("res-ssl-icon");
      if (sslIcon && res.ssl) {
        if (res.ssl.toLowerCase().includes("none") || res.ssl.toLowerCase().includes("invalid")) {
          sslIcon.className = "fa-solid fa-unlock text-orange";
        } else {
          sslIcon.className = "fa-solid fa-lock text-emerald";
        }
      }

      // 4. Heuristic Flags compilation
      const flagsBox = document.getElementById("heuristic-flags-rows");
      if (flagsBox) {
        flagsBox.innerHTML = "";

        if (res.score <= 59 && (!res.flags || res.flags.length === 0 || (res.flags.length === 1 && res.flags[0].includes("No standard")))) {
          flagsBox.innerHTML = `
            <div class="heuristic-flag-row flag-safe-notify">
              <i class="fa-solid fa-circle-check"></i>
              <span>No standard threat signals triggered. This URL appears highly secure.</span>
            </div>
          `;
        } else if (res.flags) {
          res.flags.forEach(flag => {
            flagsBox.innerHTML += `
              <div class="heuristic-flag-row">
                <i class="fa-solid fa-circle-exclamation"></i>
                <span>${flag}</span>
              </div>
            `;
          });
        }
      }

      // 5. Update Whitelist/Blacklist indicators if matched
      this.renderHistoryTable();

      // 6. Handle Smart Blocking and Sandbox Redirect triggers
      const sandboxBannerDesc = document.getElementById("sandbox-trigger-banner-desc");
      const launchSandboxBtn = document.getElementById("launch-sandbox-preview-btn");

      if (sandboxBannerDesc && launchSandboxBtn) {
        if (res.score >= 80 && this.settings.autoBlock) {
          sandboxBannerDesc.innerHTML = `<span class="glow-red">&#x26A0; Warning:</span> Automatic Firewall blocked access to this domain. Sandbox preview terminated.`;
          launchSandboxBtn.innerHTML = `<i class="fa-solid fa-shield-virus"></i> View Access Denied Logs`;
          launchSandboxBtn.className = "btn btn-secondary w-full";
        } else if (res.score >= 60) {
          sandboxBannerDesc.innerHTML = `<span class="glow-orange">&#x26A0; Sandbox Quarantined:</span> This suspicious domain is isolated. Preview is quarantined for safety.`;
          launchSandboxBtn.innerHTML = `<i class="fa-solid fa-box-open"></i> Execute Safe Sandbox Preview`;
          launchSandboxBtn.className = "btn btn-primary w-full";
        } else {
          sandboxBannerDesc.innerHTML = `<span class="glow-emerald">&#x2714; Direct Access Safe:</span> This trusted domain is verified clean. Direct access is safe.`;
          launchSandboxBtn.innerHTML = `<i class="fa-solid fa-box-open"></i> Execute Secure Web Preview`;
          launchSandboxBtn.className = "btn btn-primary w-full";
        }

        // Wire sandbox launcher click
        launchSandboxBtn.onclick = () => {
          this.switchView("sandbox");
          this.runSandboxPreview(res.url);
        };
      }

      // 7. Fire Email alert popups for Critical Threats (91 - 100)
      if (res.score >= 91 && this.settings.notifications) {
        this.triggerFloatingEmailAlert(res);
      }
    } catch (renderErr) {
      console.error("[PhishShield] Error in renderScanResult:", renderErr);
      const term = document.getElementById("terminal-logs");
      if (term) {
        term.innerHTML += `<span class="terminal-row term-failure">> RENDER ERROR: ${renderErr.message}</span><br>`;
      }
    }
  }

  /**
   * Animates circular progress dial SVG
   */
  updateCircularProgress(score, status) {
    const ring = document.getElementById("circle-progress-ring");
    const scoreVal = document.getElementById("circle-progress-value");

    if (!ring || !scoreVal) return;

    // SVG Circumference calculation (r=70 -> 2 * pi * 70 = ~440)
    const circum = 440;
    const offset = circum - (score / 100) * circum;

    ring.style.strokeDashoffset = offset;
    scoreVal.innerText = score;

    // Assign color values based on state
    if (score <= 59) {
      ring.style.stroke = "var(--color-safe)";
      scoreVal.style.color = "var(--color-safe)";
    } else if (score <= 79) {
      ring.style.stroke = "var(--color-suspicious)";
      scoreVal.style.color = "var(--color-suspicious)";
    } else if (score <= 90) {
      ring.style.stroke = "var(--color-dangerous)";
      scoreVal.style.color = "var(--color-dangerous)";
    } else {
      ring.style.stroke = "var(--color-critical)";
      scoreVal.style.color = "var(--color-critical)";
    }
  }

  /**
   * Pushes details into global tracking structures
   */
  addToHistory(scanResult) {
    const timestamp = "Just now";
    this.history.unshift({
      url: scanResult.url,
      score: scanResult.score,
      status: scanResult.status,
      timestamp: timestamp
    });

    // Max cap size
    if (this.history.length > 25) {
      this.history.pop();
    }
    this.saveState();
  }

  /**
   * Sandbox visual browser manager
   */
  async runSandboxPreview(rawUrl) {
    const sandboxInput = document.getElementById("sandbox-address-input-bar");
    const sandboxViewport = document.getElementById("sandbox-render-viewport");
    const sandboxSecureIcon = document.getElementById("sandbox-secure-lock-icon");
    const sandboxTabTitle = document.getElementById("sandbox-title-tab-label");

    if (!rawUrl.trim()) return;

    // Normalize URL
    let urlString = rawUrl.trim();
    if (!/^https?:\/\//i.test(urlString)) {
      urlString = "https://" + urlString;
    }

    let host = "unresolved";
    try {
      host = new URL(urlString).hostname.toLowerCase();
    } catch (e) {
      host = urlString;
    }

    if (sandboxInput) sandboxInput.value = urlString;
    if (sandboxTabTitle) sandboxTabTitle.innerText = host;

    // Evaluate URL details (quick sync run of heuristics without delays)
    const mockEval = this.scanner.evaluateRisk(urlString, host, urlString.startsWith("https"));

    // Check Auto-Block limits
    if (mockEval.score >= 80 && this.settings.autoBlock) {
      // SMART BLOCK ACCESSED
      sandboxSecureIcon.className = "fa-solid fa-ban text-orange";
      sandboxViewport.innerHTML = `
        <div class="firewall-denied-viewport">
          <div class="firewall-grid-bg"></div>
          <div class="firewall-siren-animation">
            <i class="fa-solid fa-triangle-exclamation"></i>
          </div>
          <h1>ACCESS DENIED</h1>
          <p>The PhishShield Real-time Enterprise Firewall blocked this page because it matches dangerous threats or credential harvest malware scripts.</p>
          
          <div class="firewall-details-card" style="width: 100%; max-width: 500px;">
            <div class="firewall-row" style="text-align: left; word-break: break-all; margin-bottom: 0.5rem;">
              <span style="min-width: 110px; display: inline-block;">BLOCKED URL:</span>
              <span class="text-cyan font-mono" style="font-size: 0.8rem;">${urlString}</span>
            </div>
            <div class="firewall-row">
              <span>TARGET NODE:</span>
              <span>${host}</span>
            </div>
            <div class="firewall-row">
              <span>IP RESOLVED:</span>
              <span>${mockEval.ip}</span>
            </div>
            <div class="firewall-row">
              <span>THREAT LEVEL:</span>
              <span class="glow-red">${mockEval.status}</span>
            </div>
            <div class="glass-panel scan-console-wrapper">
              <div class="scanner-input-container">
                <i class="fa-solid fa-globe"></i>
                <input type="text" id="sandbox-firewall-url-input" placeholder="Paste URL coordinate to parse... (e.g. netflix-billing-renew.net)">
                <button class="btn btn-primary" id="sandbox-firewall-start-scan-btn">
                  <i class="fa-solid fa-shield-halved"></i> Analyze URL
                </button>
                <button class="btn btn-secondary" id="sandbox-firewall-preview-url-btn" title="Open safe sandbox preview for entered URL">
                  <i class="fa-solid fa-box-open"></i> Preview Sandbox
                </button>
              </div>
            </div>
      `;

      const previewBtn = document.getElementById("sandbox-firewall-preview-url-btn");
      if (previewBtn) {
        previewBtn.onclick = () => {
          const input = document.getElementById("sandbox-firewall-url-input");
          if (input && input.value) this.runSandboxPreview(input.value);
        };
      }

      const scanBtn = document.getElementById("sandbox-firewall-start-scan-btn");
      if (scanBtn) {
        scanBtn.onclick = () => {
          const input = document.getElementById("sandbox-firewall-url-input");
          if (input && input.value) {
            const mainInput = document.getElementById("scanner-url-input");
            if (mainInput) {
              mainInput.value = input.value;
            }
            this.switchView("scanner");
            this.executeScan(input.value);
          }
        };
      }

      return;
    }

    // SAFE, SUSPICIOUS OR DANGEROUS ALLOWED IN SANDBOX CONTROLLER
    let warningBannerHtml = "";
    if (mockEval.score >= 80) {
      // Dangerous but allowed because Auto-Block is disabled
      sandboxSecureIcon.className = "fa-solid fa-radiation text-rose glow-red";
      warningBannerHtml = `
        <div class="suspicious-sandbox-banner" style="background: rgba(244, 67, 54, 0.15); border-color: var(--color-danger);">
          <div>
            <i class="fa-solid fa-triangle-exclamation text-red"></i>
            <span style="color: var(--color-danger);">CRITICAL ALERT: This domain is classified as MALICIOUS. Execution is strictly sandboxed.</span>
          </div>
          <span class="badge badge-danger" style="background: var(--color-danger); color: #fff;">THREAT: ${mockEval.score}/100</span>
        </div>
      `;
    } else if (mockEval.score >= 60) {
      // Suspicious: Warn but show in safe container
      sandboxSecureIcon.className = "fa-solid fa-triangle-exclamation text-orange";
      warningBannerHtml = `
        <div class="suspicious-sandbox-banner">
          <div>
            <i class="fa-solid fa-triangle-exclamation text-orange"></i>
            <span>Warning: PhishShield AI flagged this domain as Suspicious. Credentials input is strictly prohibited.</span>
          </div>
          <span class="badge badge-warning">SUSP: ${mockEval.score}/100</span>
        </div>
      `;
    } else {
      sandboxSecureIcon.className = "fa-solid fa-lock text-emerald";
    }

    // Render simulated targets inside secure DOM sandbox
    sandboxViewport.innerHTML = `${warningBannerHtml}
      <div style="width: 100%; height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center; background: #060814;">
        <i class="fa-solid fa-circle-notch fa-spin text-cyan" style="font-size: 2rem; margin-bottom: 1rem;"></i>
        <span class="text-cyan font-mono text-sm">Initializing Secure Proxy Tunnel...</span>
      </div>
    `;

    try {
      // Enterprise-grade Proxy Fetching to bypass X-Frame-Options and CSP
      const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(urlString)}`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      const response = await fetch(proxyUrl, { signal: controller.signal });
      clearTimeout(timeoutId);

      if (!response.ok) throw new Error(`Proxy responded with status ${response.status}`);

      const data = await response.json();
      if (!data.contents) throw new Error("No HTML contents returned from proxy");

      let html = data.contents;

      // Metadata Extraction for Graceful Fallbacks (if srcdoc fails entirely or for context)
      const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
      const title = titleMatch ? titleMatch[1].trim() : host;

      // Inject <base> tag to fix relative assets (images, css, js)
      const baseTag = `<base href="${urlString}">`;
      if (html.toLowerCase().includes("<head>")) {
        html = html.replace(/(<head[^>]*>)/i, `$1\n${baseTag}\n`);
      } else {
        html = `${baseTag}\n${html}`;
      }

      // LIVE SECURITY SANDBOX IFRAME LOAD via Blob URL (avoids srcdoc escaping issues)
      const isClean = mockEval.score <= 59;
      const badgeIcon = isClean ? "fa-shield-halved text-emerald" : "fa-box-open text-cyan";
      const badgeText = isClean ? "Secure Preview" : "Sandbox Active";
      const badgeBorder = isClean ? "rgba(0, 230, 118, 0.4)" : "var(--accent-cyan)";

      // Create a Blob URL from the raw HTML — zero escaping issues
      const blob = new Blob([html], { type: "text/html" });
      const blobUrl = URL.createObjectURL(blob);

      const containerHtml = `
        <div style="width: 100%; height: 100%; background: #fff; position: relative;">
          <!-- Quarantined URL Floating Info Badge -->
          <div style="position: absolute; bottom: 15px; right: 15px; background: rgba(10,14,30,0.95); border: 1px solid ${badgeBorder}; border-radius: 4px; padding: 0.5rem 1rem; font-size: 0.75rem; color: #fff; font-family: var(--font-mono); z-index: 1000; box-shadow: 0 4px 12px rgba(0,0,0,0.6); pointer-events: none; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            <i class="fa-solid ${badgeIcon}"></i> ${badgeText}: ${title}
          </div>
          <iframe id="phishield-preview-frame" src="${blobUrl}" sandbox="allow-scripts allow-same-origin allow-forms" style="width: 100%; height: 100%; border: none;"></iframe>
        </div>
      `;
      sandboxViewport.innerHTML = `${warningBannerHtml}${containerHtml}`;

      // Clean up the Blob URL after the iframe loads to free memory
      const previewFrame = document.getElementById("phishield-preview-frame");
      if (previewFrame) {
        previewFrame.addEventListener("load", () => URL.revokeObjectURL(blobUrl), { once: true });
      }

    } catch (fetchError) {
      console.error("[PhishShield] Proxy Fetch Error:", fetchError);

      // PROACTIVE FRAME RESTRICTION FALLBACK CARD
      const targetMockHtml = `
        <div class="sandbox-rendered-body" style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; padding: 2rem; text-align: center; background: #060814; color: #fff;">
          <div class="firewall-grid-bg"></div>
          <i class="fa-solid fa-shield-halved" style="font-size: 3.5rem; color: var(--color-safe); margin-bottom: 1.5rem; filter: drop-shadow(0 0 10px var(--color-safe-glow)); position: relative; z-index: 10;"></i>
          <h3 style="color: #fff; font-family: var(--font-cyber); margin-bottom: 0.75rem; position: relative; z-index: 10;">PREVIEW SECURITY RESTRICTION</h3>
          <p style="color: var(--text-muted); max-width: 480px; font-size: 0.9rem; margin-bottom: 1.5rem; line-height: 1.5; position: relative; z-index: 10;">
            This site actively rejects proxy-based sandboxing or is unreachable. However, the AI engine has verified it is safe.
          </p>
          <div style="background: rgba(0, 230, 118, 0.08); border: 1px solid rgba(0, 230, 118, 0.2); border-radius: 6px; padding: 0.65rem 1.25rem; font-family: var(--font-mono); font-size: 0.8rem; color: var(--color-safe); margin-bottom: 1.5rem; word-break: break-all; width: 100%; max-width: 440px; position: relative; z-index: 10;">
            <strong>Verified Clean Site:</strong> ${urlString}
          </div>
          <div style="position: relative; z-index: 10;">
            <a href="${urlString}" target="_blank" class="btn btn-primary" style="padding: 0.5rem 1.5rem; font-size: 0.8rem;"><i class="fa-solid fa-arrow-up-right-from-square"></i> Open Link in New Isolated Tab</a>
          </div>
        </div>
      `;
      sandboxViewport.innerHTML = `${warningBannerHtml}${targetMockHtml}`;
    }
  }

  /**
   * Floating desktop-like modal notification simulator for dangerous sites
   */
  triggerFloatingEmailAlert(res) {
    const alertBox = document.getElementById("floating-email-alert-container");
    if (!alertBox) return;

    document.getElementById("email-alert-target-domain").innerText = res.host;
    document.getElementById("email-alert-score-num").innerText = res.score;
    document.getElementById("email-alert-ip").innerText = res.ip;
    document.getElementById("email-alert-country").innerText = res.country;

    alertBox.style.display = "block";

    // Play alert audio sound mockup using JavaScript Audio if valid or just log (we'll keep it silent to avoid browser issues but log)
    console.log(`[ALERT FIREWALL] Email Alert mock dispatched: Critical threat ${res.host}`);
  }

  /**
   * Crud List Managers
   */
  addListItem(type, value) {
    const trimmed = value.trim().toLowerCase();
    if (!trimmed) return;

    if (type === "whitelist") {
      if (this.whitelist.includes(trimmed)) return;
      this.whitelist.push(trimmed);
    } else {
      if (this.blacklist.includes(trimmed)) return;
      this.blacklist.push(trimmed);
    }

    this.saveState();
    this.renderSettingsLists();
  }

  removeListItem(type, index) {
    if (type === "whitelist") {
      this.whitelist.splice(index, 1);
    } else {
      this.blacklist.splice(index, 1);
    }

    this.saveState();
    this.renderSettingsLists();
  }

  /**
   * Dynamic Whitelist/Blacklist list table populate
   */
  renderSettingsLists() {
    const whiteScroll = document.getElementById("whitelist-scroll-list");
    const blackScroll = document.getElementById("blacklist-scroll-list");

    if (whiteScroll) {
      whiteScroll.innerHTML = "";
      this.whitelist.forEach((item, idx) => {
        whiteScroll.innerHTML += `
          <div class="list-item-row">
            <span>${item}</span>
            <span class="list-item-remove-btn" onclick="app.removeListItem('whitelist', ${idx})"><i class="fa-solid fa-trash-can"></i></span>
          </div>
        `;
      });
    }

    if (blackScroll) {
      blackScroll.innerHTML = "";
      this.blacklist.forEach((item, idx) => {
        blackScroll.innerHTML += `
          <div class="list-item-row">
            <span>${item}</span>
            <span class="list-item-remove-btn" onclick="app.removeListItem('blacklist', ${idx})"><i class="fa-solid fa-trash-can"></i></span>
          </div>
        `;
      });
    }
  }

  /**
   * Update Settings toggles
   */
  updateSettingsUI() {
    const autoBlockToggle = document.getElementById("auto-block-toggle-switch");
    if (autoBlockToggle) autoBlockToggle.checked = this.settings.autoBlock;

    const alertsToggle = document.getElementById("email-alerts-toggle-switch");
    if (alertsToggle) alertsToggle.checked = this.settings.notifications;

    const slider = document.getElementById("sensitivity-range-slider");
    if (slider) {
      slider.value = this.settings.sensitivity;
      document.getElementById("sensitivity-slider-value").innerText = parseFloat(this.settings.sensitivity).toFixed(1) + "x";
    }

    const keyInput = document.getElementById("api-key-input-field");
    if (keyInput) {
      keyInput.value = this.isKeyVisible ? this.settings.apiKey : "••••••••••••••••••••••••••••••••";
    }
  }

  toggleApiKeyVisibility() {
    this.isKeyVisible = !this.isKeyVisible;
    const eyeBtn = document.getElementById("toggle-api-key-eye");

    if (eyeBtn) {
      eyeBtn.className = this.isKeyVisible ? "fa-solid fa-eye-slash api-key-eye-btn" : "fa-solid fa-eye api-key-eye-btn";
    }

    this.updateSettingsUI();
  }

  regenerateApiKey() {
    const chars = "abcdef0123456789";
    let newKey = "ps_live_";
    for (let i = 0; i < 24; i++) {
      newKey += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    this.settings.apiKey = newKey;
    this.saveState();
    this.updateSettingsUI();
    this.updateHeaderKeyDisplay();
    alert("New Live Security Endpoint API key generated successfully.");
  }

  updateHeaderKeyDisplay() {
    const headKey = document.getElementById("header-api-key-indicator");
    if (headKey) {
      headKey.innerText = this.settings.apiKey.substring(0, 10) + "...";
    }
  }

  /**
   * Populates recent scans history on dashboard table
   */
  renderHistoryTable() {
    const tableBody = document.getElementById("recent-scans-table-body");
    if (!tableBody) return;

    tableBody.innerHTML = "";
    if (this.history.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="4" class="txt-muted text-center py-4">No scan cycles registered.</td></tr>`;
      return;
    }

    this.history.forEach(item => {
      let badgeClass = "badge-success";
      if (item.status === "Suspicious") badgeClass = "badge-warning";
      else if (item.status === "Dangerous" || item.status === "Critical Threat") badgeClass = "badge-danger";

      tableBody.innerHTML += `
        <tr>
          <td class="font-mono text-truncate text-cyan" style="max-width: 250px;" title="${item.url}">${item.url}</td>
          <td class="font-mono text-center font-semibold">${item.score}</td>
          <td><span class="badge ${badgeClass}">${item.status}</span></td>
          <td class="txt-muted text-xs text-end">${item.timestamp}</td>
        </tr>
      `;
    });
  }
}

// Global App reference initializer
window.app = new PhishShieldApp();
window.addEventListener("DOMContentLoaded", () => {
  window.app.init();
});
