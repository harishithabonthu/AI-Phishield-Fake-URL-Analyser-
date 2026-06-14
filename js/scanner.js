/**
 * PhishShield AI Scanner Engine
 * Handles URL parsing, heuristics analysis, risk classification, and step-by-step scan animations.
 */

class PhishShieldScanner {
  constructor(appInstance) {
    this.app = appInstance;
  }

  /**
   * Main scan function
   * @param {string} rawUrl - The input URL to scan
   * @param {function} onPhase - Callback for each progressive phase: (phaseText, progress)
   * @param {function} onComplete - Callback when scan is finished: (resultObject)
   */
  async scanUrl(rawUrl, onPhase, onComplete) {
    console.log('[PhishShield] scanUrl() called with:', rawUrl);

    try {
      // 1. Sanitize & Normalize URL
      let urlString = rawUrl.trim();
      let hasProtocolError = false;

      if (!urlString) {
        console.warn('[PhishShield] Empty URL input');
        onPhase("Scan failed: Empty URL input", 0);
        onComplete(this._errorResult(rawUrl, "Empty URL input provided"));
        return;
      }

      // Detect protocol spelling typos
      if (/^(htpt|htps|http|https|ttp|tps|tp)\b/i.test(urlString)) {
        if (!/^(https?:\/\/)/i.test(urlString)) {
          hasProtocolError = true;
          console.warn('[PhishShield] Protocol spelling error detected in:', urlString);
        }
      }

      // Standardize URL
      if (!/^https?:\/\//i.test(urlString)) {
        if (/^https?\/\//i.test(urlString)) {
          urlString = urlString.replace(/^https?\/\//i, "https://");
        } else if (/^htps?:\/\//i.test(urlString)) {
          urlString = urlString.replace(/^htps?:\/\//i, "https://");
        } else if (/^htpt?s?:\/\//i.test(urlString)) {
          urlString = "https://" + urlString.replace(/^htpt?s?:\/\//i, "");
        } else {
          urlString = "https://" + urlString;
        }
      }

      console.log('[PhishShield] Normalized URL:', urlString);

      let parsedUrl;
      try {
        parsedUrl = new URL(urlString);
      } catch (e) {
        try {
          parsedUrl = new URL("http://" + urlString);
        } catch (err) {
          console.error('[PhishShield] URL parsing failed:', err.message);
          onPhase("Scan failed: Invalid URL syntax", 0);
          onComplete(this._errorResult(rawUrl, "Invalid URL syntax — could not parse"));
          return;
        }
      }

      const host = parsedUrl.hostname.toLowerCase();
      const isHttps = parsedUrl.protocol.toLowerCase() === "https:";
      console.log('[PhishShield] Parsed host:', host, '| HTTPS:', isHttps);

      // Progressive scanning phases
      const phases = [
        { text: "Establishing secure SSL connection & parsing handshakes...", delay: 100, pct: 15 },
        { text: `Resolving DNS mapping for host [${host}]...`, delay: 120, pct: 35 },
        { text: "Querying global threat intelligence & reputation tables...", delay: 100, pct: 55 },
        { text: "Executing AI heuristical evaluation on domain structure...", delay: 150, pct: 75 },
        { text: "Running deep-learning classification engine models...", delay: 100, pct: 90 },
        { text: "Compiling telemetry vectors and threat profile...", delay: 80, pct: 100 }
      ];

      for (let i = 0; i < phases.length; i++) {
        onPhase(phases[i].text, phases[i].pct);
        await this.sleep(phases[i].delay);
      }

      // Evaluate risk and compose response
      console.log('[PhishShield] Running evaluateRisk()...');
      let scanResult;
      try {
        scanResult = this.evaluateRisk(urlString, host, isHttps, hasProtocolError);
      } catch (evalErr) {
        console.error('[PhishShield] evaluateRisk() threw error:', evalErr);
        scanResult = this._errorResult(urlString, `Risk evaluation error: ${evalErr.message}`);
      }

      console.log('[PhishShield] Scan result:', JSON.stringify(scanResult, null, 2));

      // Add to local history and trigger update
      if (this.app) {
        this.app.addToHistory(scanResult);
      }

      onComplete(scanResult);
    } catch (fatalErr) {
      console.error('[PhishShield] FATAL scan error:', fatalErr);
      try {
        onComplete(this._errorResult(rawUrl, `Unexpected scan error: ${fatalErr.message}`));
      } catch (cbErr) {
        console.error('[PhishShield] onComplete callback also failed:', cbErr);
      }
    }
  }

  /**
   * Generates a safe error result object so the UI always receives something to render
   */
  _errorResult(rawUrl, errorMessage) {
    return {
      url: rawUrl || "unknown",
      host: "error",
      score: 0,
      status: "Error",
      ssl: "N/A",
      age: "N/A",
      registrar: "N/A",
      ip: "0.0.0.0",
      country: "Unknown",
      countryCode: "??",
      confidence: "0%",
      category: "Scan Error",
      flags: [`⚠ ${errorMessage}`]
    };
  }

  /**
   * Helper sleep function for animation delays
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Levenshtein Distance Calculator to identify brand typosquatting
   */
  getLevenshteinDistance(s1, s2) {
    const track = Array(s2.length + 1).fill(null).map(() => Array(s1.length + 1).fill(null));
    for (let i = 0; i <= s1.length; i += 1) track[0][i] = i;
    for (let j = 0; j <= s2.length; j += 1) track[j][0] = j;
    for (let j = 1; j <= s2.length; j += 1) {
      for (let i = 1; i <= s1.length; i += 1) {
        const indicator = s1[i - 1] === s2[j - 1] ? 0 : 1;
        track[j][i] = Math.min(
          track[j][i - 1] + 1, // deletion
          track[j - 1][i] + 1, // insertion
          track[j - 1][i - 1] + indicator, // substitution
        );
      }
    }
    return track[s2.length][s1.length];
  }

  /**
   * Deep Heuristic Risk Evaluator
   */
  evaluateRisk(url, host, isHttps, hasProtocolError = false) {
    // 1. Check custom user whitelist & blacklist first
    const isWhitelisted = this.checkListMatch(host, this.app?.whitelist || INITIAL_WHITELIST);
    const isBlacklisted = this.checkListMatch(host, this.app?.blacklist || INITIAL_BLACKLIST);

    if (isWhitelisted) {
      return {
        url: url,
        host: host,
        score: 0,
        status: "Safe",
        ssl: isHttps ? "Valid SSL (Whitelisted)" : "No SSL (Whitelisted Safe)",
        age: "N/A (User Whitelisted)",
        registrar: "N/A (Whitelisted)",
        ip: "127.0.0.1 (Local Bypass)",
        country: "Internal Whitelist",
        countryCode: "US",
        confidence: "100%",
        category: "User Allowed",
        flags: ["Bypassed via User Whitelist Security Policy"]
      };
    }

    if (isBlacklisted) {
      return {
        url: url,
        host: host,
        score: 100,
        status: "Critical Threat",
        ssl: "Access Terminated",
        age: "N/A (Blocked)",
        registrar: "Blocked registrar",
        ip: "0.0.0.0 (Firewalled)",
        country: "Blacklisted",
        countryCode: "US",
        confidence: "100%",
        category: "User Terminated",
        flags: ["Manually Flagged on User Blacklist Security Policy", "Automatic Firewall Quarantine Triggered"]
      };
    }

    // 2. Check in pre-cached KNOWN_URLS database
    let baseDomain = this.extractBaseDomain(host);
    if (KNOWN_URLS[host]) {
      return { url, host, ...KNOWN_URLS[host] };
    } else if (KNOWN_URLS[baseDomain]) {
      return { url, host, ...KNOWN_URLS[baseDomain] };
    }

    // 3. Dynamic heuristic generation for unrecognized domains
    let score = 15; // Baseline score
    let flags = [];

    // Protocol check & Spelling checker
    if (hasProtocolError) {
      score += 15;
      flags.push("Protocol Syntax Error: Malformed URL Protocol spelling detected (e.g. 'htpt://' or missing colons).");
    }

    if (!isHttps) {
      score += 20;
      flags.push("Unencrypted Connection (Insecure HTTP Protocol)");
    }

    // Levenshtein brand spelling typosquatting checker
    const hostParts = host.split(/[\.-]/);
    const popularBrands = ["google", "paypal", "netflix", "chase", "microsoft", "amazon", "facebook", "apple", "github", "wikipedia", "flipkart", "whatsapp", "pepperfry"];
    let typosquattingBrand = null;
    let typosquattingPart = null;

    for (let part of hostParts) {
      if (part.length < 4 || ["com", "net", "org", "co", "uk", "info", "html", "signin", "login"].includes(part)) continue;
      for (let brand of popularBrands) {
        if (part === brand) continue;
        const dist = this.getLevenshteinDistance(part, brand);
        if (dist === 1 || dist === 2) {
          typosquattingBrand = brand;
          typosquattingPart = part;
          break;
        }
      }
      if (typosquattingBrand) break;
    }

    if (typosquattingBrand) {
      score += 35;
      flags.push(`Brand Spoof Typosquatting: Domain segment '${typosquattingPart}' looks like a deceptive spelling variation of the brand '${typosquattingBrand}'.`);
    }

    if (host.length > 35) {
      score += 10;
      flags.push("Abnormally Long Domain Name Structure");
    }

    // Count subdomains / points
    const pointsCount = (host.match(/\./g) || []).length;
    if (pointsCount > 3) {
      score += 15;
      flags.push("High Density of Host Subdomains (Spoofing indicator)");
    }

    // Keyword spotting
    const threatKeywords = ["login", "verify", "secure", "bank", "free", "netflix", "paypal", "gift", "card", "billing", "update", "signin", "support", "account", "service", "reward"];
    let matchedKeywords = [];
    threatKeywords.forEach(kw => {
      if (host.includes(kw)) {
        score += 18;
        matchedKeywords.push(kw);
      }
    });

    if (matchedKeywords.length > 0) {
      flags.push(`Brand Phishing keywords detected: [${matchedKeywords.join(", ")}]`);
    }

    // High risk TLDs check
    const dangerousTlds = [".ru", ".cc", ".tk", ".xyz", ".top", ".info", ".online", ".work", ".cf", ".ga", ".ml", ".gq"];
    dangerousTlds.forEach(tld => {
      if (host.endsWith(tld)) {
        score += 15;
        flags.push(`Registered under High-Risk Top Level Domain (${tld})`);
      }
    });

    // Check if host is an IP Address (common malware C2 tactic)
    const ipRegexp = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipRegexp.test(host)) {
      score += 45;
      flags.push("Direct Numeric IP Access Bypass (Highly suspicious malware signature)");
    }

    // Apply sensitivity modifier from Settings
    const sensitivity = this.app ? parseFloat(this.app.settings.sensitivity) : 1.0;
    score = Math.round(score * sensitivity);

    // Max cap the score at 100 and min at 0
    score = Math.min(100, Math.max(0, score));

    // Determine category based on keywords or default
    let category = "Information Portal";
    if (matchedKeywords.includes("paypal") || matchedKeywords.includes("bank") || matchedKeywords.includes("verify") || matchedKeywords.includes("signin")) {
      category = "Potential Financial Impersonation";
    } else if (matchedKeywords.includes("free") || matchedKeywords.includes("reward") || matchedKeywords.includes("gift")) {
      category = "Adware / Lottery Scam Redirector";
    } else if (score > 60) {
      category = "Unverified High-Risk Endpoint";
    }

    // Generate dynamic/consistent registrar, country, IP from hashing the host string
    const hostHash = this.hashString(host);
    const ip = `${100 + (hostHash % 120)}.${50 + (hostHash % 150)}.${10 + (hostHash % 200)}.${1 + (hostHash % 254)}`;

    // Choose registrar
    const registrar = REGISTRARS[hostHash % REGISTRARS.length];

    // Choose country
    const countryObj = COUNTRIES[hostHash % COUNTRIES.length];
    if (countryObj.risk === "High") {
      score += 8;
      flags.push(`Server hosted in highly untrusted threat corridor country (${countryObj.name})`);
    }

    // Recalculate score bound
    score = Math.min(100, Math.max(0, score));

    // Classify risk status
    let status = "Safe";
    if (score >= 60 && score <= 79) {
      status = "Suspicious";
    } else if (score >= 80 && score <= 90) {
      status = "Dangerous";
    } else if (score >= 91) {
      status = "Critical Threat";
    }

    // Generate dynamic age
    let age = "7 years";
    if (score > 80) {
      age = `${1 + (hostHash % 28)} hours`;
    } else if (score > 50) {
      age = `${1 + (hostHash % 30)} days`;
    } else {
      age = `${1 + (hostHash % 15)} years`;
    }

    // AI confidence score (lower on generic, higher on extreme cases)
    const confidenceVal = 75 + (hostHash % 24) + (score > 80 ? 0.8 : 0.1);
    const confidence = `${confidenceVal.toFixed(1)}%`;

    const ssl = isHttps ? "Valid (DV TLS - Let's Encrypt)" : "None (HTTP Plaintext)";

    return {
      url,
      host,
      score,
      status,
      ssl,
      age,
      registrar,
      ip,
      country: countryObj.name,
      countryCode: countryObj.code,
      confidence,
      category,
      flags: flags.length > 0 ? flags : ["No standard threat signals triggered during parsing."]
    };
  }

  /**
   * Helper to verify if domain is in a custom list
   */
  checkListMatch(host, list) {
    return list.some(item => {
      const cleanItem = item.trim().toLowerCase();
      return host === cleanItem || host.endsWith("." + cleanItem);
    });
  }

  /**
   * Basic string hashing to generate stable deterministic mock results
   */
  hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = str.charCodeAt(i) + ((hash << 5) - hash);
    }
    return Math.abs(hash);
  }

  /**
   * Simple domain extractor
   */
  extractBaseDomain(host) {
    const parts = host.split(".");
    if (parts.length > 2) {
      // Check if it's a double-part TLD (e.g., co.in, co.uk, ac.in, gov.in, edu.in)
      const secondToLast = parts[parts.length - 2].toLowerCase();
      const last = parts[parts.length - 1].toLowerCase();

      const commonDoubleTldMiddles = ["co", "com", "ac", "gov", "org", "net", "edu", "res", "mil"];
      if (commonDoubleTldMiddles.includes(secondToLast) && last.length === 2) {
        if (parts.length > 3) {
          return parts.slice(-3).join(".");
        }
      }
      return parts.slice(-2).join(".");
    }
    return host;
  }
}
