/**
 * PhishShield Threat Intelligence - Mock Databases
 * Provides structured static lookup data, reputation patterns, and logs for scanning simulation.
 */

const KNOWN_URLS = {
  // Safe / Normal Sites (Score 0 - 30)
  "google.com": {
    score: 8,
    status: "Safe",
    ssl: "Valid (SHA-256)",
    age: "28 years",
    registrar: "MarkMonitor, Inc.",
    ip: "142.250.190.46",
    country: "United States",
    countryCode: "US",
    confidence: "99.8%",
    category: "Search Engine",
    flags: ["No standard threat signals triggered during parsing."]
  },
  "github.com": {
    score: 12,
    status: "Safe",
    ssl: "Valid (DigiCert)",
    age: "18 years",
    registrar: "MarkMonitor, Inc.",
    ip: "140.82.112.4",
    country: "United States",
    countryCode: "US",
    confidence: "99.2%",
    category: "Software & Technology",
    flags: ["No standard threat signals triggered during parsing."]
  },
  "wikipedia.org": {
    score: 5,
    status: "Safe",
    ssl: "Valid (Let's Encrypt)",
    age: "25 years",
    registrar: "MarkMonitor, Inc.",
    ip: "208.80.154.224",
    country: "United States",
    countryCode: "US",
    confidence: "99.9%",
    category: "Education & Reference",
    flags: ["No standard threat signals triggered during parsing."]
  },
  "microsoft.com": {
    score: 7,
    status: "Safe",
    ssl: "Valid (Microsoft IT)",
    age: "35 years",
    registrar: "MarkMonitor, Inc.",
    ip: "20.112.52.29",
    country: "United States",
    countryCode: "US",
    confidence: "99.6%",
    category: "Software & Technology",
    flags: ["No standard threat signals triggered during parsing."]
  },

  // Indian Commerce & Education Safe Sites
  "pepperfry.com": {
    score: 10,
    status: "Safe",
    ssl: "Valid (Amazon RSA)",
    age: "14 years",
    registrar: "GoDaddy.com, LLC",
    ip: "13.227.188.43",
    country: "India",
    countryCode: "IN",
    confidence: "97.5%",
    category: "E-Commerce & Furniture",
    flags: ["No standard threat signals triggered during parsing."]
  },
  "whatsapp.com": {
    score: 8,
    status: "Safe",
    ssl: "Valid (DigiCert SHA-256)",
    age: "17 years",
    registrar: "MarkMonitor, Inc.",
    ip: "157.240.22.60",
    country: "United States",
    countryCode: "US",
    confidence: "99.7%",
    category: "Social Networking & Communication",
    flags: ["No standard threat signals triggered during parsing."]
  },
  "amazon.in": {
    score: 10,
    status: "Safe",
    ssl: "Valid (DigiCert)",
    age: "13 years",
    registrar: "MarkMonitor, Inc.",
    ip: "52.95.120.21",
    country: "India",
    countryCode: "IN",
    confidence: "99.1%",
    category: "E-Commerce & Retail",
    flags: ["No standard threat signals triggered during parsing."]
  },
  "flipkart.com": {
    score: 6,
    status: "Safe",
    ssl: "Valid (DigiCert SHA-256)",
    age: "18 years",
    registrar: "GoDaddy.com, LLC",
    ip: "163.53.78.128",
    country: "India",
    countryCode: "IN",
    confidence: "99.4%",
    category: "E-Commerce & Retail",
    flags: ["No standard threat signals triggered during parsing."]
  },
  "shopsy.in": {
    score: 12,
    status: "Safe",
    ssl: "Valid (DigiCert)",
    age: "5 years",
    registrar: "GoDaddy.com, LLC",
    ip: "163.53.78.130",
    country: "India",
    countryCode: "IN",
    confidence: "96.8%",
    category: "E-Commerce (Flipkart Group)",
    flags: ["No standard threat signals triggered during parsing."]
  },
  "avniet.ac.in": {
    score: 14,
    status: "Safe",
    ssl: "Valid (Let's Encrypt)",
    age: "8 years",
    registrar: "NIXI (.in Registry)",
    ip: "103.146.22.56",
    country: "India",
    countryCode: "IN",
    confidence: "95.2%",
    category: "Education & Academic Institution",
    flags: ["No standard threat signals triggered during parsing."]
  },
  "tkrcet.in": {
    score: 15,
    status: "Safe",
    ssl: "Valid (Let's Encrypt)",
    age: "10 years",
    registrar: "NIXI (.in Registry)",
    ip: "103.21.58.192",
    country: "India",
    countryCode: "IN",
    confidence: "94.8%",
    category: "Education & Engineering College",
    flags: ["No standard threat signals triggered during parsing."]
  },

  // Suspicious Sites (Score 31 - 59)
  "free-netflix-promo.com": {
    score: 48,
    status: "Suspicious",
    ssl: "Valid (Cloudflare Inc)",
    age: "12 days",
    registrar: "Namecheap, Inc.",
    ip: "104.21.36.192",
    country: "Canada",
    countryCode: "CA",
    confidence: "82.4%",
    category: "Entertainment (Unverified)",
    flags: ["Short Domain Age", "Misleading Brand Keywords", "No Corporate Association"]
  },
  "verify-steam-gift.ru": {
    score: 52,
    status: "Suspicious",
    ssl: "Invalid (Expired 2 days ago)",
    age: "3 months",
    registrar: "REGRU-RU",
    ip: "91.228.152.12",
    country: "Russian Federation",
    countryCode: "RU",
    confidence: "87.1%",
    category: "Gaming Promotion",
    flags: ["Expired SSL Certificate", "High-Risk Top-Level Domain (.ru)", "Suspicious Subdomain Structure"]
  },
  "meta-rewards-login.net": {
    score: 44,
    status: "Suspicious",
    ssl: "Valid (Let's Encrypt)",
    age: "24 days",
    registrar: "Hostinger",
    ip: "185.119.173.8",
    country: "Germany",
    countryCode: "DE",
    confidence: "79.5%",
    category: "Social Network Mock",
    flags: ["Recently Registered Domain", "Targeting Brand: Meta"]
  },

  // Fraud / Dangerous (Score 60 - 90)
  "paypal-security-update.com": {
    score: 78,
    status: "Dangerous",
    ssl: "None (HTTP Only)",
    age: "2 days",
    registrar: "NameSilo, LLC",
    ip: "192.99.14.205",
    country: "Ukraine",
    countryCode: "UA",
    confidence: "94.6%",
    category: "Phishing Target: PayPal",
    flags: ["No SSL/TLS Encryption", "Brand Phishing Trigger: 'paypal'", "Active Credential Harvesting Attempt"]
  },
  "chase-onlinebanking-signin.net": {
    score: 84,
    status: "Dangerous",
    ssl: "Valid (Let's Encrypt - Free)",
    age: "5 days",
    registrar: "Public Domain Registry",
    ip: "45.142.120.33",
    country: "Romania",
    countryCode: "RO",
    confidence: "96.2%",
    category: "Financial Fraud",
    flags: ["Free SSL on Banking Term", "Targeting Brand: Chase", "High Risk IP Block"]
  },
  "walmart-giftcard-winner.org": {
    score: 72,
    status: "Dangerous",
    ssl: "Valid (ZeroSSL)",
    age: "1 week",
    registrar: "Namecheap, Inc.",
    ip: "198.54.117.200",
    country: "Turkey",
    countryCode: "TR",
    confidence: "91.8%",
    category: "Giftcard Scam",
    flags: ["Clickbait Redirect Chain", "Brand Impersonation: Walmart", "Scrape Script Detected"]
  },

  // Critical Threat (Score 91 - 100)
  "system-security-alert-09a.exe-download.com": {
    score: 98,
    status: "Critical Threat",
    ssl: "None",
    age: "6 hours",
    registrar: "Porkbun LLC",
    ip: "109.236.88.94",
    country: "Netherlands",
    countryCode: "NL",
    confidence: "99.7%",
    category: "Malware Distribution",
    flags: ["Executable Payload Delivery", "Active Command & Control (C2) Server IP", "Direct Drive-By Download Hook"]
  },
  "bankofamerica-login-verify.com": {
    score: 95,
    status: "Critical Threat",
    ssl: "Self-Signed Certificate",
    age: "18 hours",
    registrar: "Tucows Domains Inc.",
    ip: "185.220.101.4",
    country: "Iceland",
    countryCode: "IS",
    confidence: "99.1%",
    category: "Bank Phishing / Credential Leak",
    flags: ["Self-Signed SSL Certificate", "Direct Banking Login Copycat", "Suspicious Form Submissions"]
  }
};

const REGISTRARS = [
  "Namecheap, Inc.",
  "GoDaddy.com, LLC",
  "Tucows Domains Inc.",
  "Porkbun LLC",
  "MarkMonitor, Inc.",
  "Hostinger",
  "NameSilo, LLC",
  "Dynadot Inc",
  "Cloudflare, Inc."
];

const COUNTRIES = [
  { name: "United States", code: "US", risk: "Low" },
  { name: "Germany", code: "DE", risk: "Low" },
  { name: "Netherlands", code: "NL", risk: "Medium" },
  { name: "Canada", code: "CA", risk: "Low" },
  { name: "Russian Federation", code: "RU", risk: "High" },
  { name: "Ukraine", code: "UA", risk: "Medium" },
  { name: "Romania", code: "RO", risk: "High" },
  { name: "Iceland", code: "IS", risk: "Low" },
  { name: "Brazil", code: "BR", risk: "Medium" },
  { name: "Singapore", code: "SG", risk: "Low" },
  { name: "China", code: "CN", risk: "High" }
];

const THREAT_FEED_TEMPLATES = [
  { type: "Credential Phishing", path: "/login/verification/chase" },
  { type: "Malware Drop", path: "/payloads/update.exe" },
  { type: "Cryptojacking Script", path: "/miner/coinhive.js" },
  { type: "Ransomware Distribution", path: "/assets/lock.pdf" },
  { type: "Social Engineering Scam", path: "/rewards/giftcard" }
];

const INITIAL_SCAN_HISTORY = [
  { url: "https://google.com", score: 8, status: "Safe", timestamp: "5 mins ago" },
  { url: "http://paypal-security-update.com/signin", score: 78, status: "Dangerous", timestamp: "12 mins ago" },
  { url: "https://wikipedia.org/wiki/Phishing", score: 5, status: "Safe", timestamp: "1 hour ago" },
  { url: "https://free-netflix-promo.com/gift", score: 48, status: "Suspicious", timestamp: "2 hours ago" },
  { url: "http://system-security-alert-09a.exe-download.com", score: 98, status: "Critical Threat", timestamp: "4 hours ago" }
];

const INITIAL_WHITELIST = [
  "google.com",
  "github.com",
  "wikipedia.org",
  "microsoft.com",
  "youtube.com",
  "amazon.com",
  "facebook.com",
  "whatsapp.com",
  "amazon.in",
  "flipkart.com",
  "pepperfry.com"
];

const INITIAL_BLACKLIST = [
  "hackers-portal.net",
  "crypto-double-your-btc.com",
  "login-banking-secure-routing.net",
  "steal-your-credentials.org",
  "free-steam-codes-2026.ru"
];
