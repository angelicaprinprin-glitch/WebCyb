/*
 * WebCyb phishing detector
 * Runs entirely in the browser: the email you paste is never sent anywhere or stored.
 *
 * How it works:
 *   1. Keyword rules: looks for words and phrases scammers use (English and Spanish).
 *   2. Link rules: fake brand links, lookalike spellings, hidden destinations, risky domains.
 *   3. Sender rules: fake display names, free email accounts, mismatched Reply-To.
 *   4. Attachment and formatting rules.
 * Every finding adds points. The total score (0-100) gives the risk level.
 */
const WebCyb = (() => {
  // ---------- 1. Keyword rules ----------
  // points: added per phrase found. max: most points the category can add.
  const KEYWORD_RULES = [
    {
      id: "urgency", label: "Urgent language", points: 8, max: 25,
      explain: "it tries to rush you into acting before you think",
      words: ["urgent", "urgently", "immediately", "immediate action", "act now", "act fast", "right away",
        "as soon as possible", "asap", "within 24 hours", "within 48 hours", "within 12 hours", "within 72 hours",
        "today only", "expires today", "expire", "expires", "expiring", "final notice", "final warning",
        "last warning", "last chance", "time sensitive", "time-sensitive", "deadline", "don't delay",
        "do not ignore", "respond now", "reply now", "limited time", "before it's too late", "action required",
        "immediate attention", "attention required", "important notice", "failure to comply", "failure to respond",
        "urgente", "inmediatamente", "de inmediato", "último aviso", "ultimo aviso", "tiempo limitado", "acción requerida"],
    },
    {
      id: "threat", label: "Threats", points: 12, max: 30,
      explain: "it threatens you with closing your account, fines or legal trouble",
      words: ["account suspended", "account will be suspended", "account has been suspended", "account will be closed",
        "account will be locked", "account has been locked", "temporarily locked", "permanently deleted",
        "permanently closed", "will be deactivated", "has been deactivated", "will be terminated", "legal action",
        "lawsuit", "arrest warrant", "warrant for your arrest", "penalty", "late fee", "collection agency",
        "will be reported", "unauthorized access", "security breach", "your account has been compromised",
        "you have been hacked", "loss of access", "lose access",
        "cuenta suspendida", "cuenta bloqueada", "su cuenta será bloqueada", "su cuenta sera bloqueada",
        "será suspendida", "acción legal", "accion legal", "multa"],
    },
    {
      id: "account", label: "Fake security alert", points: 10, max: 25,
      explain: "it uses a fake security alert about your account",
      words: ["unusual activity", "suspicious activity", "unusual sign-in", "unusual sign in", "suspicious login",
        "suspicious sign-in", "login attempt", "sign-in attempt", "unrecognized device", "new device",
        "verify your account", "confirm your account", "validate your account", "confirm your identity",
        "verify your identity", "reactivate your account", "restore access", "restore your account",
        "unlock your account", "update your account", "update your information", "update your details",
        "password expires", "password will expire", "password reset", "reset your password", "security alert",
        "security update", "mailbox is full", "mailbox full", "storage is full", "storage full", "quota exceeded",
        "email will be deactivated", "account verification", "verification required",
        "actividad inusual", "actividad sospechosa", "verifique su cuenta", "verificar su cuenta",
        "confirme su identidad", "actualice sus datos", "restablecer su contraseña"],
    },
    {
      id: "personal", label: "Asks for personal information", points: 15, max: 40,
      explain: "it asks for private information like passwords, codes or card numbers",
      words: ["password", "passcode", "social security", "ssn", "credit card", "card number", "debit card", "cvv",
        "cvc", "security code", "bank account", "account number", "routing number", "pin", "pin number",
        "login credentials", "username and password", "date of birth", "mother's maiden name", "driver's license",
        "passport number", "tax id", "security question", "one-time code", "one time code", "verification code",
        "otp", "2fa code", "billing information", "billing details", "payment details", "payment information",
        "update your payment", "full name and address", "home address", "photo of your id",
        "contraseña", "contrasena", "número de tarjeta", "numero de tarjeta", "tarjeta de crédito",
        "tarjeta de credito", "datos bancarios", "código de verificación", "codigo de verificacion",
        "confirme sus datos", "número de seguro social"],
    },
    {
      id: "money", label: "Money or payment request", points: 12, max: 30,
      explain: "it asks you to pay or move money, often in ways that can't be refunded",
      words: ["wire transfer", "bank transfer", "western union", "moneygram", "gift card", "gift cards",
        "itunes card", "google play card", "steam card", "bitcoin", "btc", "cryptocurrency", "crypto wallet",
        "usdt", "ethereum", "tax refund", "overpayment", "outstanding balance", "unpaid invoice", "payment failed",
        "payment declined", "payment overdue", "processing fee", "transfer fee", "customs fee", "small fee",
        "send money", "cash app", "zelle", "venmo", "pay now", "purchase gift cards",
        "transferencia", "tarjeta de regalo", "reembolso", "pago pendiente", "pago rechazado"],
    },
    {
      id: "prize", label: "Too good to be true", points: 10, max: 25,
      explain: "it promises prizes, money or rewards that are too good to be true",
      words: ["you have won", "you've won", "you are a winner", "you're a winner", "winner", "lottery", "jackpot",
        "claim your prize", "claim your reward", "cash prize", "congratulations", "you have been selected",
        "you've been selected", "free gift", "free iphone", "free money", "sweepstakes", "giveaway",
        "exclusive offer", "100% free", "risk-free", "risk free", "guaranteed income",
        "ganador", "felicidades", "felicitaciones", "premio", "ha ganado", "has ganado", "gratis"],
    },
    {
      id: "advance", label: "Advance-fee scam", points: 15, max: 35,
      explain: "it looks like an inheritance or 'big money transfer' scam",
      words: ["inheritance", "beneficiary", "next of kin", "million dollars", "millions of dollars", "transfer of funds",
        "unclaimed funds", "foreign bank", "barrister", "diplomat", "consignment", "compensation fund",
        "business proposal", "strictly confidential", "confidential transaction", "late husband", "deceased client",
        "herencia", "beneficiario", "fondos no reclamados"],
    },
    {
      id: "delivery", label: "Fake delivery notice", points: 7, max: 15,
      explain: "it uses a fake package or delivery problem",
      words: ["delivery failed", "failed delivery", "delivery attempt", "unable to deliver", "could not be delivered",
        "redelivery", "reschedule delivery", "held at customs", "shipping fee", "confirm your address",
        "address confirmation", "parcel is on hold", "package is on hold",
        "paquete retenido", "entrega fallida", "no pudimos entregar"],
    },
    {
      id: "job", label: "Job or easy-money offer", points: 10, max: 20,
      explain: "it offers easy money or a job you never applied for",
      words: ["work from home", "earn money", "easy money", "part-time job", "job offer", "hiring immediately",
        "no experience needed", "no experience required", "data entry job", "mystery shopper",
        "personal assistant position", "earn $", "per week from home", "trabajo desde casa", "dinero fácil"],
    },
    {
      id: "techsupport", label: "Fake tech support", points: 15, max: 30,
      explain: "it pretends your device has a problem and asks you to call or install something",
      words: ["virus detected", "your computer is infected", "your device is infected", "malware detected",
        "call this number", "call support", "tech support", "technical support", "microsoft support",
        "apple support", "remote access", "install this software", "toll-free", "toll free"],
    },
    {
      id: "action", label: "Pushes you to click", points: 6, max: 15,
      explain: "it pushes you to click a link or open a file",
      words: ["click here", "click below", "click the link", "click on the link", "click the button", "tap here",
        "follow the link", "open the attachment", "download the attachment", "download now", "log in here",
        "login here", "sign in here", "sign in now", "verify here", "verify now", "update now", "confirm now",
        "scan the qr code", "qr code", "haga clic aquí", "haga clic aqui", "haz clic aquí", "haz clic aqui",
        "ingrese aquí", "descargue"],
    },
    {
      id: "secrecy", label: "Asks for secrecy", points: 12, max: 20,
      explain: "it asks you to keep it secret, so nobody can warn you",
      words: ["do not share this", "don't tell anyone", "keep this confidential", "keep this between us",
        "do not contact", "do not discuss", "no le diga a nadie", "confidencial"],
    },
    {
      id: "greeting", label: "Generic greeting", points: 10, max: 10,
      explain: "it doesn't use your real name",
      words: ["dear customer", "dear user", "dear client", "dear account holder", "dear sir", "dear madam",
        "dear sir/madam", "dear member", "dear valued customer", "dear email user", "dear beneficiary",
        "dear friend", "valued customer", "hello user", "estimado cliente", "estimado usuario",
        "querido cliente", "estimado miembro"],
    },
    {
      id: "grammar", label: "Unusual wording", points: 6, max: 12,
      explain: "it uses odd wording common in scam emails",
      words: ["kindly", "do the needful", "revert back", "verify you account", "your are", "dear esteemed",
        "we detected that you", "the undersigned"],
    },
  ];

  // ---------- 2. Brands and domains ----------
  const BRANDS = ["paypal", "amazon", "apple", "icloud", "microsoft", "office365", "outlook", "netflix", "google",
    "gmail", "facebook", "instagram", "whatsapp", "meta", "linkedin", "twitter", "chase", "wellsfargo",
    "bankofamerica", "citibank", "capitalone", "usbank", "dhl", "fedex", "ups", "usps", "irs", "ebay", "walmart",
    "costco", "coinbase", "binance", "venmo", "zelle", "spotify", "adobe", "dropbox", "docusign", "steam",
    "roblox", "tiktok", "santander", "bbva", "hulu", "disney", "verizon", "att", "tmobile", "xfinity"];
  // Real domains a brand also uses
  const BRAND_ALIASES = {
    google: ["gmail", "youtube"], microsoft: ["live", "outlook", "office", "office365", "hotmail", "xbox"],
    apple: ["icloud", "me"], meta: ["facebook", "instagram", "whatsapp"], facebook: ["meta", "fb"],
    instagram: ["meta"], twitter: ["x"], amazon: ["amazonaws", "aws"],
  };
  const FREE_MAIL = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com",
    "protonmail.com", "proton.me", "gmx.com", "mail.ru", "yandex.com", "zoho.com", "live.com", "ymail.com"];
  const URL_SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "lnkd.in"];
  const RISKY_TLDS = ["xyz", "top", "click", "zip", "mov", "ru", "tk", "ml", "ga", "cf", "gq", "work", "info",
    "live", "shop", "online", "site", "icu", "buzz", "rest", "cam", "monster", "support", "help", "loan", "win"];
  const LURE_WORDS_IN_LINK = ["login", "log-in", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "billing", "password", "unlock", "wallet", "support", "refund"];
  const RISKY_EXT = ["exe", "scr", "js", "vbs", "bat", "cmd", "msi", "jar", "zip", "rar", "7z", "iso", "img",
    "html", "htm", "docm", "xlsm", "pptm", "lnk", "apk", "dmg", "pkg", "hta", "ps1"];
  const SECOND_LEVEL = ["co", "com", "org", "net", "gov", "edu", "ac"];

  // ---------- helpers ----------
  const escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const phraseRe = w => new RegExp("(?<![\\p{L}\\p{N}])" + escapeRe(w) + "(?![\\p{L}\\p{N}])", "iu");
  const COMPILED = KEYWORD_RULES.map(r => ({ ...r, regs: r.words.map(w => [w, phraseRe(w)]) }));
  const title = s => s.charAt(0).toUpperCase() + s.slice(1);
  const quoteList = ws => ws.slice(0, 5).map(w => `"${w}"`).join(", ");

  function hostOf(url) {
    try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
  }
  // "secure.paypal.co.uk" -> "paypal"   "paypal-login.xyz" -> "paypal-login"
  function mainLabel(host) {
    const parts = host.split(".").filter(Boolean);
    if (parts.length >= 3 && SECOND_LEVEL.includes(parts[parts.length - 2])) return parts[parts.length - 3];
    return parts.length >= 2 ? parts[parts.length - 2] : parts[0] || "";
  }
  const tld = host => host.split(".").pop();
  // Undo tricks like paypa1, amaz0n, rnicrosoft
  const unLookalike = s => s.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/4/g, "a")
    .replace(/5/g, "s").replace(/7/g, "t").replace(/rn/g, "m").replace(/vv/g, "w");

  // Which brand does this domain *claim* to be (if any)?
  function claimedBrand(host) {
    const tokens = host.split(/[.\-_]/);
    const check = toks => BRANDS.find(b => toks.some(t => b.length <= 4 ? t === b : t.includes(b)));
    const direct = check(tokens);
    if (direct) return { brand: direct, lookalike: false };
    const fixed = check(tokens.map(unLookalike));
    return fixed ? { brand: fixed, lookalike: true } : null;
  }
  function isRealBrandDomain(host, brand) {
    const label = mainLabel(host);
    return label === brand || (BRAND_ALIASES[brand] || []).includes(label);
  }

  // ---------- main analysis ----------
  function analyze(emailText) {
    const text = emailText.normalize("NFC");
    const lower = text.toLowerCase();
    const findings = []; // { points, category, detail, explain }
    const add = (points, category, detail, explain) => findings.push({ points, category, detail, explain });

    // 1. Keyword rules
    for (const rule of COMPILED) {
      const hits = rule.regs.filter(([, re]) => re.test(text)).map(([w]) => w);
      if (hits.length) add(Math.min(rule.points * hits.length, rule.max), rule.label,
        `Uses phrases like ${quoteList(hits)}`, rule.explain);
    }

    // 2. Link rules
    const urls = [...new Set(text.match(/(?:https?:\/\/|www\.)[^\s<>"'()\[\]]+/gi) || [])]
      .map(u => u.replace(/[.,;:!?]+$/, ""));
    const linkExplain = "it contains links that don't go where they claim to";
    for (const url of urls) {
      const full = /^https?:/i.test(url) ? url : "http://" + url;
      const host = hostOf(full);
      if (!host) continue;
      if (/^https?:\/\/\d{1,3}(\.\d{1,3}){3}/i.test(full))
        add(25, "Suspicious link", `Link uses a number address instead of a website name: ${url}`, linkExplain);
      if (URL_SHORTENERS.some(s => host === s || host.endsWith("." + s)))
        add(15, "Suspicious link", `Link is shortened, hiding where it really goes: ${url}`, linkExplain);
      if (RISKY_TLDS.includes(tld(host)))
        add(15, "Suspicious link", `Link ends in ".${tld(host)}", an ending often used by scammers: ${host}`, linkExplain);
      if (/^https?:\/\/[^/]*@/i.test(full))
        add(25, "Suspicious link", `Link uses an "@" trick to hide its real destination: ${url}`, linkExplain);
      if (host.includes("xn--"))
        add(25, "Suspicious link", `Link uses look-alike foreign letters to copy a real website: ${host}`, linkExplain);
      const claim = claimedBrand(host);
      if (claim && !isRealBrandDomain(host, claim.brand)) {
        add(25, "Suspicious link", claim.lookalike
          ? `Link misspells ${title(claim.brand)} to trick you: ${host}`
          : `Link pretends to be ${title(claim.brand)} but goes to ${host}`, linkExplain);
      } else if (!claim && LURE_WORDS_IN_LINK.some(w => host.includes(w))) {
        add(10, "Suspicious link", `Link uses words like "login" or "secure" to look official: ${host}`, linkExplain);
      }
      if (host.split(".").length >= 5)
        add(10, "Suspicious link", `Link has an unusually long web address: ${host}`, linkExplain);
      if (/^http:\/\//i.test(url))
        add(5, "Suspicious link", `Link is not secure (starts with http, not https): ${url}`, linkExplain);
    }
    if (urls.length >= 6) add(10, "Suspicious link", `The email contains many links (${urls.length})`, linkExplain);
    if (/\b(?:javascript|data):/i.test(text))
      add(25, "Suspicious link", "Contains hidden code links (javascript: or data:)", linkExplain);

    // 3. Sender rules (reads "From:" / "Reply-To:" lines if pasted)
    const senderExplain = "the sender isn't who they claim to be";
    const header = name => {
      const m = text.match(new RegExp("^\\s*" + name + "\\s*:\\s*(.+)$", "im"));
      if (!m) return null;
      const line = m[1].trim();
      const addr = (line.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/) || [""])[0].toLowerCase();
      const display = line.replace(/<[^>]*>/, "").replace(addr, "").replace(/["']/g, "").trim().toLowerCase();
      return { addr, display, domain: addr.split("@")[1] || "" };
    };
    const from = header("from") || header("de");
    const replyTo = header("reply-to") || header("responder a");
    const allAddrs = [...new Set((text.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g) || []).map(a => a.toLowerCase()))];

    if (from && from.domain) {
      const nameBrand = BRANDS.find(b => from.display.replace(/\s+/g, "").includes(b));
      if (nameBrand && !isRealBrandDomain(from.domain, nameBrand))
        add(25, "Fake sender", `The sender name says "${title(nameBrand)}" but the email comes from ${from.domain}`, senderExplain);
      if (FREE_MAIL.includes(from.domain) && (nameBrand || /support|security|team|service|billing|bank|admin|help|ceo|manager|director|payroll|hr/.test(from.display)))
        add(20, "Fake sender", `A company message sent from a free personal email account (${from.domain})`, senderExplain);
      if (replyTo && replyTo.domain && mainLabel(replyTo.domain) !== mainLabel(from.domain))
        add(20, "Fake sender", `Replies would go to a different address (${replyTo.addr}) than the sender (${from.addr})`, senderExplain);
    }
    for (const addr of allAddrs) {
      const domain = addr.split("@")[1];
      const claim = claimedBrand(domain);
      if (claim && !isRealBrandDomain(domain, claim.brand) && !FREE_MAIL.includes(domain))
        add(25, "Fake sender", claim.lookalike
          ? `Email address misspells ${title(claim.brand)}: ${addr}`
          : `Email address imitates ${title(claim.brand)}: ${addr}`, senderExplain);
      if (/\d{4,}/.test(mainLabel(domain)))
        add(10, "Fake sender", `Email address looks automatically generated: ${addr}`, senderExplain);
      if (RISKY_TLDS.includes(tld(domain)))
        add(10, "Fake sender", `Email address ends in ".${tld(domain)}", often used by scammers: ${addr}`, senderExplain);
    }

    // Phone number + "call" is a classic tech-support or bank scam move
    if (/\b(?:call|llame|llamar)\b/i.test(text) && /(?:\+?\d[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}/.test(text))
      add(15, "Fake tech support", "Asks you to call a phone number written in the email",
        "it pretends your device has a problem and asks you to call or install something");

    // 4. Attachments
    const fileExplain = "it includes a file type that can install malware";
    const double = text.match(new RegExp("\\b[\\w-]+\\.(?:pdf|doc|docx|jpg|png|txt|xls|xlsx)\\.(?:" + RISKY_EXT.join("|") + ")\\b", "i"));
    if (double) add(50, "Dangerous attachment", `File with a hidden double ending: ${double[0]}`, fileExplain);
    const files = [...new Set((text.match(new RegExp("\\b[\\w-]+\\.(?:" + RISKY_EXT.join("|") + ")\\b", "gi")) || [])
      .filter(f => !urls.some(u => u.toLowerCase().includes(f.toLowerCase()))))];
    if (files.length && !double)
      add(20, "Dangerous attachment", `Mentions a risky file: ${files.slice(0, 4).join(", ")}`, fileExplain);

    // 5. Formatting
    const formatExplain = "it uses loud formatting to create panic";
    const capsWords = (text.match(/\b[A-Z]{4,}\b/g) || []).filter(w => !["HTTP", "HTTPS", "HTML"].includes(w));
    if (capsWords.length >= 4) add(8, "Pressure formatting", `Lots of words in CAPITAL LETTERS (${capsWords.length})`, formatExplain);
    if (/!{2,}/.test(text) || (text.match(/!/g) || []).length >= 4)
      add(5, "Pressure formatting", "Many exclamation marks", formatExplain);
    if (/[$€£]\s?\d{1,3}(?:[,.]\d{3}){2,}/.test(text) || /\b\d+(?:\.\d+)?\s?million\b/i.test(lower))
      add(10, "Pressure formatting", "Mentions a very large amount of money", formatExplain);

    // ---------- score ----------
    const score = Math.min(findings.reduce((s, f) => s + f.points, 0), 100);
    const level = score >= 50 ? "High" : score >= 20 ? "Medium" : "Low";
    const verdict = { High: "Phishing", Medium: "Suspicious", Low: "Likely safe" }[level];

    // Group findings by category for display
    const groups = [];
    for (const f of findings) {
      let g = groups.find(x => x.category === f.category);
      if (!g) groups.push(g = { category: f.category, explain: f.explain, points: 0, details: [] });
      g.points += f.points; g.details.push(f.detail);
    }
    groups.sort((a, b) => b.points - a.points);

    return { score, level, verdict, groups, advice: ADVICE[level], reply: agentReply(level, groups) };
  }

  const ADVICE = {
    High: ["Do not click any links or open any attachments.",
      "Do not reply, and never send passwords, codes or card numbers.",
      "If you are worried about your account, type the company's official website yourself or call their official number.",
      "Report the email as phishing in your email app, then delete it.",
      "If you already clicked or shared information, change your password right away and contact your bank."],
    Medium: ["Be careful: don't click or reply yet.",
      "Check the sender's address and where links really go (hover over them on a computer).",
      "Contact the company or person through a website or number you already trust to confirm."],
    Low: ["No strong phishing signs were found.",
      "Still, never share passwords or codes by email, and verify anything that feels off."],
  };

  // Short plain-language reply written from the findings
  function agentReply(level, groups) {
    const signs = groups.slice(0, 4).map(g => g.explain);
    const list = a => a.length < 2 ? a.join("") : a.slice(0, -1).join(", ") + ", and " + a[a.length - 1];
    if (level === "High")
      return `This email is very likely a phishing attempt. The main warning signs are that ${list(signs)}. ` +
        "Please don't click anything or reply. If you think your account might really have a problem, go to the company's official website on your own.";
    if (level === "Medium")
      return `This email looks suspicious because ${list(signs)}. It might be harmless, but treat it with care ` +
        "and confirm with the sender through a way you already trust before you click or reply.";
    return signs.length
      ? `No strong phishing signs were found, although ${list(signs)}. It is probably fine, but stay alert.`
      : "No common phishing signs were found. It looks safe, but if anything feels off, check with the sender another way.";
  }

  return { analyze };
})();

if (typeof module !== "undefined") module.exports = WebCyb;
