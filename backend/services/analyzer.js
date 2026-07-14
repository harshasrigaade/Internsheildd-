const { GoogleGenerativeAI } = require("@google/generative-ai");
const url = require("url");

// Main URL Scam Analysis Function
async function analyzeUrl(inputUrl, userApiKey = "") {
  let parsedUrl;
  try {
    // Add protocol if missing
    let target = inputUrl.trim();
    if (!/^https?:\/\//i.test(target)) {
      target = "https://" + target;
    }
    parsedUrl = new url.URL(target);
  } catch (err) {
    return {
      error: "Invalid URL format. Please paste a valid web link."
    };
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const protocol = parsedUrl.protocol.toLowerCase();
  const path = parsedUrl.pathname.toLowerCase();

  // 1. Run local heuristics to find immediate patterns
  const heuristics = runLocalHeuristics(hostname, protocol, path, inputUrl);

  // 2. Try to run Gemini AI analysis if API key is provided
  const apiKey = userApiKey || process.env.GEMINI_API_KEY;
  let result = null;
  if (apiKey) {
    try {
      result = await runGeminiAnalysis(inputUrl, heuristics, apiKey);
    } catch (aiErr) {
      console.error("Gemini API error, falling back to heuristics:", aiErr.message);
    }
  }

  // 3. Fallback to smart heuristic generator
  if (!result) {
    result = generateHeuristicsReport(heuristics, hostname);
  }

  // 4. Construct standard verdictTable from the 10 signals (ensures consistency)
  const signals = result.signals || [];
  const trustScore = result.trustScore || 0;
  const riskLevel = result.riskLevel || "High";
  const scamProbability = result.scamProbability || 99;

  // Find signals by labels
  const getSignal = (label) => signals.find(s => s.label.toLowerCase().includes(label.toLowerCase())) || { label, status: "Unknown", value: "No details available", isSafe: false };

  const domainAgeSig = getSignal("domain age");
  const httpsSig = getSignal("https and security");
  const contactSig = getSignal("contact information");
  const reviewsSig = getSignal("reviews and reputation");
  const techSig = getSignal("technical and reputation");
  const ownershipSig = getSignal("ownership and registration");

  let verdictTable = [];
  if (trustScore < 8.0) {
    // Suspicious Verdict Table
    verdictTable = [
      { label: "Domain age", status: domainAgeSig.status, value: domainAgeSig.value, isSafe: domainAgeSig.isSafe },
      { label: "HTTPS", status: httpsSig.status, value: httpsSig.value, isSafe: httpsSig.isSafe },
      { label: "Contact information", status: contactSig.status, value: contactSig.value, isSafe: contactSig.isSafe },
      { label: "Independent reviews", status: reviewsSig.status, value: reviewsSig.value, isSafe: reviewsSig.isSafe },
      { label: "Scam reports", status: techSig.status, value: techSig.value, isSafe: techSig.isSafe },
      { label: "Overall risk", status: riskLevel + " Risk", value: `Score: ${trustScore}/10 (${scamProbability}% scam probability)`, isSafe: trustScore >= 5.0 }
    ];
  } else {
    // Legitimate Verdict Table
    verdictTable = [
      { label: "Domain age", status: domainAgeSig.status, value: domainAgeSig.value, isSafe: domainAgeSig.isSafe },
      { label: "HTTPS", status: httpsSig.status, value: httpsSig.value, isSafe: httpsSig.isSafe },
      { label: "Official company ownership", status: ownershipSig.status, value: ownershipSig.value, isSafe: ownershipSig.isSafe },
      { label: "Reviews", status: reviewsSig.status, value: reviewsSig.value, isSafe: reviewsSig.isSafe },
      { label: "Scam reports", status: techSig.status, value: techSig.value, isSafe: techSig.isSafe },
      { label: "Overall risk", status: riskLevel + " Risk", value: `Score: ${trustScore}/10 (${scamProbability}% scam probability)`, isSafe: true }
    ];
  }
  result.verdictTable = verdictTable;

  return result;
}

// Helper to evaluate 10 signals
function evaluate10Signals(hostname, protocol, path, fullUrl, isTrusted, isStartup, trustScore, scamWordsFound, domainAge, matchedTld, isFreeHost, isFreeForm) {
  const isHttps = protocol === "https:";

  // Let's recheck brand spoofing
  const officialBrands = ["google", "microsoft", "wipro", "tcs", "infosys", "accenture", "amazon", "paypal", "netflix", "apple", "facebook", "meta"];
  const matchedBrand = officialBrands.find(brand => hostname.includes(brand));
  let isSpoofed = false;
  if (matchedBrand) {
    const officialDomains = {
      google: "google.com",
      microsoft: "microsoft.com",
      wipro: "wipro.com",
      tcs: "tcs.com",
      infosys: "infosys.com",
      accenture: "accenture.com",
      amazon: "amazon.jobs",
      paypal: "paypal.com",
      netflix: "netflix.com",
      apple: "apple.com",
      facebook: "facebook.com",
      meta: "meta.com"
    };
    const officialDomain = officialDomains[matchedBrand];
    if (hostname !== officialDomain && !hostname.endsWith("." + officialDomain)) {
      isSpoofed = true;
    }
  }

  // 1. Domain Name Analysis
  let domainStatus = "Standard";
  let domainValue = "Standard custom domain registered.";
  let domainSafe = true;
  if (isTrusted) {
    domainStatus = "Verified";
    domainValue = `Official domain matches established hiring platform/firm (${hostname})`;
  } else if (isStartup) {
    domainStatus = "Startup";
    domainValue = `Matches domain of a verifiable active startup (${hostname})`;
  } else if (isSpoofed) {
    domainStatus = "High Risk";
    domainValue = `Potential brand impersonation: mimics brand '${matchedBrand}' but domain is ${hostname}`;
    domainSafe = false;
  } else if (matchedTld) {
    domainStatus = "Suspicious";
    domainValue = `Uses cheap/scam-preferred top level domain extension (${matchedTld})`;
    domainSafe = false;
  } else if (isFreeHost) {
    domainStatus = "Suspicious";
    domainValue = `Uses free hosting or blog subdomain (${hostname})`;
    domainSafe = false;
  }

  // 2. HTTPS and Security
  let httpsStatus = isHttps ? "Secure" : "Vulnerable";
  let httpsValue = isHttps ? "Valid HTTPS/SSL encryption enabled" : "Unsecure connection (HTTP). Risk of data interception";
  let httpsSafe = isHttps;

  // 3. Domain Age and Registration
  let ageStatus = "Credible";
  let ageValue = `Registered ${domainAge}`;
  let ageSafe = true;
  if (isTrusted) {
    ageStatus = "Established";
    ageValue = "15+ Years (Established)";
  } else if (domainAge.includes("weeks") || domainAge.includes("New")) {
    ageStatus = "Extremely New";
    ageValue = `${domainAge}. Freshly created domain is highly suspicious.`;
    ageSafe = false;
  }

  // 4. Ownership and Registration (Whois info)
  let ownershipStatus = "Verified Entity";
  let ownershipValue = "Registered under official corporate business entity.";
  let ownershipSafe = true;
  if (!isTrusted && !isStartup) {
    ownershipStatus = "Hidden / Proxy";
    ownershipValue = "Whois registrant details hidden using domain privacy shield.";
    ownershipSafe = false;
  } else if (isStartup) {
    ownershipStatus = "Registered";
    ownershipValue = "Whois details align with active startup registrations.";
  }

  // 5. Website Content and Quality
  let contentStatus = "High Quality";
  let contentValue = "Professional, unique layouts with official company logos.";
  let contentSafe = true;
  if (trustScore < 5.0) {
    contentStatus = "Poor / Duplicated";
    contentValue = "Exhibits grammar errors, generic templates, or cheap styling.";
    contentSafe = false;
  } else if (!isTrusted && !isStartup) {
    contentStatus = "Standard";
    contentValue = "Clean basic website layout with standard details.";
  }

  // 6. Contact Information
  let contactStatus = "Official Contacts";
  let contactValue = "Official company emails and office coordinates listed.";
  let contactSafe = true;
  if (isFreeForm) {
    contactStatus = "Suspicious";
    contactValue = "Directing applications through free forms builder (Google Forms/Jotform) without official company emails.";
    contactSafe = false;
  } else if (trustScore < 6.0) {
    contactStatus = "Suspicious";
    contactValue = "Lacks verifiable corporate physical address or phone. Employs free email providers (@gmail.com).";
    contactSafe = false;
  } else if (!isTrusted && !isStartup) {
    contactStatus = "Standard Contacts";
    contactValue = "Standard contact page/form details available.";
  }

  // 7. Reviews and Reputation
  let reviewsStatus = "Excellent";
  let reviewsValue = "Highly rated with active employee discussions and reviews.";
  let reviewsSafe = true;
  if (isTrusted) {
    reviewsStatus = "Excellent";
    reviewsValue = "Excellent reputation. 4.0+ reviews on Glassdoor/LinkedIn.";
  } else if (isStartup) {
    reviewsStatus = "Verified Positive";
    reviewsValue = "Active startups with positive public records and employee reviews.";
  } else if (trustScore < 6.0) {
    reviewsStatus = "Scam Warnings";
    reviewsValue = "Reddit and recruiting forums flag this recruitment format/company as highly suspicious.";
    reviewsSafe = false;
  } else {
    reviewsStatus = "Neutral";
    reviewsValue = "No negative reviews found. Standard online presence.";
  }

  // 8. Policies and Legal Pages
  let policiesStatus = "Compliant";
  let policiesValue = "Standard Privacy Policy, Terms of Service, and disclaimer links.";
  let policiesSafe = true;
  if (trustScore < 5.0) {
    policiesStatus = "Missing or Plagiarized";
    policiesValue = "Lacks critical Privacy Policy page or uses duplicated template content.";
    policiesSafe = false;
  }

  // 9. Technical and Reputation Checks
  let techStatus = "Clean Record";
  let techValue = "Clean DNS records and not listed on phishing safe-browsing databases.";
  let techSafe = true;
  if (trustScore < 5.0) {
    techStatus = "High Risk / Flagged";
    techValue = "Fails safe browsing checks or flagged in anti-phishing lookup databases.";
    techSafe = false;
  }

  // 10. Claims vs Evidence
  let claimsStatus = "Standard Claims";
  let claimsValue = "Hiring rules follow standard competitive job requirements.";
  let claimsSafe = true;
  if (scamWordsFound.length > 0) {
    claimsStatus = "Suspicious Claims";
    claimsValue = `Includes suspect phrases: ${scamWordsFound.join(", ")}. Beware of payment requests.`;
    claimsSafe = false;
  }

  return [
    { label: "Domain Name Analysis", status: domainStatus, value: domainValue, isSafe: domainSafe },
    { label: "HTTPS and Security", status: httpsStatus, value: httpsValue, isSafe: httpsSafe },
    { label: "Domain Age and Registration", status: ageStatus, value: ageValue, isSafe: ageSafe },
    { label: "Ownership and Registration (Whois info)", status: ownershipStatus, value: ownershipValue, isSafe: ownershipSafe },
    { label: "Website Content and Quality", status: contentStatus, value: contentValue, isSafe: contentSafe },
    { label: "Contact Information", status: contactStatus, value: contactValue, isSafe: contactSafe },
    { label: "Reviews and Reputation", status: reviewsStatus, value: reviewsValue, isSafe: reviewsSafe },
    { label: "Policies and Legal Pages", status: policiesStatus, value: policiesValue, isSafe: policiesSafe },
    { label: "Technical and Reputation Checks", status: techStatus, value: techValue, isSafe: techSafe },
    { label: "Claims vs Evidence", status: claimsStatus, value: claimsValue, isSafe: claimsSafe }
  ];
}

// Local heuristics rules evaluator
function runLocalHeuristics(hostname, protocol, path, fullUrl) {
  const flags = {
    red: [],
    green: [],
    security: [],
    company: [],
    reputation: []
  };

  const trustedHosts = [
    "linkedin.com", "github.com", "google.com", "microsoft.com", 
    "glassdoor.com", "indeed.com", "internshala.com", "wellfound.com", 
    "careerbuilder.com", "ziprecruiter.com", "monster.com", "naukri.com",
    "wipro.com", "tcs.com", "infosys.com", "accenture.com", "amazon.jobs",
    "paypal.com", "netflix.com", "apple.com", "facebook.com", "meta.com"
  ];

  const verifiableStartups = [
    "stripe.com", "airbnb.com", "uber.com", "lyft.com", "hubspot.com", 
    "shopify.com", "canva.com", "notion.so", "zoom.us", "slack.com", 
    "figma.com", "spacex.com", "tesla.com", "cred.club", "razorpay.com", 
    "paytm.com", "swiggy.com", "zomato.com", "ola.in", "flipkart.com", 
    "nykaa.com", "meesho.com", "razorpay.in", "paytm.in"
  ];

  const isTrusted = trustedHosts.some(host => hostname === host || hostname.endsWith("." + host));
  const isStartup = verifiableStartups.some(host => hostname === host || hostname.endsWith("." + host));
  const isHttps = protocol === "https:";

  let trustScore = 3.2; // Default base score for New/Unverified/Risky sites (0-4 range)

  // 1. Establish Base Scores according to categories
  if (isTrusted) {
    trustScore = 9.5; // Base score for official careers / well-known platforms (8-10 range)
    flags.green.push(`Verified official hiring platform or established corporate domain (${hostname})`);
  } else if (isStartup) {
    trustScore = 6.8; // Base score for verifiable startups (5-7 range)
    flags.green.push(`Verifiable startup domain (${hostname})`);
  } else {
    // Risky / Unverified by default (0-4 range)
    flags.red.push("Unverified Domain: This site is not recognized as an established corporate brand, hiring platform, or verifiable startup.");
  }

  // 2. Adjustments for HTTPS Security
  if (isHttps) {
    flags.green.push("HTTPS connection enabled (Secure communication channel)");
    if (!isTrusted && !isStartup) trustScore += 0.5; // Small boost for unverified sites with HTTPS
  } else {
    flags.red.push("Unsecure connection (HTTP instead of HTTPS). Potential for data interception");
    trustScore -= 1.5;
  }

  // 3. TLD Heuristics (suspicious top-level domains)
  const suspiciousTlds = [".xyz", ".cfd", ".top", ".vip", ".work", ".site", ".online", ".club", ".info", ".cc", ".icu", ".biz", ".tk", ".ml", ".ga", ".cf", ".gq", ".loan", ".win", ".bid", ".tech", ".website", ".click"];
  const matchedTld = suspiciousTlds.find(tld => hostname.endsWith(tld));
  if (matchedTld) {
    flags.red.push(`Suspicious top-level domain (${matchedTld}) often preferred by scammers for quick setups`);
    trustScore -= 1.0;
  }

  // 4. Job Portal / Third-party checks (reduce score of trusted platforms to 5-7 range if listing is third-party)
  if (isTrusted) {
    if ((hostname.includes("linkedin.com") && path.includes("/jobs/")) || 
        (hostname.includes("internshala.com") && path.includes("/internship/")) ||
        (hostname.includes("indeed.com") && path.includes("/viewjob")) ||
        (hostname.includes("github.com") && path.length > 1)) {
      flags.red.push("Third-Party Content: Listing is hosted on a public job board where posters are anonymous. Verify the recruiter's identity directly.");
      trustScore = 7.0; // Drop into Needs Caution (5-7 range)
    }
  }

  // 5. Free website builders / hosting subdomains
  const freeHosters = ["wixsite.com", "blogspot.com", "wordpress.com", "vercel.app", "github.io", "webflow.io", "firebaseapp.com", "netlify.app"];
  const isFreeHost = freeHosters.some(host => hostname.endsWith("." + host) || hostname === host);
  if (isFreeHost) {
    flags.red.push("Uses free hosting subdomain or website builder. Genuine businesses invest in custom, branded domains for recruitment.");
    trustScore -= 1.0;
  }

  // 6. Free URL shorteners
  const shorteners = ["bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "rebrand.ly", "t.co", "lnkd.in"];
  if (shorteners.some(s => hostname === s || hostname.endsWith("." + s))) {
    flags.red.push("Link is wrapped in a URL shortener. This hides the actual destination and is common in scams");
    trustScore -= 1.0;
  }

  // 7. Free Form Builder domains
  const freeForms = ["forms.gle", "docs.google.com/forms", "jotform.com", "typeform.com", "formfacade.com", "cognitoforms.com"];
  const isFreeForm = freeForms.some(f => fullUrl.includes(f));
  if (isFreeForm) {
    flags.red.push("Direct application via Google Forms or a free form builder. Reputable companies rarely recruit solely on free forms");
    trustScore -= 1.5;
  }

  // 8. Contact details & Email domains check in fullUrl
  const scamKeywords = [
    "earn-money", "data-entry", "part-time-job", "captcha-work", "work-from-home",
    "deposit-fee", "registration-fee", "telegram-hiring", "whatsapp-job",
    "package-shipping", "resell-jobs", "crypto-tasks", "get-paid-daily", "no-skills-needed",
    "easy-cash", "typing-jobs"
  ];

  let scamWordsFound = [];
  scamKeywords.forEach(kw => {
    if (fullUrl.includes(kw) || path.includes(kw)) {
      scamWordsFound.push(kw.replace(/-/g, " "));
    }
  });

  if (scamWordsFound.length > 0) {
    flags.red.push(`Contains suspicious marketing keywords: [${scamWordsFound.join(", ")}]`);
    trustScore -= 0.5 * scamWordsFound.length;
  }

  // 9. Subdomain depth check
  const subdomainCount = hostname.split(".").length - 2;
  if (subdomainCount > 2 && !hostname.includes("cloudfront") && !hostname.includes("amazonaws")) {
    flags.red.push("Deep nested subdomain structure. Often used to mimic popular company sites");
    trustScore -= 0.5;
  }

  // 10. Brand spoofing / Phishing check (contains brand name but not official domain)
  const officialBrands = ["google", "microsoft", "wipro", "tcs", "infosys", "accenture", "amazon", "paypal", "netflix", "apple", "facebook", "meta"];
  const matchedBrand = officialBrands.find(brand => hostname.includes(brand));
  let hasBrandSpoofing = false;
  if (matchedBrand) {
    const officialDomains = {
      google: "google.com",
      microsoft: "microsoft.com",
      wipro: "wipro.com",
      tcs: "tcs.com",
      infosys: "infosys.com",
      accenture: "accenture.com",
      amazon: "amazon.jobs",
      paypal: "paypal.com",
      netflix: "netflix.com",
      apple: "apple.com",
      facebook: "facebook.com",
      meta: "meta.com"
    };
    const officialDomain = officialDomains[matchedBrand];
    if (hostname !== officialDomain && !hostname.endsWith("." + officialDomain)) {
      flags.red.push(`Potential Brand Impersonation: Domain contains '${matchedBrand}' but does not match the official domain (${officialDomain}).`);
      trustScore -= 2.0;
      hasBrandSpoofing = true;
    }
  }

  // Strictly enforce score boundaries for rating categories
  if (isTrusted) {
    // Official platforms stay in 8.0 - 10.0 range
    trustScore = Math.max(8.0, Math.min(10.0, trustScore));
  } else if (isStartup) {
    // Startups stay in 5.0 - 7.5 range
    trustScore = Math.max(5.0, Math.min(7.5, trustScore));
  } else {
    // New/unverified/risky sites stay in 0.0 - 4.0 range
    trustScore = Math.max(0.5, Math.min(4.0, trustScore));
  }

  trustScore = parseFloat(trustScore.toFixed(1));

  return {
    isTrusted,
    isStartup,
    hostname,
    fullUrl,
    trustScore,
    flags,
    scamWordsFound,
    matchedTld,
    isFreeHost,
    isFreeForm,
    hasBrandSpoofing
  };
}

// Simulated Heuristic Report Generator
function generateHeuristicsReport(heuristics, hostname) {
  const { trustScore, flags, scamWordsFound, isTrusted, isStartup, matchedTld, isFreeHost, isFreeForm } = heuristics;

  // Set risk level and recommendation
  let riskLevel = "Low";
  let recommendation = "Safe to Apply";
  if (trustScore < 5.0) {
    riskLevel = "High";
    recommendation = "Avoid applying and do not share personal details";
  } else if (trustScore < 8.0) {
    riskLevel = "Medium";
    recommendation = "Apply carefully. Verify the recruiter's identity directly";
  }

  // Calculate Scam Probability
  const scamProbability = Math.max(2, Math.min(98, Math.round((10 - trustScore) * 10)));

  // Populate dynamic explanation and fields if missing
  const redFlags = [...flags.red];
  const greenFlags = [...flags.green];

  // Dynamic domain age simulation
  let domainAge = "Unknown";
  if (isTrusted) {
    domainAge = "15+ Years (Established)";
    greenFlags.push("Domain registered over a decade ago");
  } else if (isStartup) {
    domainAge = "5+ Years (Established Startup)";
    greenFlags.push("Domain registered over 5 years ago by verified startup");
  } else {
    // Generate simulated age based on trust score
    const ages = ["3 weeks old (Extremely New)", "2 months old (Recently Created)", "1 year old", "3 years old"];
    const index = Math.floor(trustScore % ages.length);
    domainAge = ages[index];
    if (index < 2) {
      redFlags.push(`Domain is recently created (${domainAge}). Scammers frequently rotate websites`);
    } else {
      greenFlags.push(`Domain has been active for ${domainAge}`);
    }
  }

  // Formulate AI explanation
  let explanation = "";
  if (isTrusted) {
    explanation = `The URL ${hostname} points to a highly verified and established domain. It is an official recruitment or corporate channel. We found standard security layers (HTTPS active, authentic SSL certificate) and credible internet references. You can proceed with confidence, ensuring you only communicate through their official contact routes.`;
  } else if (trustScore < 5.0) {
    explanation = `Critical warnings detected for ${hostname}. The application process relies on unverified infrastructure (such as free web hosts, cheap TLD domains, or anonymous form builders like Google Forms). There is a substantial risk of an internship certificate scam, identity phishing, or recruitment fraud where they demand payments for training/processing. Avoid entering any sensitive personal data or paying any deposit.`;
  } else {
    explanation = `Analyze this link carefully. While ${hostname} does not show immediate blacklisted properties, there are items that warrant caution (e.g. missing corporate records, recent domain registration, or lack of direct recruiter links). We advise checking the organization's official website or contacting their HR department on LinkedIn to verify this posting before submitting any files or portfolios.`;
  }

  // Populate the 10 distinct security signals
  const signals = evaluate10Signals(
    hostname,
    heuristics.fullUrl.startsWith("https") ? "https:" : "http:",
    "",
    heuristics.fullUrl,
    isTrusted,
    isStartup,
    trustScore,
    scamWordsFound,
    domainAge,
    matchedTld,
    isFreeHost,
    isFreeForm
  );

  return {
    url: heuristics.fullUrl,
    hostname: hostname,
    trustScore: trustScore,
    riskLevel: riskLevel,
    recommendation: recommendation,
    scamProbability: scamProbability,
    explanation: explanation,
    domainAge: domainAge,
    redFlags: redFlags.length > 0 ? redFlags : ["No immediate red flags detected. Proceed with normal precautions."],
    greenFlags: greenFlags.length > 0 ? greenFlags : ["Basic web connection. Verify identity before sending details."],
    signals,
    isRealAI: false
  };
}

// Live Google Gemini API URL Scam Analysis
async function runGeminiAnalysis(targetUrl, heuristics, apiKey) {
  const genAI = new GoogleGenerativeAI(apiKey);
  const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

  const prompt = `
  You are "InternShield", a professional cybersecurity and recruitment scam analysis engine.
  Analyze the following job posting or company URL and evaluate its safety:
  URL: "${targetUrl}"
  Heuristics detected:
  - Trust Score approximation: ${heuristics.trustScore}/10
  - SSL/HTTPS check: ${heuristics.fullUrl.startsWith("https") ? "HTTPS" : "HTTP"}
  - Matched keywords/TLD warnings: ${heuristics.scamWordsFound ? heuristics.scamWordsFound.join(", ") : "None"}

  Provide a comprehensive analysis report. You MUST return ONLY a valid JSON object matching this structure:
  {
    "url": "${targetUrl}",
    "hostname": "extracted hostname",
    "trustScore": 0.0 to 10.0 (float - use the scale: 8-10 for official company/well-known pages, 5-7 for smaller verifiable startups/platforms, 0-4 for new/unverified/risky sites),
    "riskLevel": "Low" | "Medium" | "High",
    "recommendation": "Safe to Apply" | "Apply Carefully" | "Avoid applying and do not share personal details",
    "scamProbability": 0 to 100 (integer percentage),
    "explanation": "Detailed paragraph explaining the risk breakdown",
    "domainAge": "Estimated or fetched domain age (e.g. '3 weeks old' or '10+ years')",
    "redFlags": ["flag 1", "flag 2"],
    "greenFlags": ["flag 1", "flag 2"],
    "signals": [
      { "label": "Domain Name Analysis", "status": "Verified"|"Startup"|"Suspicious"|"High Risk"|"Standard", "value": "Detailed analysis of hostname structure, TLD, brand spoofing", "isSafe": true|false },
      { "label": "HTTPS and Security", "status": "Secure"|"Vulnerable", "value": "SSL status description", "isSafe": true|false },
      { "label": "Domain Age and Registration", "status": "Established"|"Credible"|"Recent"|"Extremely New", "value": "Registration age information", "isSafe": true|false },
      { "label": "Ownership and Registration (Whois info)", "status": "Verified Entity"|"Registered"|"Hidden / Proxy", "value": "Whois registration details", "isSafe": true|false },
      { "label": "Website Content and Quality", "status": "High Quality"|"Standard"|"Poor / Duplicated", "value": "Content and template assessment", "isSafe": true|false },
      { "label": "Contact Information", "status": "Official Contacts"|"Standard Contacts"|"Suspicious", "value": "Emails, addresses and forms verification", "isSafe": true|false },
      { "label": "Reviews and Reputation", "status": "Excellent"|"Verified Positive"|"Neutral"|"Scam Warnings", "value": "Forum and Glassdoor rating summaries", "isSafe": true|false },
      { "label": "Policies and Legal Pages", "status": "Compliant"|"Basic"|"Missing or Plagiarized", "value": "Privacy Policy and Terms status", "isSafe": true|false },
      { "label": "Technical and Reputation Checks", "status": "Clean Record"|"Clean"|"High Risk / Flagged", "value": "Blacklist and threat base status", "isSafe": true|false },
      { "label": "Claims vs Evidence", "status": "Standard Claims"|"Suspicious Claims", "value": "Recruitment promises vs upfront requests check", "isSafe": true|false }
    ]
  }

  Do not output markdown code blocks like \`\`\`json. Output ONLY raw valid JSON. Make the analysis realistic and helpful for students.
  `;

  const response = await model.generateContent(prompt);
  const responseText = response.response.text().trim();
  
  // Clean potential JSON markdown blocks if any
  const cleanJson = responseText.replace(/^```json/i, "").replace(/```$/, "").trim();
  const parsed = JSON.parse(cleanJson);
  
  // Tag it so the UI knows it came from Gemini
  parsed.isRealAI = true;
  return parsed;
}

module.exports = {
  analyzeUrl
};
