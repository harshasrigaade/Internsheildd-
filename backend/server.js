const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const pdfParse = require("pdf-parse");
const Tesseract = require("tesseract.js");
require("dotenv").config();

const { analyzeUrl } = require("./services/analyzer");
const { handleChat } = require("./services/chatbot");

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS & JSON Parsing
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    status: "online",
    name: "InternShield API Backend",
    model: "DistilBERT ML Spam Detection Active 🛡️"
  });
});

// Set up file upload destination
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

// In-Memory Database for Community Reports (Prefilled with realistic cases)
let communityReports = [
  {
    id: "rep-1",
    companyName: "Zenith Typing Solutions",
    role: "Data Entry Clerk",
    url: "https://zenith-data-entry-careers.online",
    scamType: "Typing / Data Entry Scam",
    details: "Approached on WhatsApp. Hired immediately without interview. Required 30 pages typed in 3 days. Afterwards, they claimed I had 2 errors and demanded a $150 'rectification fee' to get my $800 salary.",
    reportedAt: "2026-05-25T14:30:00.000Z",
    upvotes: 42
  },
  {
    id: "rep-2",
    companyName: "Global Apex Digital",
    role: "SEO Specialist Intern",
    url: "https://forms.gle/x2yBqW8572P12",
    scamType: "Suspicious Form / Phishing",
    details: "LinkedIn job listing redirected to a sketchy Google Form. They asked for my Social Security Number (SSN) and full bank routing details on the initial application page.",
    reportedAt: "2026-05-26T09:15:00.000Z",
    upvotes: 18
  },
  {
    id: "rep-3",
    companyName: "Apex Certificate Group",
    role: "Business Development Trainee",
    url: "https://apex-biz-skills.site",
    scamType: "Certificate trap / MLM",
    details: "Unpaid internship where they make you sell online courses to your friends. They promise a certificate only if you hit a $500 sales quota. No mentoring available.",
    reportedAt: "2026-05-27T11:02:00.000Z",
    upvotes: 29
  }
];

// 1. Analyze URL Endpoint
app.post("/api/analyze", async (req, res) => {
  const { url: targetUrl, apiKey } = req.body;
  if (!targetUrl) {
    return res.status(400).json({ error: "URL is required" });
  }

  try {
    const report = await analyzeUrl(targetUrl, apiKey);
    res.json(report);
  } catch (err) {
    console.error("Analysis route error:", err);
    res.status(500).json({ error: "Failed to perform URL safety scan" });
  }
});

// 2. Chatbot AI Endpoint
app.post("/api/chat", async (req, res) => {
  const { message, history, apiKey } = req.body;
  if (!message) {
    return res.status(400).json({ error: "Message content is required" });
  }

  try {
    const response = await handleChat(message, history || [], apiKey);
    res.json(response);
  } catch (err) {
    console.error("Chat route error:", err);
    res.status(500).json({ error: "Chat processing failed" });
  }
});

// 3. Analyze Offer Letter (PDF / Text) Endpoint
app.post("/api/analyze-offer", upload.single("file"), async (req, res) => {
  let offerText = req.body.text || "";
  let sourceFileName = "Manual Paste";

  // Check if a file was uploaded
  if (req.file) {
    sourceFileName = req.file.originalname;
    const filePath = req.file.path;
    try {
      if (req.file.mimetype === "application/pdf") {
        const dataBuffer = fs.readFileSync(filePath);
        const parsed = await pdfParse(dataBuffer);
        offerText = parsed.text;
      } else {
        // Plain text files
        offerText = fs.readFileSync(filePath, "utf-8");
      }
      // Clean up uploaded file asynchronously
      fs.unlink(filePath, () => {});
    } catch (parseErr) {
      console.error("Offer PDF parsing error:", parseErr);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      return res.status(500).json({ error: "Failed to parse the uploaded file. Ensure it is a valid PDF or Text file." });
    }
  }

  if (!offerText || offerText.trim().length < 20) {
    return res.status(400).json({ error: "Insufficient text provided. Please write or upload a complete offer letter." });
  }

  try {
    const report = runOfferSafetyAudit(offerText, sourceFileName);
    res.json(report);
  } catch (err) {
    console.error("Offer audit route error:", err);
    res.status(500).json({ error: "An error occurred during the offer letter audit." });
  }
});

// Heuristics engine for offer letter auditing
function runOfferSafetyAudit(text, sourceName) {
  const lowercaseText = text.toLowerCase();
  const redFlags = [];
  const greenFlags = [];
  let safetyScore = 9.0; // Base score

  // 1. Check for payment indicators (Critical red flags)
  const paymentKeywords = [
    { phrase: "training fee", reason: "Employer asking candidates to pay for mandatory job training." },
    { phrase: "security deposit", reason: "Demanding refundable deposits before contract initiation." },
    { phrase: "onboarding charge", reason: "Billing applicants for admin, HR setup, or contract processing." },
    { phrase: "laptop setup fee", reason: "Charging candidates to ship or configure work laptops." },
    { phrase: "equipment payment", reason: "Asking candidate to buy setup gear through a designated vendor." },
    { phrase: "purchase a software", reason: "Requiring purchase of unverified licensing codes." }
  ];

  paymentKeywords.forEach(kw => {
    if (lowercaseText.includes(kw.phrase)) {
      redFlags.push(kw.reason);
      safetyScore -= 3.0;
    }
  });

  // 2. Check for suspicious interview/contact mechanisms
  if (lowercaseText.includes("telegram interview") || lowercaseText.includes("interview over telegram")) {
    redFlags.push("Mentions interviewing or onboarding exclusively via Telegram chat.");
    safetyScore -= 2.0;
  }
  if (lowercaseText.includes("whatsapp interview") || lowercaseText.includes("interview on whatsapp")) {
    redFlags.push("Mentions job screening conducted over WhatsApp chat.");
    safetyScore -= 1.5;
  }

  // 3. Free email servers used inside letter
  const emailRegex = /([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi;
  const emailsFound = text.match(emailRegex) || [];
  const gmailEmails = emailsFound.filter(email => email.toLowerCase().endsWith("@gmail.com") || email.toLowerCase().endsWith("@yahoo.com") || email.toLowerCase().endsWith("@outlook.com"));
  
  if (gmailEmails.length > 0) {
    redFlags.push(`Uses free public email servers inside the offer letter: [${gmailEmails.join(", ")}]. Legitimate offer letters originate from corporate domains.`);
    safetyScore -= 2.0;
  }

  // 4. Grammar and phrasing red flags
  const urgentKeywords = ["urgent hiring", "join immediately", "no experience required", "easy task", "huge commission", "deposit as soon as possible"];
  let urgencyWordsFound = urgentKeywords.filter(w => lowercaseText.includes(w));
  if (urgencyWordsFound.length >= 2) {
    redFlags.push("Uses high-pressure or overly urgent vocabulary ('easy money', 'pay immediately', etc.) typical of phishing traps.");
    safetyScore -= 1.0;
  }

  // 5. Positive factors (Green Flags)
  if (lowercaseText.includes("confidentiality agreement") || lowercaseText.includes("non-disclosure")) {
    greenFlags.push("Contains standard corporate NDA and confidentiality clauses.");
    safetyScore += 0.5;
  }
  if (lowercaseText.includes("benefits") || lowercaseText.includes("healthcare") || lowercaseText.includes("provident fund") || lowercaseText.includes("401k") || lowercaseText.includes("leave policy")) {
    greenFlags.push("Lists standard corporate benefits, indicating comprehensive legal review.");
    safetyScore += 0.5;
  }
  if (lowercaseText.includes("probationary period") || lowercaseText.includes("termination policy")) {
    greenFlags.push("Defines clear terms of termination and probationary rules.");
    safetyScore += 0.5;
  }
  if (lowercaseText.includes("salary details") || lowercaseText.includes("compensation structure") || lowercaseText.includes("stipend of")) {
    greenFlags.push("Includes detailed break-up of stipends or salary brackets.");
  }

  // Clamp safetyScore
  safetyScore = Math.max(0.5, Math.min(10.0, parseFloat(safetyScore.toFixed(1))));

  let auditLevel = "Low Risk";
  let verdict = "Legitimate Format";
  if (safetyScore < 5.0) {
    auditLevel = "High Risk";
    verdict = "Highly Suspicious / Potential Scam";
  } else if (safetyScore < 8.0) {
    auditLevel = "Medium Risk";
    verdict = "Needs Verification / Proceed with Caution";
  }

  return {
    sourceName,
    safetyScore,
    auditLevel,
    verdict,
    redFlags: redFlags.length > 0 ? redFlags : ["No obvious scam clauses detected inside the letter text."],
    greenFlags: greenFlags.length > 0 ? greenFlags : ["Basic formatting template. Verify email sender authenticity."],
    extractedLength: text.length,
    scamWarning: safetyScore < 7.0 ? "WARNING: This document contains clauses asking for financial commitment, free-domain emails, or chat-app interviewing. Do NOT provide signatures or bank credentials without video validation of the company's HR department." : "VERDICT: This document aligns with general recruitment layouts. Verify that the sender address corresponds exactly with the official organization domain before sharing signature files."
  };
}

// 4. Analyze Poster Screenshot Endpoint (OCR Scan)
app.post("/api/analyze-screenshot", upload.single("image"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "An image file is required for screenshot scanning." });
  }

  const filePath = req.file.path;
  try {
    // Run OCR via Tesseract
    const { data: { text } } = await Tesseract.recognize(filePath, "eng");
    
    // Clean up file
    fs.unlink(filePath, () => {});

    if (!text || text.trim().length < 5) {
      return res.status(422).json({ error: "No readable text found in the image. Please upload a clear poster screenshot." });
    }

    // Reuse offer/text analyzer with modified weights for poster ads
    const analysis = runPosterSafetyAudit(text, req.file.originalname);
    res.json(analysis);
  } catch (ocrErr) {
    console.error("OCR analysis error:", ocrErr);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    res.status(500).json({ error: "Failed to extract text from poster screenshot. Verify image formatting." });
  }
});

function runPosterSafetyAudit(text, sourceName) {
  const lowercaseText = text.toLowerCase();
  const redFlags = [];
  const greenFlags = [];
  let safetyScore = 8.5;

  // Search terms typical of flyer/instagram scams
  const highSalaryRegex = /(?:stipend|salary|earn|pay)[:\s-]*[\d,]+\s*(?:usd|rs|inr|gbp)?\s*(?:per\s*month|monthly|weekly|daily|per\s*week|\/mo|\/wk)/gi;
  const numbersFound = text.match(highSalaryRegex) || [];
  if (numbersFound.length > 0) {
    greenFlags.push(`Discloses wage rates clearly on poster: [${numbersFound.slice(0,2).join(", ")}]`);
  }

  if (lowercaseText.includes("work from home") || lowercaseText.includes("wfh") || lowercaseText.includes("flexible hours")) {
    greenFlags.push("Offers remote/flexible working models.");
  }

  // Suspicious flyer indicators
  if (lowercaseText.includes("no interview") || lowercaseText.includes("direct joining") || lowercaseText.includes("spot selection")) {
    redFlags.push("Promises 'direct joining' or 'no interview selection'. Legitimate companies perform structural screening.");
    safetyScore -= 2.0;
  }

  if (lowercaseText.includes("daily payout") || lowercaseText.includes("earn up to") || lowercaseText.includes("earn daily")) {
    redFlags.push("Promises 'daily payouts' or exaggerated rates. This is typical of captcha, MLM, or survey traps.");
    safetyScore -= 1.5;
  }

  if (lowercaseText.includes("registration fee") || lowercaseText.includes("buy ticket") || lowercaseText.includes("certificate fee")) {
    redFlags.push("Demands registration or certification fees directly on the poster.");
    safetyScore -= 3.0;
  }

  if (lowercaseText.includes("whatsapp to") || lowercaseText.includes("whatsapp me") || lowercaseText.includes("ping on whatsapp")) {
    redFlags.push("Directs applicants to WhatsApp contacts rather than a formal web form.");
    safetyScore -= 1.5;
  }

  // Check for public emails
  const emails = text.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi) || [];
  const publicEmails = emails.filter(e => e.includes("gmail.com") || e.includes("yahoo.com") || e.includes("outlook.com"));
  if (publicEmails.length > 0) {
    redFlags.push(`Lists free public email contacts: [${publicEmails.join(", ")}]`);
    safetyScore -= 2.0;
  }

  // Adjust scores
  safetyScore = Math.max(0.5, Math.min(10.0, parseFloat(safetyScore.toFixed(1))));

  let auditLevel = "Low Risk";
  if (safetyScore < 5.0) {
    auditLevel = "High Risk";
  } else if (safetyScore < 8.0) {
    auditLevel = "Medium Risk";
  }

  return {
    sourceName,
    safetyScore,
    auditLevel,
    extractedText: text.trim(),
    redFlags: redFlags.length > 0 ? redFlags : ["No obvious flyer scam phrases detected."],
    greenFlags: greenFlags.length > 0 ? greenFlags : ["Standard internship design banner. Review digital presence."]
  };
}

// 5. Community Reports Endpoints
app.get("/api/reports", (req, res) => {
  res.json(communityReports);
});

app.post("/api/reports", (req, res) => {
  const { companyName, role, url, scamType, details } = req.body;
  if (!companyName || !scamType || !details) {
    return res.status(400).json({ error: "Company name, scam type, and details are required." });
  }

  const newReport = {
    id: `rep-${Date.now()}`,
    companyName,
    role: role || "Not Specified",
    url: url || "",
    scamType,
    details,
    reportedAt: new Date().toISOString(),
    upvotes: 1
  };

  communityReports.unshift(newReport);
  res.status(201).json(newReport);
});

app.post("/api/reports/:id/upvote", (req, res) => {
  const reportId = req.params.id;
  const report = communityReports.find(r => r.id === reportId);
  if (!report) {
    return res.status(404).json({ error: "Report not found." });
  }

  report.upvotes += 1;
  res.json(report);
});

// Serve static assets in production if compiled
const frontendDist = path.join(__dirname, "frontend", "dist");
const alternativeFrontendDist = path.join(__dirname, "../frontend/dist");

if (fs.existsSync(frontendDist)) {
  app.use(express.static(frontendDist));
  app.get("*", (req, res) => {
    if (!req.path.startsWith("/api/")) {
      res.sendFile(path.resolve(frontendDist, "index.html"));
    }
  });
} else if (fs.existsSync(alternativeFrontendDist)) {
  app.use(express.static(alternativeFrontendDist));
  app.get("*", (req, res) => {
    if (!req.path.startsWith("/api/")) {
      res.sendFile(path.resolve(alternativeFrontendDist, "index.html"));
    }
  });
}

// Start Server
app.listen(PORT, () => {
  console.log(`[InternShield] Server is running on port ${PORT}`);
});
