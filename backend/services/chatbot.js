const { GoogleGenerativeAI } = require("@google/generative-ai");

async function handleChat(message, history = [], userApiKey = "") {
  const apiKey = userApiKey || process.env.GEMINI_API_KEY;

  if (apiKey) {
    try {
      return await runGeminiChat(message, history, apiKey);
    } catch (err) {
      console.error("Gemini chatbot error, falling back to heuristics:", err.message);
    }
  }

  return generateHeuristicChatResponse(message);
}

// Simulated Chatbot responses based on typical student concerns
function generateHeuristicChatResponse(message) {
  const msg = message.toLowerCase();

  if (msg.includes("evaluate") || msg.includes("score") || msg.includes("framework") || msg.includes("rubric") || msg.includes("rate") || msg.includes("scale")) {
    return {
      text: `📊 **InternShield Internship Evaluation Framework**\n\nWhen verifying an offer, we evaluate it across three core layers out of a **Total Score of 10**:\n\n1. **Company Legitimacy (Weight: 3)**: Active online presence, LinkedIn page, physical address, business registration.\n2. **Website & URL (Weight: 2)**: Professional TLD, HTTPS, DNS registry age, legal pages.\n3. **Offer Letter Quality (Weight: 2)**: Grammar, logo, duration, stipend, signature, address.\n4. **Hiring Process (Weight: 1)**: Proper evaluation stages vs instant hiring.\n5. **Reviews & Reputation (Weight: 1)**: Glassdoor reviews, Reddit discussions.\n6. **No Payment Demands (Weight: 1)**: Absence of training, laptop, or certification fees.\n\n**Score Interpretation:**\n- **9.0–10.0**: Very likely genuine\n- **7.0–8.9**: Probably legitimate\n- **5.0–6.9**: Mixed signals; verify further\n- **3.0–4.9**: High caution\n- **0.0–2.9**: Likely fake or scam\n\n*Action:* Share a website link, company name, or details of your recruitment process, and I will evaluate it for you!`,
      suggestions: ["Is paying for training normal?", "Recruiter uses a Gmail address"]
    };
  }

  if (msg.includes("pay") || msg.includes("fee") || msg.includes("deposit") || msg.includes("charge") || msg.includes("money")) {
    return {
      text: `⚠️ **Crucial Security Advisory: Recruitment Payment Requests**\n\nNo genuine company will **ever** request payment from an applicant for processing fees, background checks, laptop setups, or mandatory training materials. \n\n**Common Scam Strategy:** Scammers send a fake check for you to purchase office equipment from a specific "verified vendor" (who is actually the scammer), or they demand a refundable security deposit. \n\n*Action:* Immediately cease communications with this recruiter. Do not send money or banking details.`,
      suggestions: ["How can I verify a company email?", "What if I already sent them money?"]
    };
  }

  if (msg.includes("telegram") || msg.includes("whatsapp") || msg.includes("hangouts") || msg.includes("chat app")) {
    return {
      text: `📱 **Communication Risk: Messaging Platforms**\n\nBe highly suspicious of companies that conduct interviews exclusively on Telegram, WhatsApp, or Signal, especially if they refuse to hold a phone or video call on professional tools (like Google Meet, Teams, or Zoom).\n\n**Why scammers do this:** It allows them to maintain anonymity, easily delete conversation histories, and scale their fraud operations from overseas.\n\n*Safety Checklist:*\n1. Check if the interviewer's email matches the company domain (e.g. \`hr@google.com\` and NOT \`googlecareers.hr@gmail.com\`).\n2. Request a formal video meeting with camera on.`,
      suggestions: ["What are signs of a fake email?", "Is LinkedIn messaging safe?"]
    };
  }

  if (msg.includes("data entry") || msg.includes("typing") || msg.includes("captcha") || msg.includes("filling") || msg.includes("sms")) {
    return {
      text: `⌨️ **Scam Alert: Online Data Entry / Captcha Tasks**\n\nAlmost 95% of remote "Data Entry", "Typing", or "Captcha Solving" internships targeted at college students are fraudulent. \n\n**How the Trap Works:** They promise an attractive weekly salary for typing pages. Once you complete the work, they claims you made "formatting errors" and demand a "rectification fee" or "account activation deposit" before releasing your earnings. They never pay.\n\n*Recommendation:* Avoid these offers entirely. Look for internships that build real, verifiable skills (software, design, marketing, research).`,
      suggestions: ["Show me safe remote job boards", "What are legitimate entry-level roles?"]
    };
  }

  if (msg.includes("offer letter") || msg.includes("hired") || msg.includes("contract") || msg.includes("pdf")) {
    return {
      text: `📄 **Auditing Internship Offer Letters**\n\nIf you have received an offer letter, use our **Offer Letter Auditor** tab! You can upload the PDF or paste the text, and we will scan it for scam signatures. \n\n**Red flags in written offers:**\n- Lack of a specific physical office address or contact information.\n- Poor layout design, pixelated logo, or grammatical blunders.\n- Fast hiring (e.g., getting hired within 2 hours of applying without a video call).\n- Clauses requesting you to deposit funds for background verification.`,
      suggestions: ["Go to Offer Auditor page", "How to verify company registration?"]
    };
  }

  if (msg.includes("unpaid") || msg.includes("certificate") || msg.includes("free") || msg.includes("commission")) {
    return {
      text: `🎓 **Unpaid Internships & Certificate Scams**\n\nUnpaid internships are legal only if the student is the "primary beneficiary" (usually involving academic credit and structured learning). Beware of companies that:\n- Offer "guaranteed certificates" but require you to sell their products to your friends/family first (disguised MLM/sales traps).\n- Ask you to do high-volume work for months with no mentoring or guidance.\n- Charge you a fee to receive your internship certificate (Certificate Traps).\n\n*Advice:* A certificate from a fake/unregulated company has zero value on your resume. Seek positions with defined training structures.`,
      suggestions: ["How to check company registration?", "What is an MLM trap?"]
    };
  }

  if (msg.includes("reddit") || msg.includes("glassdoor") || msg.includes("reviews") || msg.includes("search")) {
    return {
      text: `🔍 **Internet Reputation Checks**\n\nBefore accepting any role, execute these search queries on Google:\n- \`"[Company Name] scam"\`\n- \`"[Company Name] Glassdoor"\`\n- \`"[Company Name] Reddit recruitment"\`\n\nIf the company does not exist on Glassdoor, or if Reddit posts report phishing interviews, withdraw immediately. Legitimate startups should at least have a visible founder profile on LinkedIn.`,
      suggestions: ["How to check LinkedIn founders?", "Search a company now"]
    };
  }

  // Default response
  return {
    text: `🛡️ **Welcome to the InternShield AI Threat Advisor!**\n\nI can help you evaluate internship offers, website links, or company names using our three-layer score card out of 10. \n\nFeel free to ask me questions like:\n- *"How do I evaluate this company?"*\n- *"What are the risks of a WhatsApp recruitment chat?"*\n- *"How do I know if an offer letter is fake?"*\n- *"Is this data-entry job a scam?"*`,
    suggestions: [
      "Explain the evaluation framework",
      "Recruiter uses a Gmail address",
      "I was hired without an interview"
    ]
  };
}

// Live Gemini Chatbot interaction
async function runGeminiChat(message, history, apiKey) {
  const genAI = new GoogleGenerativeAI(apiKey);
  const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

  const chatSession = model.startChat({
    history: history.map(h => ({
      role: h.role === "user" ? "user" : "model",
      parts: [{ text: h.text }]
    })),
    generationConfig: {
      maxOutputTokens: 500,
    }
  });

  const prompt = `
  You are the "InternShield AI Safety Advisor", a chatbot integrated into a job scam detection web app.
  Your goal is to answer queries from students, freshers, and job seekers who are worried about recruitment scams, fake certificates, phishing, and advance-fee schemes.
  
  When the user shares a company name, website link, or details of their internship offer, you MUST apply this exact Suggested Scoring Model (Out of 10):
  - Company legitimacy (weight 3): active presence, LinkedIn page, employees online, physical address, business registration.
  - Website and URL trustworthiness (weight 2): professional TLD vs suspicious TLDs, HTTPS, contact/privacy pages.
  - Offer letter quality (weight 2): grammar mistakes, address, manager name, company email, signature.
  - Hiring process authenticity (weight 1): screening/interview vs instant selection/offer.
  - Employee reviews and reputation (weight 1): Glassdoor/Reddit recruitment discussions.
  - No suspicious payment requests (weight 1): demands for training fees, security deposits, laptop fees.
  - Total: 10
  
  Interpretation Scale:
  - 9.0–10.0: Very likely genuine
  - 7.0–8.9: Probably legitimate
  - 5.0–6.9: Mixed signals; verify further
  - 3.0–4.9: High caution
  - 0.0–2.9: Likely fake or scam
  
  Format your reply using professional, comforting, and clear Markdown (bullet points, bold text). When evaluating, explicitly list the score out of 10 for each category, compute the total score, and explain your safety interpretation. Highlight warning signs with emojis (like ⚠️, 📱, 📄). Keep responses under 250 words and directly actionable.
  
  Suggest 2 short follow-up questions at the very end of your response inside a JSON block format starting with [SUGGESTIONS] so the system can parse them. Example:
  [SUGGESTIONS] ["What is an advance fee scam?", "How do I verify a LinkedIn page?"]
  
  User message: "${message}"
  `;

  const result = await chatSession.sendMessage(prompt);
  const responseText = result.response.text();

  // Extract suggestions if any
  let cleanText = responseText;
  let suggestions = [];
  const suggestionIndex = responseText.indexOf("[SUGGESTIONS]");
  if (suggestionIndex !== -1) {
    cleanText = responseText.substring(0, suggestionIndex).trim();
    try {
      const jsonStr = responseText.substring(suggestionIndex + 13).trim();
      suggestions = JSON.parse(jsonStr);
    } catch (e) {
      // Fallback if parsing failed
      suggestions = ["How to spot fake jobs?", "Verify recruitment email"];
    }
  } else {
    suggestions = ["How to spot fake jobs?", "Verify recruitment email"];
  }

  return {
    text: cleanText,
    suggestions: suggestions
  };
}

module.exports = {
  handleChat
};
