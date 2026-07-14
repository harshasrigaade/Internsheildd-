# InternShield 🛡️ – AI-Powered Job & Internship Verification

Live Demo: **[View Deployed Web App on Render](https://your-app-name.onrender.com)** *(Replace this with your actual Render URL)*

InternShield is a modern, full-stack web application designed to help college students, freshers, and remote job seekers identify whether an internship listing, recruitment offer letter, or flyer poster is genuine or potentially a scam. It features a cybersecurity-themed dashboard with circular trust speedometers, an AI chatbot advisor, an automated offer letter auditor, and a screenshot OCR scanner.

---

## 🚀 Key Features

* **URL Trust Scanner**: Analyzes URL protocols, domains (detecting cheap TLDs like `.xyz`, `.cfd`), nested subdomains, brand-spoofing keywords, and free form builders.
* **Veracity Score**: Returns a rating from 0 to 10 matching strict boundaries (8-10 established, 5-7 startups, 0-4 unverified).
* **Offer Letter Auditor**: Upload PDF or TXT agreements to scan for payment traps (training fees, software deposits) and free email communication routes. Renders a printable Veracity Seal.
* **Poster Screenshot Scanner**: Drag-and-drop flyer graphics. Employs backend OCR (`tesseract.js`) to parse text blocks and isolate suspicious contact details.
* **Safety Bot Chatbot**: Interactive conversational safety advisor powered by Gemini AI.
* **Community Threat Board**: Anonymous dashboard where job seekers search, report, and upvote recruitment scams.
* **Interactive Quiz & Guides**: Education deck on student rights and an active safety quiz.
* **Chrome Extension**: Manifest v3 helper that checks current tabs and fetches safety parameters instantly.

---

## 🛠️ Technologies Used

* **Frontend**: React, Vite, Tailwind CSS v4, Lucide Icons, html2pdf
* **Backend**: Node.js, Express, Multer (file uploads), Tesseract.js (OCR), PDF-Parse
* **AI Integration**: Google Gemini API SDK (`@google/generative-ai`)
* **Security & Scripts**: Windows Batch scripting (`run-app.bat` automation)

---

## 📂 Project Structure

```bash
├── backend/       # Express API server, heuristics engines, OCR and PDF parsers
├── frontend/      # React SPA source, Tailwind CSS stylesheet, visual dashboards
├── extension/     # Manifest v3 Google Chrome Extension pop-up assets
├── run-app.bat    # Windows double-click launcher
└── README.md
```

---

## ⚙️ Running Locally

1. Open your terminal in VS Code and run the automated launcher script:
   ```powershell
   .\run-app.bat
   ```
2. Navigate to `http://localhost:5173` in your browser.

---

## 🔧 Installing Chrome Extension

1. Open Google Chrome and go to `chrome://extensions/`.
2. Turn on **Developer mode** (top-right switch).
3. Click **Load unpacked** (top-left button).
4. Select the `extension` folder in this repository.

Developed by Gadhey Harsha Sri

---

## 👤 Author

* Developed by **Harsha Sri**

---

## 📄 License

This project is licensed under the MIT License.
