import React, { useState, useEffect } from "react";
import { Search, AlertTriangle, CheckCircle, ShieldAlert, Clock, Share2, Printer, Info, ExternalLink, RefreshCw } from "lucide-react";

export default function Dashboard({ apiKey }) {
  const [urlInput, setUrlInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [activeSubTab, setActiveSubTab] = useState("flags");

  // Helper to map and extract signals dynamically
  const getGroupedChecks = (res) => {
    if (!res) return { security: [], company: [], reputation: [] };
    
    const security = res.signals 
      ? res.signals.filter(s => ["domain name", "https", "domain age", "technical"].some(k => s.label.toLowerCase().includes(k)))
      : (res.securityChecks || []);

    const company = res.signals
      ? res.signals.filter(s => ["ownership", "content", "contact", "claims"].some(k => s.label.toLowerCase().includes(k)))
      : (res.companyChecks || []);

    const reputation = res.signals
      ? res.signals.filter(s => ["reviews", "policies"].some(k => s.label.toLowerCase().includes(k)))
      : (res.reputationChecks || []);

    return { security, company, reputation };
  };

  const { security: currentSecurityChecks, company: currentCompanyChecks, reputation: currentReputationChecks } = getGroupedChecks(result);

  // Sample quick tests to showcase the engine
  const sampleUrls = [
    { label: "Legitimate (TCS)", url: "https://www.tcs.com/careers" },
    { label: "Form Builder Scam", url: "https://forms.gle/zenith-hiring-portal" },
    { label: "Fake Freelancing Domain", url: "http://data-entry-typing-jobs.xyz" }
  ];

  // Load history from localStorage on mount
  useEffect(() => {
    const saved = localStorage.getItem("internshield_history");
    if (saved) {
      try {
        setHistory(JSON.parse(saved));
      } catch (e) {
        console.error(e);
      }
    }
  }, []);

  const saveToHistory = (newResult) => {
    const updated = [
      { url: newResult.url, trustScore: newResult.trustScore, riskLevel: newResult.riskLevel, timestamp: new Date().toISOString() },
      ...history.filter(item => item.url !== newResult.url)
    ].slice(0, 10); // Keep last 10
    setHistory(updated);
    localStorage.setItem("internshield_history", JSON.stringify(updated));
  };

  const handleScan = async (targetUrl) => {
    if (!targetUrl) return;
    setLoading(true);
    setResult(null);

    try {
      const apiHost = window.location.port === "5173"
        ? (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1" ? "http://localhost:5000" : `http://${window.location.hostname}:5000`)
        : window.location.origin;
      const response = await fetch(`${apiHost}/api/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          url: targetUrl,
          apiKey: apiKey
        })
      });

      const data = await response.json();
      if (response.ok) {
        setResult(data);
        saveToHistory(data);
      } else {
        alert(data.error || "Something went wrong.");
      }
    } catch (err) {
      alert("Failed to connect to the backend server. Make sure the Node server is running on port 5000.");
    } finally {
      setLoading(false);
    }
  };

  const copyReport = () => {
    if (!result) return;
    const reportText = `🛡️ INTERNSHIELD SECURITY AUDIT REPORT
URL: ${result.url}
Trust Score: ${result.trustScore}/10
Risk Level: ${result.riskLevel} Risk (${result.scamProbability}% Scam Probability)
Recommendation: ${result.recommendation}

🔴 Red Flags:
${result.redFlags.map(f => `- ${f}`).join("\n")}

🟢 Green Flags:
${result.greenFlags.map(f => `- ${f}`).join("\n")}

AI Explanation:
${result.explanation}
    `;
    navigator.clipboard.writeText(reportText);
    alert("Full report summary copied to clipboard!");
  };

  const printReport = () => {
    window.print();
  };

  // Score Color helper
  const getScoreColor = (score) => {
    if (score >= 8) return "text-emerald-500";
    if (score >= 5) return "text-amber-500";
    return "text-rose-500";
  };

  const getScoreBg = (score) => {
    if (score >= 8) return "bg-emerald-500/10 border-emerald-500/20";
    if (score >= 5) return "bg-amber-500/10 border-amber-500/20";
    return "bg-rose-500/10 border-rose-500/20";
  };

  const getRiskBorder = (risk) => {
    if (risk === "Low") return "border-emerald-500/30 shadow-[0_0_20px_rgba(16,185,129,0.15)]";
    if (risk === "Medium") return "border-amber-500/30 shadow-[0_0_20px_rgba(245,158,11,0.15)]";
    return "border-rose-500/30 shadow-[0_0_20px_rgba(239,68,68,0.15)]";
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 grid grid-cols-1 lg:grid-cols-4 gap-8">
      {/* Left History Panel (Sidebar) */}
      <div className="lg:col-span-1 glass-panel rounded-xl p-4 flex flex-col h-[fit-content] no-print">
        <div className="flex items-center gap-2 mb-4 text-gray-300 font-bold uppercase text-xs tracking-widest border-b border-[#1f2235] pb-2">
          <Clock className="w-4 h-4 text-blue-400" />
          <span>Scan History</span>
        </div>

        {history.length === 0 ? (
          <p className="text-gray-500 text-sm py-4 text-center">No recent scans. Paste a link to begin.</p>
        ) : (
          <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
            {history.map((item, idx) => (
              <div
                key={idx}
                onClick={() => { setUrlInput(item.url); handleScan(item.url); }}
                className="p-3 bg-[#0a0b10]/60 border border-[#1f2235] rounded-lg hover:border-blue-500/40 transition-colors cursor-pointer text-left"
              >
                <div className="text-xs text-gray-400 truncate mb-1" title={item.url}>{item.url}</div>
                <div className="flex items-center justify-between">
                  <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${
                    item.riskLevel === "Low" ? "bg-emerald-500/10 text-emerald-400" :
                    item.riskLevel === "Medium" ? "bg-amber-500/10 text-amber-400" :
                    "bg-rose-500/10 text-rose-400"
                  }`}>
                    {item.riskLevel} Risk
                  </span>
                  <span className="text-xs text-gray-500 font-mono">Score: {item.trustScore}/10</span>
                </div>
              </div>
            ))}
            <button
              onClick={() => { setHistory([]); localStorage.removeItem("internshield_history"); }}
              className="w-full text-center text-xs text-rose-400/80 hover:text-rose-400 mt-2 hover:underline"
            >
              Clear History
            </button>
          </div>
        )}
      </div>

      {/* Main Scanner Section */}
      <div className="lg:col-span-3 space-y-6">
        {/* URL Input Box Card */}
        <div className="glass-panel rounded-xl p-6 relative overflow-hidden no-print">
          {/* Decorative scanner line */}
          {loading && <div className="absolute left-0 right-0 h-0.5 bg-blue-500 opacity-80 animate-scanline"></div>}

          <h2 className="text-2xl font-bold text-white mb-2 tracking-tight">Paste Job or Company Link</h2>
          <p className="text-gray-400 text-sm mb-6 leading-relaxed">
            Protect yourself from fake recruiters. We scan domains, certificate traps, financial asks, and reviews to calculate authenticity.
          </p>

          <form
            onSubmit={(e) => { e.preventDefault(); handleScan(urlInput); }}
            className="flex flex-col sm:flex-row gap-3"
          >
            <div className="relative flex-1">
              <Search className="absolute left-3.5 top-3.5 w-5 h-5 text-gray-500" />
              <input
                type="text"
                placeholder="Paste URL (e.g. www.scam-jobs.xyz or linkedin job link...)"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                className="w-full bg-[#0a0b10] border border-[#1f2235] focus:border-blue-500 focus:ring-1 focus:ring-blue-500 rounded-lg pl-11 pr-4 py-3.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !urlInput}
              className="bg-blue-600 hover:bg-blue-500 text-white font-bold px-8 py-3.5 rounded-lg text-sm transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed shadow-glow-primary hover:shadow-lg flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Analyzing
                </>
              ) : (
                "Scan Link"
              )}
            </button>
          </form>

          {/* Quick Samples */}
          <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
            <span className="text-gray-500">Quick Tests:</span>
            {sampleUrls.map((s, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => { setUrlInput(s.url); handleScan(s.url); }}
                className="bg-gray-800/40 hover:bg-gray-800 border border-gray-700/50 hover:border-gray-600 text-gray-400 px-3 py-1.5 rounded-md transition-all font-semibold"
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        {/* Loading Animation Visualizer */}
        {loading && (
          <div className="glass-panel rounded-xl p-12 flex flex-col items-center justify-center space-y-6 text-center no-print">
            <div className="relative w-32 h-32">
              {/* Spinning scanning radar */}
              <div className="absolute inset-0 rounded-full border border-blue-500/20"></div>
              <div className="absolute inset-2 rounded-full border border-blue-500/30"></div>
              <div className="absolute inset-0 rounded-full border-t-2 border-r-2 border-blue-500 animate-radar"></div>
              <div className="absolute inset-10 rounded-full bg-blue-500/10 animate-pulse-glow flex items-center justify-center">
                <ShieldAlert className="w-8 h-8 text-blue-400" />
              </div>
            </div>
            <div>
              <h3 className="font-bold text-white text-lg">Running Security Checks</h3>
              <p className="text-gray-400 text-sm max-w-sm mt-1">
                Verifying HTTPS connection, WHOIS registry timelines, social presence matches, and checking community databases...
              </p>
            </div>
          </div>
        )}

        {/* Results Screen */}
        {result && (
          <div className={`border rounded-xl bg-[#121420]/80 p-6 space-y-6 relative overflow-hidden print-card ${getRiskBorder(result.riskLevel)}`}>
            {/* Top Score Summary Banner */}
            <div className="flex flex-col md:flex-row items-center justify-between gap-6 pb-6 border-b border-[#1f2235]">
              
              {/* Dynamic SVG Gauge */}
              <div className="flex items-center gap-4">
                <div className="relative w-24 h-24">
                  <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="42" stroke="rgba(31, 34, 53, 0.5)" strokeWidth="8" fill="transparent" />
                    <circle 
                      cx="50" 
                      cy="50" 
                      r="42" 
                      stroke={
                        result.trustScore >= 8 ? "#10b981" : 
                        result.trustScore >= 5 ? "#f59e0b" : "#ef4444"
                      } 
                      strokeWidth="8" 
                      fill="transparent" 
                      strokeDasharray={2 * Math.PI * 42}
                      strokeDashoffset={(2 * Math.PI * 42) * (1 - result.trustScore / 10)}
                      className="transition-all duration-1000 ease-out"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-2xl font-black font-mono tracking-tighter text-white">{result.trustScore}</span>
                    <span className="text-[10px] text-gray-500 uppercase font-bold">Trust Score</span>
                  </div>
                </div>

                <div>
                  <h3 className="text-xl font-bold text-white truncate max-w-xs md:max-w-md">{result.hostname}</h3>
                  <div className="flex flex-wrap items-center gap-2 mt-1.5">
                    <span className={`text-xs font-extrabold px-3 py-1 rounded-full ${
                      result.riskLevel === "Low" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" :
                      result.riskLevel === "Medium" ? "bg-amber-500/10 text-amber-400 border border-amber-500/20" :
                      "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                    }`}>
                      {result.riskLevel} Risk Level
                    </span>
                    <span className="text-xs text-gray-400 font-medium bg-[#1f2235]/40 border border-[#1f2235] px-3 py-1 rounded-full">
                      Scam Probability: {result.scamProbability}%
                    </span>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex gap-2 w-full md:w-auto no-print">
                <button
                  onClick={copyReport}
                  className="flex-1 md:flex-initial flex items-center justify-center gap-1.5 bg-[#1f2235]/60 hover:bg-[#1f2235] border border-[#1f2235] hover:border-blue-500/30 text-gray-300 hover:text-white px-4 py-2.5 rounded-lg text-xs font-semibold transition-all"
                >
                  <Share2 className="w-4 h-4" />
                  Copy Report
                </button>
                <button
                  onClick={printReport}
                  className="flex-1 md:flex-initial flex items-center justify-center gap-1.5 bg-[#1f2235]/60 hover:bg-[#1f2235] border border-[#1f2235] hover:border-blue-500/30 text-gray-300 hover:text-white px-4 py-2.5 rounded-lg text-xs font-semibold transition-all"
                >
                  <Printer className="w-4 h-4" />
                  Export PDF
                </button>
              </div>
            </div>

            {/* Recommendation Box */}
            <div className={`p-4 rounded-lg border ${getScoreBg(result.trustScore)}`}>
              <div className="flex items-start gap-3">
                {result.trustScore >= 8 ? (
                  <CheckCircle className="w-6 h-6 text-emerald-500 flex-shrink-0 mt-0.5" />
                ) : (
                  <AlertTriangle className={`w-6 h-6 flex-shrink-0 mt-0.5 ${getScoreColor(result.trustScore)}`} />
                )}
                <div>
                  <h4 className="font-bold text-white text-sm">Security Recommendation: {result.recommendation}</h4>
                  <p className="text-gray-400 text-xs mt-1 leading-relaxed">{result.explanation}</p>
                </div>
              </div>
            </div>

            {/* Verdict Table (Prominent tabular safety verdict) */}
            <div className="bg-[#0a0b10]/80 border border-[#1f2235] rounded-xl p-5 shadow-inner">
              <h4 className="text-sm font-bold text-gray-200 uppercase tracking-widest mb-3 flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${result.trustScore >= 8 ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.7)]' : 'bg-rose-500 shadow-[0_0_8px_rgba(239,68,68,0.7)]'}`}></span>
                {result.trustScore >= 8 ? "Legitimate Verdict Table" : "Suspicious Verdict Table"}
              </h4>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-[#1f2235] bg-[#121420]/60">
                      <th className="p-3 text-xs font-bold text-gray-400 uppercase tracking-wider">Check Parameter</th>
                      <th className="p-3 text-xs font-bold text-gray-400 uppercase tracking-wider">Verdict</th>
                      <th className="p-3 text-xs font-bold text-gray-400 uppercase tracking-wider">Detailed Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1f2235]">
                    {result.verdictTable && result.verdictTable.map((row, idx) => (
                      <tr key={idx} className="hover:bg-[#121420]/35 transition-colors">
                        <td className="p-3 text-xs font-bold text-gray-200">{row.label}</td>
                        <td className="p-3">
                          <span className={`text-[10px] font-extrabold px-2.5 py-1 rounded-full uppercase tracking-wider ${
                            row.isSafe 
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" 
                              : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                          }`}>
                            {row.status}
                          </span>
                        </td>
                        <td className="p-3 text-xs text-gray-400 leading-relaxed">{row.value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Tabs for details */}
            <div className="border-b border-[#1f2235] no-print">
              <nav className="flex space-x-4">
                {[
                  { id: "flags", label: "Red & Green Flags" },
                  { id: "security", label: "Security checks" },
                  { id: "presence", label: "Company Verification" },
                  { id: "sentiment", label: "Public Sentiment" }
                ].map(tab => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveSubTab(tab.id)}
                    className={`pb-3 text-xs uppercase tracking-wider font-bold border-b-2 transition-all ${
                      activeSubTab === tab.id
                        ? "border-blue-500 text-blue-400"
                        : "border-transparent text-gray-500 hover:text-gray-300"
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </nav>
            </div>

            {/* Tab Panels */}
            <div className="mt-4">
              {/* Flags Panel */}
              {(activeSubTab === "flags" || window.matchMedia("print").matches) && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Red flags */}
                  <div className="bg-red-500/5 border border-red-500/10 rounded-lg p-4">
                    <h5 className="font-bold text-rose-400 text-xs uppercase tracking-wider mb-3 flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4" />
                      Suspicious Signals ({result.redFlags.length})
                    </h5>
                    <ul className="space-y-2.5">
                      {result.redFlags.map((flag, i) => (
                        <li key={i} className="text-xs text-gray-300 leading-relaxed flex items-start gap-2">
                          <span className="text-rose-500 mt-0.5">&bull;</span>
                          <span>{flag}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Green flags */}
                  <div className="bg-emerald-500/5 border border-emerald-500/10 rounded-lg p-4">
                    <h5 className="font-bold text-emerald-400 text-xs uppercase tracking-wider mb-3 flex items-center gap-1.5">
                      <CheckCircle className="w-4 h-4" />
                      Trust Signals ({result.greenFlags.length})
                    </h5>
                    <ul className="space-y-2.5">
                      {result.greenFlags.map((flag, i) => (
                        <li key={i} className="text-xs text-gray-300 leading-relaxed flex items-start gap-2">
                          <span className="text-emerald-500 mt-0.5">&bull;</span>
                          <span>{flag}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}

              {/* Security Checks Panel */}
              {activeSubTab === "security" && (
                <div className="bg-[#0a0b10]/60 border border-[#1f2235] rounded-lg overflow-hidden">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-[#1f2235] bg-[#121420]/40">
                        <th className="p-3 text-xs font-bold text-gray-400 uppercase">Test</th>
                        <th className="p-3 text-xs font-bold text-gray-400 uppercase">Status</th>
                        <th className="p-3 text-xs font-bold text-gray-400 uppercase">Result Metrics</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1f2235]">
                      {currentSecurityChecks.map((check, i) => (
                        <tr key={i} className="hover:bg-[#121420]/25 transition-colors">
                          <td className="p-3 text-xs text-gray-300 font-semibold">{check.label}</td>
                          <td className="p-3">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                              check.isSafe ? "bg-emerald-500/10 text-emerald-400" : "bg-rose-500/10 text-rose-400"
                            }`}>
                              {check.status}
                            </span>
                          </td>
                          <td className="p-3 text-xs text-gray-400">{check.value}</td>
                        </tr>
                      ))}
                      {!result.signals && (
                        <tr className="hover:bg-[#121420]/25 transition-colors">
                          <td className="p-3 text-xs text-gray-300 font-semibold">Registered Age</td>
                          <td className="p-3">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                              result.domainAge.includes("weeks") || result.domainAge.includes("New") ? "bg-rose-500/10 text-rose-400" : "bg-emerald-500/10 text-emerald-400"
                            }`}>
                              {result.domainAge.includes("weeks") || result.domainAge.includes("New") ? "Suspicious" : "Credible"}
                            </span>
                          </td>
                          <td className="p-3 text-xs text-gray-400">{result.domainAge}</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Company Verification Panel */}
              {activeSubTab === "presence" && (
                <div className="bg-[#0a0b10]/60 border border-[#1f2235] rounded-lg overflow-hidden">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-[#1f2235] bg-[#121420]/40">
                        <th className="p-3 text-xs font-bold text-gray-400 uppercase">Entity Indicator</th>
                        <th className="p-3 text-xs font-bold text-gray-400 uppercase">Audit Rating</th>
                        <th className="p-3 text-xs font-bold text-gray-400 uppercase">Verification Summary</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1f2235]">
                      {currentCompanyChecks.map((check, i) => (
                        <tr key={i} className="hover:bg-[#121420]/25 transition-colors">
                          <td className="p-3 text-xs text-gray-300 font-semibold">{check.label}</td>
                          <td className="p-3">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                              check.isSafe ? "bg-emerald-500/10 text-emerald-400" : "bg-rose-500/10 text-rose-400"
                            }`}>
                              {check.status}
                            </span>
                          </td>
                          <td className="p-3 text-xs text-gray-400">{check.value}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Public Sentiment Panel */}
              {activeSubTab === "sentiment" && (
                <div className="bg-[#0a0b10]/60 border border-[#1f2235] rounded-lg overflow-hidden">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-[#1f2235] bg-[#121420]/40">
                        <th className="p-3 text-xs font-bold text-gray-400 uppercase">Forum Channel</th>
                        <th className="p-3 text-xs font-bold text-gray-400 uppercase">Sentiment Rating</th>
                        <th className="p-3 text-xs font-bold text-gray-400 uppercase">Report / Review Summary</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1f2235]">
                      {currentReputationChecks.map((check, i) => (
                        <tr key={i} className="hover:bg-[#121420]/25 transition-colors">
                          <td className="p-3 text-xs text-gray-300 font-semibold">{check.label}</td>
                          <td className="p-3">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                              check.isSafe ? "bg-emerald-500/10 text-emerald-400" : "bg-rose-500/10 text-rose-400"
                            }`}>
                              {check.status}
                            </span>
                          </td>
                          <td className="p-3 text-xs text-gray-400">{check.value}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* AI tag info */}
            <div className="pt-4 border-t border-[#1f2235] flex items-center justify-between text-[11px] text-gray-500">
              <div className="flex items-center gap-1">
                <Info className="w-3.5 h-3.5" />
                <span>
                  {result.isRealAI 
                    ? "Live deep-learning audit compiled via Gemini 1.5 Pro." 
                    : "Compiled via offline heuristics database engine."
                  }
                </span>
              </div>
              <a 
                href={`https://whois.domaintools.com/${result.hostname}`}
                target="_blank" 
                rel="noreferrer"
                className="hover:underline flex items-center gap-0.5 text-blue-500"
              >
                Inspect WHOIS
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
