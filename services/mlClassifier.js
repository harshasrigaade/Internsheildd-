cat << 'EOF' > services/mlClassifier.js
const { spawn } = require("child_process");
const path = require("path");

let pipelineInstance = null;

async function classifyInternship(text) {
  if (!text || text.trim().length === 0) {
    return {
      isSpam: false,
      scamProbability: 0,
      trustScore: 10.0,
      modelConfidence: "Low",
      signals: []
    };
  }

  try {
    try {
      const { pipeline } = require("@xenova/transformers");
      if (!pipelineInstance) {
        const modelPath = path.join(__dirname, "../models/internshield_onnx");
        pipelineInstance = await pipeline("text-classification", modelPath);
      }
      const output = await pipelineInstance(text.slice(0, 512));
      const topResult = output[0];

      const isSpam = topResult.label.toUpperCase().includes("SPAM") || topResult.label === "LABEL_1";
      const scamProb = Math.round((isSpam ? topResult.score : (1 - topResult.score)) * 100);
      const trustScore = Math.max(0, Math.min(10, parseFloat(((100 - scamProb) / 10).toFixed(1))));

      return {
        isSpam,
        scamProbability: scamProb,
        trustScore,
        modelConfidence: `${(topResult.score * 100).toFixed(1)}%`,
        signals: [{
          label: "Fine-Tuned ML Model Analysis",
          status: isSpam ? "High Scam Risk" : "Legitimate Signal",
          value: `Model confidence: ${(topResult.score * 100).toFixed(1)}% (${isSpam ? "Spam / Scam pattern detected" : "Safe patterns match verified listings"})`,
          isSafe: !isSpam
        }]
      };
    } catch (onnxErr) {
      return await runPythonPrediction(text);
    }
  } catch (err) {
    console.warn("ML Classifier prediction fallback:", err.message);
    return {
      isSpam: false,
      scamProbability: 50,
      trustScore: 5.0,
      modelConfidence: "Fallback",
      signals: []
    };
  }
}

function runPythonPrediction(text) {
  return new Promise((resolve) => {
    const scriptPath = path.join(__dirname, "predict.py");
    const pythonProcess = spawn("python", [scriptPath, text]);

    let dataString = "";

    pythonProcess.stdout.on("data", (data) => {
      dataString += data.toString();
    });

    pythonProcess.on("close", (code) => {
      if (code !== 0 || !dataString) {
        return resolve({
          isSpam: false,
          scamProbability: 50,
          trustScore: 5.0,
          modelConfidence: "Unavailable",
          signals: []
        });
      }
      try {
        const result = JSON.parse(dataString);
        resolve(result);
      } catch (parseErr) {
        resolve({
          isSpam: false,
          scamProbability: 50,
          trustScore: 5.0,
          modelConfidence: "Error",
          signals: []
        });
      }
    });

    pythonProcess.on("error", () => {
      resolve({
        isSpam: false,
        scamProbability: 50,
        trustScore: 5.0,
        modelConfidence: "Error",
        signals: []
      });
    });
  });
}

module.exports = {
  classifyInternship
};
EOF