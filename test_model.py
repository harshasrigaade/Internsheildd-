import os, torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

model_path = './models/internshield_spam_model'
tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForSequenceClassification.from_pretrained(model_path)

samples = [
    'Software Engineering Intern at Google. Responsibilities in Go/Python. Apply via careers@google.com',
    'Earn 50000 INR per month doing simple typing work. Pay 999 INR registration fee to Telegram admin @scam'
]

print("\n--- INTERNSHIELD MODEL PREDICTION TEST ---")
for text in samples:
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
        spam_prob = probs[0][1].item() * 100
        verdict = "SPAM / SCAM 🚨" if spam_prob > 50 else "LEGITIMATE ✅"
        print(f"\nInput: {text}")
        print(f"Verdict: {verdict} | Scam Likelihood: {spam_prob:.1f}%")
