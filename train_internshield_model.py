import os, json, torch, numpy as np
print('Step 1: Starting InternShield Model Training...')
from datasets import Dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer, DataCollatorWithPadding

print('Step 2: Loaded Transformers and PyTorch')
data = [
    {'text': 'Company: Google | Domain: google.com | Contact: careers@google.com | Text: Software Engineering Intern 2026. Official Google portal application only.', 'label': 0},
    {'text': 'Company: TCS | Domain: tcs.com | Contact: campus@tcs.com | Text: Graduate Trainee Analyst. No registration fee.', 'label': 0},
    {'text': 'Company: Unknown | Domain: zenith-typing.online | Contact: hr@gmail.com | Text: Typing job 50000 INR/month. Pay 999 INR registration fee.', 'label': 1},
    {'text': 'Company: Microsoft Fake | Domain: forms.gle/fake123 | Contact: Telegram @scam | Text: Pay 499 INR for certificate processing.', 'label': 1}
]

print('Step 3: Loading DistilBERT Model and Tokenizer...')
model_name = 'distilbert-base-uncased'
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2, id2label={0: 'LEGITIMATE', 1: 'SPAM_SCAM'}, label2id={'LEGITIMATE': 0, 'SPAM_SCAM': 1})

dataset = Dataset.from_list(data).train_test_split(test_size=0.2, seed=42)
tokenized_dataset = dataset.map(lambda e: tokenizer(e['text'], truncation=True, max_length=512), batched=True)
data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

save_dir = os.path.join(os.path.dirname(__file__), 'models/internshield_spam_model')
args = TrainingArguments(
    output_dir='./checkpoints',
    learning_rate=2e-5,
    per_device_train_batch_size=2,
    num_train_epochs=3,
    save_strategy='no',
    report_to='none'
)

trainer = Trainer(
    model=model,
    args=args,
    train_dataset=tokenized_dataset['train'],
    eval_dataset=tokenized_dataset['test'],
    tokenizer=tokenizer,
    data_collator=data_collator
)

print('Step 4: Training Model...')
trainer.train()

print('Step 5: Saving fine-tuned model...')
trainer.save_model(save_dir)
tokenizer.save_pretrained(save_dir)
print('SUCCESS: InternShield Model Trained and Saved Successfully')