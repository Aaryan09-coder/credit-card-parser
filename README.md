# Secure Credit Card Statement Parser

Build a PDF parser that extracts 5 key data points from credit card statements across 5 major credit card issuers.

## Problem Statement

Requirements:

- Support statements from 5 different credit card providers (choose any)
- Extract 5 key data points (examples: transaction info, card variant, last 4 digits, billing cycle, payment due date, total balance)
- Handle real-world PDF statement formats

## Features

- Extracts card issuer, last 4 digits, minimum payment, statement date, total balance, and account holder name
- Supports password-protected PDFs
- Encrypts sensitive information before sending to AI
- Decrypts and returns clean, readable results locally

## How it Works

1. **PDF Processing:** Extracts text from PDFs, including password-protected ones
2. **PII Encryption:** Detects sensitive data (account numbers, names, emails) and replaces them with placeholders
3. **AI Extraction:** Groq LLaMA extracts key data points from the encrypted text
4. **Decryption & Output:** Placeholders are replaced with original values locally

## Technology Stack

| Component      | Technology         |
| -------------- | ------------------ |
| Backend        | Flask              |
| PDF Processing | PyMuPDF (fitz)     |
| AI Model       | Groq LLaMA 3.3 70B |
| Encryption     | Fernet (AES-128)   |
| Env Management | python-dotenv      |
