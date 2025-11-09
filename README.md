# Secure Credit Card Statement Parser

## Overview

This project is a secure and context-aware PDF parser for credit card statements. Unlike traditional regex-based extractors which are issuer-specific and brittle, this system leverages a Large Language Model (Groq LLaMA 3.3 70B) to extract key data points from **any credit card issuer**. It also encrypts sensitive PII like card numbers, phone numbers, emails, and account holder names, making the solution extremely secure.

It supports password-protected PDFs, eliminating the hassle of manually unlocking bank documents. Users can upload statements along with passwords, allowing seamless extraction.

---

## Key Features

- Extracts card issuer, last 4 digits, minimum payment, statement date, total balance, and account holder name.  
- Supports **any credit card issuer**, thanks to LLM context awareness.  
- Encrypts sensitive information (card numbers, phone numbers, emails, names) for safety.  
- Handles **password-protected PDFs** efficiently.  
- Returns clean, decrypted JSON results locally.  

---

## Why LLM Over Regex?

- Regex and traditional parsing are **issuer-specific**, brittle, and can miss context-sensitive data.  
- LLM understands **textual context** across formats, allowing extraction from practically **any statement layout**.  
- Preserves structured data even when formats vary or include unusual line breaks.  

---

## Technology Stack

| Component      | Technology         |
| -------------- | ----------------- |
| Backend        | Flask              |
| PDF Processing | PyMuPDF (fitz)     |
| AI Model       | Groq LLaMA 3.3 70B |
| Encryption     | Fernet (AES-128)   |
| Env Management | python-dotenv      |

---

## How It Works

1. **PDF Processing:** Reads PDF content, including password-protected statements.  
2. **PII Encryption:** Detects and encrypts sensitive information while preserving placeholders.  
3. **LLM Extraction:** Sends encrypted text to Groq LLaMA for accurate, context-aware data extraction.  
4. **Decryption:** Placeholders are replaced locally with original values to provide clean JSON output.  

---

## App Structure

- **app.py** – Main Flask application handling uploads, encryption, LLM extraction, and decryption.  
- **PIIEncryptor** – Handles encryption of sensitive information and mapping for decryption.  
- **PDF Extraction** – Uses PyMuPDF to read text from PDFs, including password-protected files.  
- **LLM Integration** – Uses Groq API for extracting key data points.  

---

## Setup Instructions

1. **Clone Repository**  
   ```bash
   git clone <repo-url>
   cd <repo-directory>
2. **Install Dependencies**
3. **Create .env File**
   ```bash
   GROQ_API_KEY=<your-groq-api-key>
   
5. **Run Flask App**
   ```bash
   python app.py
