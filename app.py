import os
from flask import Flask, request, jsonify, render_template
import json
import re
import fitz  # PyMuPDF
from groq import Groq
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import base64

load_dotenv()

API_KEY = os.getenv("GROQ_API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")

# Generate encryption key (store this securely!)
# For production, use: SECRET_KEY from .env
if not SECRET_KEY:
    SECRET_KEY = Fernet.generate_key().decode()
    print(f"Generated key: {SECRET_KEY}")

cipher = Fernet(SECRET_KEY.encode() if isinstance(SECRET_KEY, str) else SECRET_KEY)

app = Flask(__name__)
client = Groq(api_key=API_KEY)


class PIIEncryptor:
    """Encrypts PII values while preserving labels and structure"""
    
    def __init__(self, cipher):
        self.cipher = cipher
        self.mapping = {}  # Store original -> encrypted mappings
        self.last_4_digits = None  # Store last 4 digits of account number
        
    def _create_placeholder(self, value, prefix="ENC"):
        """Create a readable placeholder that preserves format hints"""
        # Encrypt the actual value
        encrypted = self.cipher.encrypt(value.encode()).decode()
        
        # Create a short token for the LLM
        token = base64.urlsafe_b64encode(encrypted[:12].encode()).decode()[:8]
        placeholder = f"{prefix}_{token}"
        
        # Store mapping for decryption
        self.mapping[placeholder] = value
        return placeholder
    
    def encrypt_text(self, text):
        """Encrypt PII in text while keeping labels"""
        encrypted_text = text
        
        # 1. Encrypt 10-digit phone numbers (not 4-digit last 4)
        # Must be exactly 10 digits, possibly with separators
        def replace_phone(match):
            return self._create_placeholder(match.group(0), "PHONE")
        
        # Match 10-digit phone patterns
        encrypted_text = re.sub(
            r'\b\d{10}\b|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b|\(\d{3}\)\s?\d{3}[-.\s]\d{4}',
            replace_phone,
            encrypted_text
        )
        
        # 2. Encrypt full account/card numbers (12-19 digits, not 4 digits)
        # Only if it's a long sequence, not "Last 4 Digits"
        def replace_account(match):
            full_number = match.group(0)
            # Skip if it's only 4 digits (that's the last 4)
            digits_only = re.sub(r'[\s-]', '', full_number)
            if len(digits_only) <= 4:
                return full_number  # Don't encrypt last 4
            
            if '-' in full_number or ' ' in full_number:
                return self._create_placeholder(full_number, "CARD")
            return self._create_placeholder(full_number, "ACCT")
        
        encrypted_text = re.sub(
            r'\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4,6}\b',  # 16-19 digit cards
            replace_account,
            encrypted_text
        )
        
        # 3. Encrypt account numbers (various formats)
        # Match patterns like "Account Number: 123456789012"
        def replace_account_num(match):
            prefix = match.group(1)
            number = match.group(2)
            # Only encrypt if it's more than 4 digits
            if len(number) > 4:
                # Store last 4 digits before encrypting
                if not self.last_4_digits:  # Only store first account number found
                    self.last_4_digits = number[-4:]
                return f"{prefix}{self._create_placeholder(number, 'ACCT')}"
            return match.group(0)
        
        encrypted_text = re.sub(
            r'(Account Number|Account #|Acct\s*#?|Account No\.?)[\s:]+(\d{5,})',
            replace_account_num,
            encrypted_text,
            flags=re.IGNORECASE
        )
        
        # Also look for standalone long numbers that might be account numbers
        def replace_standalone_account(match):
            number = match.group(0)
            # Only if 10+ digits and not already encrypted
            if len(number) >= 10:
                if not self.last_4_digits:
                    self.last_4_digits = number[-4:]
                return self._create_placeholder(number, 'ACCT')
            return number
        
        # Match standalone sequences of 10+ digits (likely account numbers)
        encrypted_text = re.sub(
            r'\b\d{10,}\b',
            replace_standalone_account,
            encrypted_text
        )
        
        # 3. Encrypt names - more precise pattern
        # Match "Name\n" followed by actual name on next line or after whitespace
        def replace_name(match):
            prefix = match.group(1)
            name = match.group(2).strip()
            
            # Skip if it's just labels/headers
            if name.lower() in ['name', 'detail', 'field', 'information']:
                return match.group(0)
            
            encrypted_name = self._create_placeholder(name, "NAME")
            return f"{prefix}{encrypted_name}"
        
        # Pattern: "Cardmember Name" followed by newline/whitespace and actual name
        encrypted_text = re.sub(
            r'(Cardmember Name|Account Holder Name|Customer Name)[\s\n]+([A-Z][a-z]+(?:\s+[A-Z]\.?\s+)?[A-Z][a-z]+)',
            replace_name,
            encrypted_text,
            flags=re.IGNORECASE
        )
        
        # 4. Encrypt SSN
        def replace_ssn(match):
            return self._create_placeholder(match.group(0), "SSN")
        
        encrypted_text = re.sub(
            r'\b\d{3}-\d{2}-\d{4}\b',
            replace_ssn,
            encrypted_text
        )
        
        # 5. Encrypt email addresses
        def replace_email(match):
            return self._create_placeholder(match.group(0), "EMAIL")
        
        encrypted_text = re.sub(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            replace_email,
            encrypted_text
        )
        
        return encrypted_text
    
    def decrypt_response(self, response_data):
        """Decrypt PII in the parsed response"""
        if isinstance(response_data, dict):
            decrypted = {}
            for key, value in response_data.items():
                if isinstance(value, str):
                    # Check if value contains our placeholders
                    for placeholder, original in self.mapping.items():
                        if placeholder in value:
                            value = value.replace(placeholder, original)
                decrypted[key] = value
            return decrypted
        return response_data


def extract_text_from_pdf(file_stream, password=None):
    """Extract text from PDF with optional password handling."""
    try:
        doc = fitz.open(stream=file_stream.read(), filetype="pdf")
        
        if doc.is_encrypted:
            if password:
                if not doc.authenticate(password):
                    raise ValueError("Incorrect password for PDF.")
            else:
                raise ValueError("PDF is encrypted. Please provide a password.")
        
        text = ""
        for page in doc:
            text += page.get_text()
        
        if not text.strip():
            raise ValueError("No text could be extracted from the PDF.")
        
        return text
    
    except Exception as e:
        raise ValueError(f"Error reading PDF: {e}")


def safe_parse_groq_response(raw_response):
    """Safely extract JSON from Groq/LLaMA response."""
    try:
        cleaned = re.sub(r"```(?:json)?\n|```", "", raw_response).strip()
        start = cleaned.find("{")
        end = cleaned.rfind("}") + 1
        json_str = cleaned[start:end]
        return json.loads(json_str)
    except Exception as e:
        print("Failed to parse Groq response:", e)
        return {"error": "Failed to parse Groq response"}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/parse", methods=["POST"])
def parse_statement():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files["file"]
    password = request.form.get("password")
    
    try:
        # Extract text from PDF
        if file.filename.lower().endswith(".pdf"):
            text = extract_text_from_pdf(file, password=password)
        else:
            text = file.read().decode(errors="ignore")
        
        # Initialize encryptor
        encryptor = PIIEncryptor(cipher)
        
        # Encrypt PII in the text
        encrypted_text = encryptor.encrypt_text(text)
        
        print("=== ORIGINAL TEXT (first 500 chars) ===")
        print(text[:500])
        print("\n=== ENCRYPTED TEXT (first 500 chars) ===")
        print(encrypted_text[:500])
        print(f"\n=== ENCRYPTION MAPPING ===")
        print(json.dumps(encryptor.mapping, indent=2))
        
        # Send encrypted text to Groq
        system_prompt = (
            "You are a helpful assistant. Extract the following fields from a credit card statement:\n"
            "1. Card Issuer\n"
            "2. Last 4 Digits of account number or card number (ONLY THE LAST 4 DIGITS, not the full number)\n"
            "3. Minimum Payment Due\n"
            "4. Statement Date\n"
            "5. Total Balance Due\n"
            "6. Account Holder Name (if present)\n\n"
            "IMPORTANT: For 'last_4', extract ONLY the last 4 digits of any account/card number. "
            "If you see a full number like '50100697807676', return only '7676'.\n"
            "If the number is encrypted (like ACCT_xxxxx), return 'ENCRYPTED' as the value.\n\n"
            "Note: Some values may be encrypted (like ENC_XXXXX, CARD_XXXXX, NAME_XXXXX). "
            "Extract them as-is, preserving the encrypted format.\n\n"
            "Return the answer as JSON with keys: card_issuer, last_4, min_payment, "
            "statement_date, total_balance, account_holder."
        )
        
        user_prompt = f"Extract data from the following text:\n\n{encrypted_text}"
        
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            model="llama-3.3-70b-versatile"
        )
        
        raw_response = chat_completion.choices[0].message.content
        print("\n=== GROQ RAW RESPONSE ===")
        print(raw_response)
        
        # Parse response
        encrypted_data = safe_parse_groq_response(raw_response)
        
        # Decrypt PII in the response
        decrypted_data = encryptor.decrypt_response(encrypted_data)
        
        # Add the last 4 digits if we extracted them
        if encryptor.last_4_digits:
            decrypted_data['last_4'] = encryptor.last_4_digits
        
        print("\n=== DECRYPTED RESPONSE ===")
        print(json.dumps(decrypted_data, indent=2))
        
        return jsonify(decrypted_data)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)
    app.run(debug=True)