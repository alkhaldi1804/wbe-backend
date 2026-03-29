from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import os

# Import tools
from tools.whois_tool import run_whois
from tools.email_checker import check_email
from tools.binary_analyzer import analyze_binary
from tools.identity_scanner import analyze_identity

# Create FastAPI app
app = FastAPI(
    title="WBE Tools API",
    description="Backend API for WBE Cybersecurity Tools",
    version="1.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Upload folder
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Root
@app.get("/")
def home():
    return {
        "status": "running",
        "service": "WBE Tools Backend",
        "tools": [
            "WHOIS Lookup",
            "Email Checker",
            "Binary Analyzer",
            "Identity Exposure Scanner"
        ]
    }

# -----------------------------
# WHOIS
# -----------------------------
@app.get("/whois")
def whois_lookup(domain: str):
    return run_whois(domain)

# -----------------------------
# Email Checker
# -----------------------------
@app.get("/email")
def email_lookup(email: str):
    return check_email(email)

# -----------------------------
# Binary Analyzer
# -----------------------------
@app.post("/binary-analyze")
async def binary_analyze(file: UploadFile = File(...)):

    safe_filename = os.path.basename(file.filename).replace(" ", "_")
    file_path = os.path.join(UPLOAD_FOLDER, safe_filename)

    with open(file_path, "wb") as f:
        f.write(await file.read())

    result = analyze_binary(file_path)

    try:
        os.remove(file_path)
    except:
        pass

    return {
        "status": "success",
        "analysis": result
    }

# -----------------------------
# 🔥 Identity Exposure Scanner
# -----------------------------
@app.get("/identity")
def identity_scan(value: str):

    result = analyze_identity(value)

    return {
        "input": value,
        "analysis": result
    }