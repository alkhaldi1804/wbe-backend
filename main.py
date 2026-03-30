from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
import os
import bcrypt
import uuid

# 🔥 Database
from database import engine, SessionLocal
from models import Base, User

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

# Create tables
Base.metadata.create_all(bind=engine)

# CORS
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

# -----------------------------
# Request Model
# -----------------------------
class SignupRequest(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str

# -----------------------------
# Root
# -----------------------------
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
    try:
        return run_whois(domain)
    except Exception as e:
        return {"error": str(e)}

# -----------------------------
# Email Checker
# -----------------------------
@app.get("/email")
def email_lookup(email: str):
    try:
        return check_email(email)
    except Exception as e:
        return {"error": str(e)}

# -----------------------------
# Binary Analyzer
# -----------------------------
@app.post("/binary-analyze")
async def binary_analyze_endpoint(file: UploadFile = File(...)):
    try:
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

    except Exception as e:
        return {"error": str(e)}

# -----------------------------
# Identity Exposure Scanner
# -----------------------------
@app.get("/identity")
def identity_scan(value: str):
    try:
        result = analyze_identity(value)

        return {
            "input": value,
            "analysis": result
        }

    except Exception as e:
        return {"error": str(e)}

# -----------------------------
# Signup API
# -----------------------------
@app.post("/signup")
def signup(data: SignupRequest):

    db: Session = SessionLocal()

    # Check email
    existing_user = db.query(User).filter(User.email == data.email).first()
    if existing_user:
        db.close()
        raise HTTPException(status_code=400, detail="Email already exists")

    # Hash password
    hashed_password = bcrypt.hashpw(
        data.password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    # Generate verification token
    token = str(uuid.uuid4())

    # Create user
    new_user = User(
        first_name=data.first_name,
        last_name=data.last_name,
        email=data.email,
        password=hashed_password,
        verification_token=token
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    db.close()

    return {
        "message": "User created successfully",
        "verification_token": token
    }

# -----------------------------
# Email Verification API
# -----------------------------
@app.get("/verify")
def verify_email(token: str):

    db: Session = SessionLocal()

    user = db.query(User).filter(User.verification_token == token).first()

    if not user:
        db.close()
        raise HTTPException(status_code=400, detail="Invalid token")

    user.is_verified = True
    user.verification_token = None

    db.commit()
    db.close()

    return {
        "message": "Email verified successfully"
    }