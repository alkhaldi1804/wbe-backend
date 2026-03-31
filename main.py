from fastapi.responses import RedirectResponse
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session
import os
import bcrypt
import uuid
import asyncio  # 🔥 NEW


# 🔥 EMAIL
from email_utils import send_verification_email  # 🔥 NEW

# 🔥 JWT
from jose import jwt, JWTError
from datetime import datetime, timedelta

# 🔥 Database
from database import engine, SessionLocal
from models import Base, User

# Import tools
from tools.whois_tool import run_whois
from tools.email_checker import check_email
from tools.binary_analyzer import analyze_binary
from tools.identity_scanner import analyze_identity

# -----------------------------
# JWT CONFIG
# -----------------------------
SECRET_KEY = "9f8d7a6b5c4e3f2a1b0c9d8e7f6a5b4c"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# -----------------------------
# SECURITY
# -----------------------------
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")

        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        return email

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Create FastAPI app
app = FastAPI(
    title="WBE Tools API",
    description="Backend API for WBE Cybersecurity Tools",
    version="1.0"
)

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

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
# Request Models
# -----------------------------
class SignupRequest(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

# -----------------------------
# JWT Function
# -----------------------------
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

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
# Identity Exposure Scanner (🔒 Protected)
# -----------------------------
@app.get("/identity")
def identity_scan(value: str, user: str = Depends(get_current_user)):
    try:
        result = analyze_identity(value)

        return {
            "user": user,
            "input": value,
            "analysis": result
        }

    except Exception as e:
        return {"error": str(e)}

# -----------------------------
# Signup API (🔥 UPDATED)
# -----------------------------
@app.post("/signup")
async def signup(data: SignupRequest):

    db: Session = SessionLocal()

    existing_user = db.query(User).filter(User.email == data.email).first()
    if existing_user:
        db.close()
        raise HTTPException(status_code=400, detail="Email already exists")

    hashed_password = bcrypt.hashpw(
        data.password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    token = str(uuid.uuid4())

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

    # 🔥 BACKGROUND TASK (بدون انتظار)
    asyncio.get_event_loop().create_task(
        send_verification_email(
            new_user.email,
            token,
            new_user.first_name
        )
    )

    db.close()

    return {
        "message": "User created successfully",
        "verification_token": token
    }

# -----------------------------
# Email Verification API
# -----------------------------
@app.get("/verify", response_class=HTMLResponse)
def verify_email(token: str):

    db: Session = SessionLocal()

    user = db.query(User).filter(User.verification_token == token).first()

    # ❌ توكن غير صحيح أو مستخدم
    if not user:
        db.close()

        return """
        <html>
        <head>
        <title>Verification Failed</title>
        </head>
        <body style="background:#0f172a;display:flex;justify-content:center;align-items:center;height:100vh;color:white;font-family:sans-serif;">
        
        <div style="text-align:center;background:rgba(255,255,255,0.05);padding:30px;border-radius:15px;">
            <h1 style="color:red;">❌ Invalid or Expired Link</h1>
            <p>This verification link is no longer valid.</p>
        </div>

        </body>
        </html>
        """

    # ❗ إذا مفعل مسبقًا
    if user.is_verified:
        db.close()

        return f"""
        <html>
        <body style="background:#0f172a;display:flex;justify-content:center;align-items:center;height:100vh;color:white;font-family:sans-serif;">
        
        <div style="text-align:center;background:rgba(255,255,255,0.05);padding:30px;border-radius:15px;">
            <h1 style="color:orange;">⚠️ Already Verified</h1>
            <p>This email has already been verified.</p>
        </div>

        </body>
        </html>
        """

    # ✅ تفعيل الحساب
    user.is_verified = True
    user.verification_token = None

    db.commit()
    db.close()

    return f"""
    <html>
    <body style="background:#0f172a;display:flex;justify-content:center;align-items:center;height:100vh;color:white;font-family:sans-serif;">
    
    <div style="text-align:center;background:rgba(255,255,255,0.05);padding:30px;border-radius:15px;">
        <h1 style="color:#00FF99;">✅ Email Verified Successfully</h1>
        <p>You can now return to the app and continue.</p>
    </div>

    </body>
    </html>
    """
# -----------------------------
# Login API (JWT)
# -----------------------------
@app.post("/login")
def login(data: LoginRequest):

    db: Session = SessionLocal()

    user = db.query(User).filter(User.email == data.email).first()

    if not user:
        db.close()
        raise HTTPException(status_code=400, detail="Invalid email or password")

    if not bcrypt.checkpw(data.password.encode(), user.password.encode()):
        db.close()
        raise HTTPException(status_code=400, detail="Invalid email or password")

    if not user.is_verified:
        db.close()
        raise HTTPException(status_code=403, detail="Email not verified")

    token = create_access_token({
        "sub": user.email
    })

    db.close()

    return {
        "access_token": token,
        "token_type": "bearer"
    }

# -----------------------------
# Get Current User (JWT)
# -----------------------------
@app.get("/me")
def get_me(user_email: str = Depends(get_current_user)):

    db: Session = SessionLocal()

    user = db.query(User).filter(User.email == user_email).first()

    if not user:
        db.close()
        raise HTTPException(status_code=404, detail="User not found")

    data = {
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "is_verified": user.is_verified  # 🔥 الإضافة المهمة
    }

    db.close()

    return data