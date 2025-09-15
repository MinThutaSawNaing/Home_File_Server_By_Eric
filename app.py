import os
import json
import shutil
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import unquote

import uvicorn
from fastapi import FastAPI, Request, Response, File, UploadFile, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(title="Small Business File Server")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Constants
UPLOAD_DIR = Path("uploads")
USER_DATA_FILE = Path("users.json")
SESSION_FILE = Path("sessions.json")

# Create upload directory if it doesn't exist
UPLOAD_DIR.mkdir(exist_ok=True)

# Supported file types
SUPPORTED_EXTENSIONS = {
    'documents': ['.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'],
    'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg'],
    'audio': ['.mp3', '.wav', '.aac', '.flac'],
    'video': ['.mp4', '.avi', '.mkv', '.mov'],
    'compressed': ['.zip', '.rar', '.7z'],
    'executables': ['.exe', '.msi', '.apk', '.dmg']
}

# Initialize user data file if it doesn't exist
if not USER_DATA_FILE.exists():
    with open(USER_DATA_FILE, 'w') as f:
        json.dump({}, f)

# Initialize session file if it doesn't exist
if not SESSION_FILE.exists():
    with open(SESSION_FILE, 'w') as f:
        json.dump({}, f)

class User(BaseModel):
    name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class FolderCreateRequest(BaseModel):
    name: str
    path: str

class FileMoveCopyRequest(BaseModel):
    source: str
    destination: str

class FileDeleteRequest(BaseModel):
    path: str

def load_users() -> Dict:
    """Load users from JSON file"""
    try:
        with open(USER_DATA_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading users: {e}")
        return {}

def save_users(users: Dict):
    """Save users to JSON file"""
    try:
        with open(USER_DATA_FILE, 'w') as f:
            json.dump(users, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving users: {e}")

def load_sessions() -> Dict:
    """Load sessions from JSON file"""
    try:
        with open(SESSION_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading sessions: {e}")
        return {}

def save_sessions(sessions: Dict):
    """Save sessions to JSON file"""
    try:
        with open(SESSION_FILE, 'w') as f:
            json.dump(sessions, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving sessions: {e}")

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def create_session_token(email: str) -> str:
    """Create a session token"""
    token = hashlib.sha256(f"{email}{datetime.now()}".encode()).hexdigest()
    return token

def get_user_from_session(request: Request) -> Optional[Dict]:
    """Get user from session"""
    sessions = load_sessions()
    token = request.cookies.get("session_token")
    
    if token and token in sessions:
        session = sessions[token]
        # Check if session is expired (24 hours)
        if datetime.now() < datetime.fromisoformat(session["expires"]):
            users = load_users()
            if session["email"] in users:
                return {
                    "name": users[session["email"]]["name"],
                    "email": session["email"]
                }
    
    return None

def require_auth(request: Request):
    """Dependency to require authentication"""
    user = get_user_from_session(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

@app.get("/")
async def index():
    """Serve the main page"""
    return FileResponse("index.html")

@app.get("/index.html")
async def serve_index():
    """Serve the index.html file"""
    return FileResponse("index.html")

# Auth endpoints
@app.post("/api/auth/register")
async def register(user: User):
    """Register a new user"""
    users = load_users()
    
    # Check if user already exists
    if user.email in users:
        return JSONResponse({
            "success": False,
            "message": "User already exists"
        })
    
    # Hash password
    hashed_password = hash_password(user.password)
    
    # Save user
    users[user.email] = {
        "name": user.name,
        "email": user.email,
        "password": hashed_password
    }
    save_users(users)
    
    return JSONResponse({
        "success": True,
        "message": "User registered successfully"
    })

@app.post("/api/auth/login")
async def login(login_data: LoginRequest):
    """Login user"""
    users = load_users()
    
    # Check if user exists
    if login_data.email not in users:
        return JSONResponse({
            "success": False,
            "message": "Invalid email or password"
        })
    
    # Check password
    hashed_password = hash_password(login_data.password)
    if users[login_data.email]["password"] != hashed_password:
        return JSONResponse({
            "success": False,
            "message": "Invalid email or password"
        })
    
    # Create session
    token = create_session_token(login_data.email)
    sessions = load_sessions()
    sessions[token] = {
        "email": login_data.email,
        "created": datetime.now().isoformat(),
        "expires": (datetime.now() + timedelta(hours=24)).isoformat()
    }
    save_sessions(sessions)
    
    # Return response with cookie
    response = JSONResponse({
        "success": True,
        "user": {
            "name": users[login_data.email]["name"],
            "email": login_data.email
        }
    })
    response.set_cookie(
        key="session_token", 
        value=token, 
        httponly=True, 
        max_age=86400,  # 24 hours
        samesite="strict"
    )
    
    return response

@app.post("/api/auth/logout")
async def logout(request: Request):
    """Logout user"""
    token = request.cookies.get("session_token")
    if token:
        sessions = load_sessions()
        if token in sessions:
            del sessions[token]
            save_sessions(sessions)
    
    response = JSONResponse({"success": True})
    response.delete_cookie("session_token")
    return response

@app.get("/api/auth/status")
async def auth_status(request: Request):
    """Check authentication status"""
    user = get_user_from_session(request)
    return JSONResponse({
        "authenticated": user is not None,
        "user": user if user else None
    })

# File operations endpoints
@app.post("/api/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    path: str = "/",
    user: Dict = Depends(require_auth)
):
    """Upload a file"""
    try:
        # Validate file extension
        file_extension = Path(file.filename).suffix.lower()
        is_supported = any(file_extension in ext_list for ext_list in SUPPORTED_EXTENSIONS.values())
        
        if not is_supported:
            return JSONResponse({
                "success": False,
                "message": f"File type {file_extension} is not supported"
            })
        
        # Create full path
        file_path = UPLOAD_DIR / path.strip("/") / file.filename
        
        # Create directory if it doesn't exist
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save file
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        return JSONResponse({
            "success": True,
            "message": "File uploaded successfully",
            "filename": file.filename,
            "path": str(file_path.relative_to(UPLOAD_DIR))
        })
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return JSONResponse({
            "success": False,
            "message": f"Error uploading file: {str(e)}"
        })

@app.get("/api/files/list")
async def list_files(
    path: str = "/",
    user: Dict = Depends(require_auth)
):
    """List files in a directory"""
    try:
        # Create full path
        dir_path = UPLOAD_DIR / path.strip("/")
        
        # Check if directory exists
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Get files
        files = []
        for item in dir_path.iterdir():
            if item.is_file():
                files.append({
                    "name": item.name,
                    "path": str(item.relative_to(UPLOAD_DIR)),
                    "size": item.stat().st_size,
                    "modified": datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                })
        
        # Sort files by name
        files.sort(key=lambda x: x["name"])
        
        return JSONResponse({
            "success": True,
            "files": files
        })
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        return JSONResponse({
            "success": False,
            "message": f"Error listing files: {str(e)}"
        })

@app.get("/api/files/download")
async def download_file(
    path: str,
    user: Dict = Depends(require_auth)
):
    """Download a file"""
    try:
        # Decode path
        decoded_path = unquote(path)
        
        # Create full path
        file_path = UPLOAD_DIR / decoded_path.strip("/")
        
        # Check if file exists
        if not file_path.exists() or not file_path.is_file():
            raise HTTPException(status_code=404, detail="File not found")
        
        # Get filename
        filename = file_path.name
        
        return FileResponse(
            file_path,
            filename=filename,
            media_type="application/octet-stream"
        )
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        raise HTTPException(status_code=500, detail=f"Error downloading file: {str(e)}")

@app.post("/api/files/move")
async def move_file(
    request_data: FileMoveCopyRequest,
    user: Dict = Depends(require_auth)
):
    """Move a file"""
    try:
        source_path = UPLOAD_DIR / request_data.source.strip("/")
        destination_path = UPLOAD_DIR / request_data.destination.strip("/") / source_path.name
        
        # Check if source exists
        if not source_path.exists():
            return JSONResponse({
                "success": False,
                "message": "Source file not found"
            })
        
        # Create destination directory if it doesn't exist
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Move file
        shutil.move(str(source_path), str(destination_path))
        
        return JSONResponse({
            "success": True,
            "message": "File moved successfully"
        })
    except Exception as e:
        logger.error(f"Error moving file: {e}")
        return JSONResponse({
            "success": False,
            "message": f"Error moving file: {str(e)}"
        })

@app.post("/api/files/copy")
async def copy_file(
    request_data: FileMoveCopyRequest,
    user: Dict = Depends(require_auth)
):
    """Copy a file"""
    try:
        source_path = UPLOAD_DIR / request_data.source.strip("/")
        destination_path = UPLOAD_DIR / request_data.destination.strip("/") / source_path.name
        
        # Check if source exists
        if not source_path.exists():
            return JSONResponse({
                "success": False,
                "message": "Source file not found"
            })
        
        # Create destination directory if it doesn't exist
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Copy file
        shutil.copy2(str(source_path), str(destination_path))
        
        return JSONResponse({
            "success": True,
            "message": "File copied successfully"
        })
    except Exception as e:
        logger.error(f"Error copying file: {e}")
        return JSONResponse({
            "success": False,
            "message": f"Error copying file: {str(e)}"
        })

@app.post("/api/files/delete")
async def delete_file(
    request_data: FileDeleteRequest,
    user: Dict = Depends(require_auth)
):
    """Delete a file"""
    try:
        file_path = UPLOAD_DIR / request_data.path.strip("/")
        
        # Check if file exists
        if not file_path.exists():
            return JSONResponse({
                "success": False,
                "message": "File not found"
            })
        
        # Delete file
        file_path.unlink()
        
        return JSONResponse({
            "success": True,
            "message": "File deleted successfully"
        })
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return JSONResponse({
            "success": False,
            "message": f"Error deleting file: {str(e)}"
        })

# Folder operations endpoints
@app.post("/api/folders/create")
async def create_folder(
    folder_data: FolderCreateRequest,
    user: Dict = Depends(require_auth)
):
    """Create a new folder"""
    try:
        # Create full path
        folder_path = UPLOAD_DIR / folder_data.path.strip("/") / folder_data.name
        
        # Check if folder already exists
        if folder_path.exists():
            return JSONResponse({
                "success": False,
                "message": "Folder already exists"
            })
        
        # Create folder
        folder_path.mkdir(parents=True, exist_ok=True)
        
        return JSONResponse({
            "success": True,
            "message": "Folder created successfully",
            "path": str(folder_path.relative_to(UPLOAD_DIR))
        })
    except Exception as e:
        logger.error(f"Error creating folder: {e}")
        return JSONResponse({
            "success": False,
            "message": f"Error creating folder: {str(e)}"
        })

@app.get("/api/folders/list")
async def list_folders(user: Dict = Depends(require_auth)):
    """List all folders"""
    try:
        folders = []
        
        # Walk through all directories
        for dir_path in UPLOAD_DIR.rglob("*"):
            if dir_path.is_dir():
                # Skip the uploads directory itself
                if dir_path == UPLOAD_DIR:
                    continue
                
                # Get relative path
                rel_path = dir_path.relative_to(UPLOAD_DIR)
                
                folders.append({
                    "name": dir_path.name,
                    "path": str(rel_path) + "/",
                    "created": datetime.fromtimestamp(dir_path.stat().st_ctime).isoformat()
                })
        
        # Add root folder
        folders.insert(0, {
            "name": "Root",
            "path": "/",
            "created": datetime.now().isoformat()
        })
        
        # Sort folders by path
        folders.sort(key=lambda x: x["path"])
        
        return JSONResponse({
            "success": True,
            "folders": folders
        })
    except Exception as e:
        logger.error(f"Error listing folders: {e}")
        return JSONResponse({
            "success": False,
            "message": f"Error listing folders: {str(e)}"
        })

# Server status endpoint
@app.get("/api/server/status")
async def server_status():
    """Get server status"""
    try:
        # Calculate storage usage
        total_size = 0
        file_count = 0
        
        for file_path in UPLOAD_DIR.rglob("*"):
            if file_path.is_file():
                total_size += file_path.stat().st_size
                file_count += 1
        
        # Convert to human readable format
        def format_size(size_bytes):
            if size_bytes == 0:
                return "0 B"
            size_names = ["B", "KB", "MB", "GB", "TB"]
            i = 0
            while size_bytes >= 1024 and i < len(size_names) - 1:
                size_bytes /= 1024
                i += 1
            return f"{size_bytes:.1f} {size_names[i]}"
        
        # Get active users (sessions that haven't expired)
        sessions = load_sessions()
        active_users = 0
        now = datetime.now()
        
        for session in sessions.values():
            if now < datetime.fromisoformat(session["expires"]):
                active_users += 1
        
        # Determine server status
        # Simple logic: if we can read the uploads directory, server is online
        server_status = "online"
        if total_size > 100 * 1024 * 1024 * 1024:  # 100 GB
            server_status = "warning"
        
        # Calculate uptime (since server started)
        # In a real application, you would track actual server start time
        # Here we'll use a simple approximation
        uptime_seconds = 3600  # 1 hour (placeholder)
        
        # Calculate storage used percentage
        # Assuming 1TB total storage for demo purposes
        total_storage = 1024 * 1024 * 1024 * 1024  # 1 TB
        storage_used_percent = min(100, (total_size / total_storage) * 100)
        storage_used_str = f"{storage_used_percent:.1f}%"
        
        return JSONResponse({
            "success": True,
            "status": server_status,
            "storageUsed": storage_used_str,
            "activeUsers": active_users,
            "totalFiles": file_count,
            "uptime": uptime_seconds,
            "totalStorage": format_size(total_storage),
            "usedStorage": format_size(total_size)
        })
    except Exception as e:
        logger.error(f"Error getting server status: {e}")
        return JSONResponse({
            "success": False,
            "message": f"Error getting server status: {str(e)}"
        })

if __name__ == "__main__":
    # Create uploads directory if it doesn't exist
    UPLOAD_DIR.mkdir(exist_ok=True)
    
    # Start server
    uvicorn.run(app, host="0.0.0.0", port=8000)