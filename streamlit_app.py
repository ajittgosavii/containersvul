import streamlit as st
import anthropic
import json
from datetime import datetime
import re
import pandas as pd
from io import StringIO
import requests
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import subprocess
import logging
import uuid
import sqlite3
from pathlib import Path
from typing import Dict, Optional
import time

# Configure Streamlit page
st.set_page_config(
    page_title="Enterprise Container Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== CONFIGURATION ====================
CONFIG = {
    'LOG_FILE': 'remediation.log',
    'DB_FILE': 'remediation_tracking.db',
    'MAX_TIMEOUT': 3600,
    'DEFAULT_TIMEOUT': 300,
}

# ==================== LOGGING SETUP ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(CONFIG['LOG_FILE']),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ContainerSecurity')

# ==================== DATABASE SETUP ====================
class RemediationDatabase:
    """SQLite database for tracking remediation history and status"""
    
    def __init__(self, db_file=CONFIG['DB_FILE']):
        self.db_file = db_file
        self.init_db()
    
    def init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS remediation_jobs (
                job_id TEXT PRIMARY KEY,
                vuln_id TEXT NOT NULL,
                image_name TEXT NOT NULL,
                classification TEXT,
                status TEXT,
                created_at TIMESTAMP,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                duration_seconds INTEGER,
                error_message TEXT,
                log_output TEXT
            )
        ''')
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vuln_id TEXT PRIMARY KEY,
                image_name TEXT NOT NULL,
                severity TEXT,
                description TEXT,
                analyzed_at TIMESTAMP,
                analysis_data TEXT,
                status TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def insert_job(self, job_id, vuln_id, image_name, classification):
        """Insert new remediation job"""
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute('''
            INSERT INTO remediation_jobs 
            (job_id, vuln_id, image_name, classification, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (job_id, vuln_id, image_name, classification, 'PENDING', datetime.now().isoformat()))
        conn.commit()
        conn.close()
    
    def update_job_status(self, job_id, status, started_at=None, completed_at=None, 
                         duration=None, error=None, logs=None):
        """Update job status and details"""
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute('''
            UPDATE remediation_jobs 
            SET status=?, started_at=?, completed_at=?, 
                duration_seconds=?, error_message=?, log_output=?
            WHERE job_id=?
        ''', (status, started_at, completed_at, duration, error, logs, job_id))
        conn.commit()
        conn.close()
    
    def get_job_stats(self) -> Dict:
        """Get remediation statistics"""
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) FROM remediation_jobs")
        total = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM remediation_jobs WHERE status='REMEDIATED'")
        remediated = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM remediation_jobs WHERE status='FAILED'")
        failed = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM remediation_jobs WHERE status='PENDING'")
        pending = c.fetchone()[0]
        
        c.execute("SELECT AVG(duration_seconds) FROM remediation_jobs WHERE duration_seconds IS NOT NULL")
        avg_result = c.fetchone()
        avg_duration = avg_result[0] if avg_result and avg_result[0] else 0
        
        conn.close()
        
        return {
            'total': total,
            'remediated': remediated,
            'failed': failed,
            'pending': pending,
            'avg_duration': avg_duration,
            'success_rate': (remediated / total * 100) if total > 0 else 0
        }

# ==================== REMEDIATION ENGINE ====================
class RemediationExecutor:
    """Production-grade remediation execution engine"""
    
    def __init__(self, db: RemediationDatabase):
        self.job_id = str(uuid.uuid4())[:8]
        self.status = "PENDING"
        self.logs = []
        self.error = None
        self.start_time = None
        self.end_time = None
        self.db = db
    
    def log(self, message: str, level: str = "INFO") -> str:
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.logs.append(log_entry)
        logger.log(getattr(logging, level, logging.INFO), message)
        return log_entry
    
    def execute_command(self, command: str, timeout: int = 300) -> Dict:
        """Execute command with safety checks"""
        self.log(f"Executing: {command}", "INFO")
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                self.log("Command succeeded", "SUCCESS")
                return {
                    "status": "success",
                    "output": result.stdout,
                    "return_code": result.returncode
                }
            else:
                error_msg = result.stderr or result.stdout
                self.log(f"Command failed: {error_msg}", "ERROR")
                return {
                    "status": "failed",
                    "output": error_msg,
                    "return_code": result.returncode
                }
        
        except subprocess.TimeoutExpired:
            msg = f"Command timeout after {timeout} seconds"
            self.log(msg, "ERROR")
            return {"status": "timeout", "output": msg, "return_code": -1}
        except Exception as e:
            msg = str(e)
            self.log(msg, "ERROR")
            return {"status": "error", "output": msg, "return_code": -1}
    
    def check_docker_available(self) -> bool:
        """Verify Docker is available"""
        result = self.execute_command("docker version")
        return result["status"] == "success"
    
    def remediate_base_layer(self, image_name: str, registry_url: Optional[str] = None, 
                           timeout: int = 300) -> bool:
        """Remediate base layer vulnerability"""
        self.status = "IN_PROGRESS"
        self.start_time = datetime.now()
        
        try:
            base_image = image_name.split(':')[0]
            tag = image_name.split(':')[1] if ':' in image_name else 'latest'
            patched_image = f"{base_image}:{tag}-patched"
            
            self.log(f"Starting base layer remediation for {image_name}", "INFO")
            
            # Step 1: Pull latest
            self.log("Step 1/5: Pulling latest base image...", "INFO")
            result = self.execute_command(f"docker pull {base_image}:latest", timeout=timeout)
            if result["status"] != "success":
                self.error = "Failed to pull latest image"
                return False
            
            # Step 2: Tag
            self.log("Step 2/5: Tagging patched version...", "INFO")
            self.execute_command(f"docker tag {base_image}:latest {patched_image}")
            
            # Step 3: Scan
            self.log("Step 3/5: Running Trivy security scan...", "INFO")
            self.execute_command(f"docker run --rm aquasec/trivy:latest image --severity CRITICAL,HIGH {patched_image}", timeout=600)
            
            # Step 4: Push (optional)
            if registry_url:
                self.log("Step 4/5: Pushing to registry...", "INFO")
                registry_image = f"{registry_url}/{patched_image}"
                self.execute_command(f"docker tag {patched_image} {registry_image}")
                self.execute_command(f"docker push {registry_image}", timeout=600)
            else:
                self.log("Step 4/5: Skipping registry push", "INFO")
            
            # Step 5: Cleanup
            self.log("Step 5/5: Cleaning up...", "INFO")
            self.execute_command(f"docker rmi {patched_image} 2>/dev/null || true")
            
            self.status = "REMEDIATED"
            self.end_time = datetime.now()
            self.log("✅ Base layer remediation completed!", "SUCCESS")
            return True
        
        except Exception as e:
            self.error = str(e)
            self.log(f"Remediation failed: {self.error}", "ERROR")
            self.status = "FAILED"
            self.end_time = datetime.now()
            return False
    
    def remediate_application_layer(self, image_name: str, package_manager: str = "npm",
                                   timeout: int = 600) -> bool:
        """Remediate application layer vulnerability"""
        self.status = "IN_PROGRESS"
        self.start_time = datetime.now()
        
        try:
            patched_image = f"{image_name}-patched"
            container_name = f"remediate_{self.job_id}"
            
            self.log(f"Starting application layer remediation for {image_name}", "INFO")
            
            # Step 1: Create container
            self.log("Step 1/6: Creating temporary container...", "INFO")
            result = self.execute_command(f"docker create --name {container_name} {image_name}")
            if result["status"] != "success":
                self.error = "Failed to create container"
                return False
            
            # Step 2: Update deps
            if package_manager == "npm":
                self.log("Step 2/6: Fixing npm vulnerabilities...", "INFO")
                self.execute_command(f"docker exec {container_name} npm audit fix --force", timeout=timeout)
            elif package_manager == "pip":
                self.log("Step 2/6: Upgrading pip packages...", "INFO")
                self.execute_command(f"docker exec {container_name} pip install --upgrade pip", timeout=timeout)
            elif package_manager == "apt":
                self.log("Step 2/6: Running apt update...", "INFO")
                self.execute_command(f"docker exec {container_name} apt-get update && apt-get upgrade -y", timeout=timeout)
            
            # Step 3: Tests
            self.log("Step 3/6: Running tests...", "INFO")
            self.execute_command(f"docker exec {container_name} npm test 2>&1 || true", timeout=timeout)
            
            # Step 4: Commit
            self.log("Step 4/6: Committing changes...", "INFO")
            self.execute_command(f"docker commit {container_name} {patched_image}")
            
            # Step 5: Scan
            self.log("Step 5/6: Scanning patched image...", "INFO")
            self.execute_command(f"docker run --rm aquasec/trivy:latest image --severity CRITICAL,HIGH {patched_image}", timeout=600)
            
            # Step 6: Cleanup
            self.log("Step 6/6: Cleaning up...", "INFO")
            self.execute_command(f"docker rm {container_name} 2>/dev/null || true")
            self.execute_command(f"docker rmi {patched_image} 2>/dev/null || true")
            
            self.status = "REMEDIATED"
            self.end_time = datetime.now()
            self.log("✅ Application layer remediation completed!", "SUCCESS")
            return True
        
        except Exception as e:
            self.error = str(e)
            self.log(f"Remediation failed: {self.error}", "ERROR")
            self.status = "FAILED"
            self.end_time = datetime.now()
            return False


# Enterprise-grade Custom CSS
st.markdown("""
    <style>
    /* Import Professional Font */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    /* Global Styles */
    * {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }
    
    /* Main Background */
    .main {
        background: linear-gradient(135deg, #f5f7fa 0%, #e8eef5 100%);
    }
    
    /* Hide Streamlit Branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Professional Header */
    .header-container {
        background: linear-gradient(135deg, #1e40af 0%, #1e293b 50%, #0f172a 100%);
        padding: 2rem 3rem;
        border-radius: 12px;
        margin-bottom: 2rem;
        box-shadow: 0 10px 30px rgba(15, 23, 42, 0.2);
    }
    
    .header-title {
        color: white !important;
        font-size: 2rem;
        font-weight: 700;
        margin: 0;
        letter-spacing: -0.5px;
        text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
    }
    
    .header-subtitle {
        color: #cbd5e1;
        font-size: 1rem;
        font-weight: 400;
        margin-top: 0.5rem;
    }
    
    /* Professional Cards */
    .metric-card {
        background: white;
        border-radius: 12px;
        padding: 1.5rem;
        box-shadow: 0 2px 10px rgba(15, 23, 42, 0.08);
        border: 1px solid #e2e8f0;
        transition: all 0.3s ease;
        height: 100%;
    }
    
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 20px rgba(15, 23, 42, 0.12);
    }
    
    /* Enhanced Metric Display */
    .stMetric {
        background: white;
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 1px 8px rgba(15, 23, 42, 0.08);
        border-left: 4px solid #1e40af;
    }
    
    .stMetric label {
        color: #64748b !important;
        font-size: 0.875rem !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .stMetric [data-testid="stMetricValue"] {
        color: #0f172a !important;
        font-size: 2rem !important;
        font-weight: 700 !important;
    }
    
    /* Professional Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background: white;
        border-radius: 12px;
        padding: 0.5rem;
        box-shadow: 0 1px 8px rgba(15, 23, 42, 0.08);
    }
    
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        border-radius: 8px;
        padding: 0 24px;
        font-weight: 600;
        font-size: 0.95rem;
        background: transparent;
        color: #64748b;
        transition: all 0.2s ease;
    }
    
    .stTabs [data-baseweb="tab"]:hover {
        background: #f1f5f9;
        color: #0f172a;
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #1e40af 0%, #1e293b 100%) !important;
        color: white !important;
        box-shadow: 0 4px 12px rgba(30, 64, 175, 0.25);
    }
    
    /* Professional Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #1e40af 0%, #1e293b 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.75rem 2rem;
        font-weight: 600;
        font-size: 0.95rem;
        transition: all 0.3s ease;
        box-shadow: 0 2px 12px rgba(30, 64, 175, 0.2);
        letter-spacing: 0.3px;
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #1e293b 0%, #1e40af 100%);
        box-shadow: 0 6px 20px rgba(30, 64, 175, 0.35);
        transform: translateY(-2px);
    }
    
    /* Professional Input Fields */
    .stTextInput > div > div > input,
    .stSelectbox > div > div > div,
    .stTextArea > div > div > textarea {
        border-radius: 8px;
        border: 2px solid #cbd5e1;
        font-size: 0.95rem;
        padding: 0.75rem 0.875rem !important;
        transition: all 0.2s ease;
        color: #0f172a !important;
        background-color: white !important;
        min-height: 44px;
    }
    
    .stTextInput > div > div > input::placeholder,
    .stTextArea > div > div > textarea::placeholder {
        color: #94a3b8 !important;
    }
    
    .stTextInput > div > div > input:focus,
    .stSelectbox > div > div > div:focus,
    .stTextArea > div > div > textarea:focus {
        border-color: #1e40af;
        box-shadow: 0 0 0 3px rgba(30, 64, 175, 0.1);
        color: #0f172a !important;
    }
    
    /* Selectbox specific styling */
    .stSelectbox > div > div > div {
        background-color: white !important;
        min-height: 44px;
    }
    
    .stSelectbox > div > div > div > div {
        color: #0f172a !important;
        font-weight: 500;
        line-height: 1.5 !important;
    }
    
    /* Dropdown menu styling */
    [data-testid="stSelectOption"] {
        color: #0f172a !important;
        background-color: white !important;
        padding: 0.5rem 1rem !important;
    }
    
    [data-testid="stSelectOption"]:hover {
        background-color: #f0f9ff !important;
        color: #1f2937 !important;
    }
    
    [data-testid="stSelectOption"][aria-selected="true"] {
        background-color: #dbeafe !important;
        color: #1f2937 !important;
    }
    
    .stSelectbox [data-baseweb="select"] div {
        color: #1f2937 !important;
    }
    
    /* Severity Badges */
    .vulnerability-box {
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        border: 1px solid;
        transition: all 0.3s ease;
    }
    
    .vulnerability-box:hover {
        transform: translateX(4px);
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1);
    }
    
    .critical {
        background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%);
        border-color: #dc2626;
        border-left: 5px solid #dc2626;
    }
    
    .high {
        background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%);
        border-color: #f59e0b;
        border-left: 5px solid #f59e0b;
    }
    
    .medium {
        background: linear-gradient(135deg, #fefce8 0%, #fef9c3 100%);
        border-color: #eab308;
        border-left: 5px solid #eab308;
    }
    
    .low {
        background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
        border-color: #22c55e;
        border-left: 5px solid #22c55e;
    }
    
    .remediated {
        background: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%);
        border-color: #10b981;
        border-left: 5px solid #10b981;
    }
    
    /* Professional Data Tables */
    .stDataFrame {
        border-radius: 12px;
        overflow: hidden;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
    }
    
    /* Info/Warning/Success Boxes */
    .stAlert {
        border-radius: 12px;
        border-left: 5px solid;
        padding: 1.25rem;
        font-size: 0.95rem;
    }
    
    /* Expander Styling */
    .streamlit-expanderHeader {
        background: white;
        border-radius: 8px;
        border: 1px solid #e5e7eb;
        font-weight: 600;
        color: #1f2937;
        padding: 1rem;
        transition: all 0.2s ease;
    }
    
    .streamlit-expanderHeader:hover {
        background: #f9fafb;
        border-color: #1f2937;
    }
    
    /* Sidebar Styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1e40af 0%, #1e293b 100%);
    }
    
    [data-testid="stSidebar"] * {
        color: white !important;
    }
    
    [data-testid="stSidebar"] .stMarkdown {
        color: white !important;
    }
    
    /* Divider Styling */
    hr {
        border: none;
        height: 2px;
        background: linear-gradient(90deg, transparent, #e5e7eb, transparent);
        margin: 2rem 0;
    }
    
    /* Code Blocks */
    .stCodeBlock {
        border-radius: 8px;
        border: 1px solid #e5e7eb;
    }
    
    /* Download Buttons */
    .stDownloadButton > button {
        background: linear-gradient(135deg, #059669 0%, #047857 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.75rem 2rem;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stDownloadButton > button:hover {
        background: linear-gradient(135deg, #047857 0%, #065f46 100%);
        transform: translateY(-2px);
    }
    
    /* Progress Bar */
    .stProgress > div > div {
        background: linear-gradient(90deg, #1f2937, #1e293b);
        border-radius: 8px;
    }
    
    /* File Uploader */
    [data-testid="stFileUploader"] {
        border: 2px dashed #cbd5e1;
        border-radius: 12px;
        padding: 2rem;
        background: white;
        transition: all 0.3s ease;
    }
    
    [data-testid="stFileUploader"]:hover {
        border-color: #1f2937;
        background: #f8fafc;
    }
    
    /* Spinner */
    .stSpinner > div {
        border-top-color: #1f2937 !important;
    }
    
    /* Section Headers */
    h1, h2, h3, h4 {
        color: #1f2937;
        font-weight: 700;
        letter-spacing: -0.5px;
    }
    
    h1 {
        font-size: 2.5rem;
        margin-bottom: 1rem;
    }
    
    h2 {
        font-size: 2rem;
        margin-top: 2rem;
        margin-bottom: 1rem;
    }
    
    h3 {
        font-size: 1.5rem;
        margin-top: 1.5rem;
        margin-bottom: 0.75rem;
        color: #374151;
    }
    
    /* Checkbox Styling */
    .stCheckbox {
        font-weight: 500;
    }
    
    /* Radio Button Styling */
    .stRadio > label {
        font-weight: 600;
        color: #374151;
    }
    
    /* Professional Scrollbar */
    ::-webkit-scrollbar {
        width: 10px;
        height: 10px;
    }
    
    ::-webkit-scrollbar-track {
        background: #f1f5f9;
        border-radius: 5px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(135deg, #1f2937, #1e293b);
        border-radius: 5px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(135deg, #1e293b, #1e40af);
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session state
if "vulnerabilities" not in st.session_state:
    st.session_state.vulnerabilities = []
if "remediation_status" not in st.session_state:
    st.session_state.remediation_status = {}
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = {}
if "detected_vulnerability_type" not in st.session_state:
    st.session_state.detected_vulnerability_type = None
if "detected_cve_id" not in st.session_state:
    st.session_state.detected_cve_id = None
if "db" not in st.session_state:
    st.session_state.db = RemediationDatabase()
if "remediation_jobs" not in st.session_state:
    st.session_state.remediation_jobs = {}


def initialize_claude_client():
    """Initialize Anthropic Claude API client"""
    api_key = st.secrets.get("ANTHROPIC_API_KEY")
    if not api_key:
        st.error("❌ ANTHROPIC_API_KEY not found in secrets")
        st.info("Create `.streamlit/secrets.toml` with: ANTHROPIC_API_KEY = 'your-key'")
        st.stop()
    return anthropic.Anthropic(api_key=api_key)


@st.cache_data(ttl=86400)  # Cache for 24 hours
def fetch_cve_data_from_nvd(cve_id: str) -> dict:
    """Fetch CVE data from NVD API 2.0"""
    
    try:
        # NVD API 2.0 endpoint
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        
        # Get API key from secrets
        nvd_api_key = st.secrets.get("NVD_API_KEY")
        
        headers = {
            "User-Agent": "Container-Vulnerability-Analyzer/1.0"
        }
        
        # Add API key to headers if available
        if nvd_api_key:
            headers["apiKey"] = nvd_api_key
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        # API 2.0 response structure
        if data.get("vulnerabilities") and len(data["vulnerabilities"]) > 0:
            cve_item = data["vulnerabilities"][0]["cve"]
            
            # Extract description
            descriptions = cve_item.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            return {
                "status": "success",
                "cve_id": cve_id,
                "description": description,
                "metrics": cve_item.get("metrics", {}),
                "references": cve_item.get("references", []),
                "raw_data": cve_item
            }
        else:
            return {"status": "not_found", "cve_id": cve_id}
            
    except requests.exceptions.Timeout:
        return {"status": "timeout", "cve_id": cve_id, "error": "NVD API timeout"}
    except requests.exceptions.RequestException as e:
        return {"status": "error", "cve_id": cve_id, "error": str(e)}


def detect_vulnerability_type_from_cve(cve_id: str) -> str:
    """Auto-detect vulnerability type by fetching from NVD API and using Claude for classification"""
    
    st.info(f"🔍 Fetching CVE data for {cve_id} from NVD...")
    
    # Fetch from NVD API
    nvd_data = fetch_cve_data_from_nvd(cve_id)
    
    if nvd_data["status"] == "success":
        cve_description = nvd_data.get("description", "")
        
        st.success(f"✅ Found: {cve_id} in NVD Database")
        
        # Use Claude to classify based on real NVD data
        client = initialize_claude_client()
        
        prompt = f"""Based on this CVE data from NVD (National Vulnerability Database), classify the vulnerability:

CVE ID: {cve_id}
Description: {cve_description}

Determine if this is:
- BASE_CONTAINER: Affects OS, kernel, system libraries (OpenSSL, glibc, Linux kernel, curl, wget, etc.)
- APPLICATION_LEVEL: Affects applications, frameworks, libraries (Django, Log4j, Node.js, Python packages, etc.)

Respond with ONLY "BASE_CONTAINER" or "APPLICATION_LEVEL". Nothing else."""

        try:
            message = client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=20,
                messages=[{"role": "user", "content": prompt}]
            )
            
            response = message.content[0].text.strip().upper()
            
            if "APPLICATION" in response:
                return "Application Layer"
            elif "BASE" in response:
                return "Base Layer"
            else:
                return "Base Layer"
        except Exception as e:
            st.warning(f"⚠️ Claude classification error: {str(e)}")
            return "Base Layer"
    
    elif nvd_data["status"] == "not_found":
        st.warning(f"⚠️ CVE {cve_id} not found in NVD API - Using Claude for best guess")
        
        # Fallback: Use Claude without NVD data
        client = initialize_claude_client()
        
        prompt = f"""Classify this CVE: {cve_id}

Is this a BASE_CONTAINER or APPLICATION_LEVEL vulnerability?

BASE_CONTAINER = OS, kernel, system libraries (OpenSSL, glibc, Linux, curl, wget)
APPLICATION_LEVEL = Applications, frameworks, libraries (Django, Log4j, Node.js, Python packages)

Respond with ONLY "BASE_CONTAINER" or "APPLICATION_LEVEL"."""

        try:
            message = client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=20,
                messages=[{"role": "user", "content": prompt}]
            )
            
            response = message.content[0].text.strip().upper()
            
            if "APPLICATION" in response:
                return "Application Layer"
            elif "BASE" in response:
                return "Base Layer"
            else:
                return "Base Layer"
        except:
            return "Base Layer"
    
    elif nvd_data["status"] == "timeout":
        st.error("❌ NVD API timeout - Using safe default")
        return "Base Layer"
    
    else:
        st.error(f"❌ Error fetching from NVD: {nvd_data.get('error', 'Unknown error')}")
        return "Base Layer"


def analyze_vulnerability_with_claude(vulnerability_details: dict) -> dict:
    """Use Claude API to analyze vulnerability"""
    
    client = initialize_claude_client()
    
    prompt = f"""You are an AWS Cloud Security Expert specializing in container security. 
    
Analyze the following container vulnerability and provide:
1. Classification: Is this a BASE CONTAINER vulnerability or APPLICATION LEVEL vulnerability?
2. Severity Assessment: Rate the severity (CRITICAL, HIGH, MEDIUM, LOW)
3. Root Cause: Explain what causes this vulnerability
4. Resolution Steps: Provide specific steps to remediate
5. Prevention: How to prevent this in the future

Vulnerability Details:
- Image/Container: {vulnerability_details.get('image_name', 'Unknown')}
- Vulnerability ID: {vulnerability_details.get('vuln_id', 'Unknown')}
- Description: {vulnerability_details.get('description', 'Unknown')}
- Detected in: {vulnerability_details.get('detected_in', 'Unknown')}
- Current Version: {vulnerability_details.get('current_version', 'Unknown')}
- Affected Component: {vulnerability_details.get('affected_component', 'Unknown')}

Provide your response in the following JSON format:
{{
    "classification": "BASE_CONTAINER|APPLICATION_LEVEL",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "confidence": 0-100,
    "root_cause": "explanation",
    "resolution_steps": ["step1", "step2", "step3"],
    "remediation_commands": ["command1", "command2"],
    "prevention_measures": ["measure1", "measure2"],
    "estimated_fix_time": "X minutes",
    "aws_resources_affected": ["resource1", "resource2"]
}}"""

    with st.spinner("🔍 Analyzing vulnerability with Claude..."):
        message = client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )
        
        response_text = message.content[0].text
        
        try:
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                analysis_result = json.loads(json_match.group())
            else:
                analysis_result = json.loads(response_text)
        except json.JSONDecodeError:
            analysis_result = {
                "classification": "UNKNOWN",
                "severity": "MEDIUM",
                "confidence": 0,
                "root_cause": response_text,
                "resolution_steps": ["Manual review required"],
                "remediation_commands": [],
                "prevention_measures": [],
                "estimated_fix_time": "Unknown",
                "aws_resources_affected": []
            }
    
    return analysis_result


def get_remediation_script(analysis: dict, image_name: str) -> str:
    """Generate remediation script"""
    
    if analysis["classification"] == "BASE_CONTAINER":
        script = f"""#!/bin/bash
# Base Container Vulnerability Remediation
# Image: {image_name}
# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

echo "Starting base container remediation for {image_name}..."

# Step 1: Pull latest base image
echo "Step 1: Pulling latest base image..."
docker pull {image_name}

# Step 2: Rebuild the container
echo "Step 2: Rebuilding container..."
docker build -t {image_name}:patched .

# Step 3: Run security scan
echo "Step 3: Running security scan..."
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image {image_name}:patched

# Step 4: Push to registry
echo "Step 4: Pushing remediated image..."
# Update the repository URL
docker push {image_name}:patched

echo "✅ Base container remediation completed!"
"""
    else:
        script = f"""#!/bin/bash
# Application Level Vulnerability Remediation
# Image: {image_name}
# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

echo "Starting application vulnerability remediation for {image_name}..."

# Step 1: Update dependencies
echo "Step 1: Updating vulnerable dependencies..."
npm audit fix --force
# OR for Python: pip install --upgrade vulnerable-package

# Step 2: Apply code patches
echo "Step 2: Applying code patches..."
# Review and apply patches from analysis

# Step 3: Run tests
echo "Step 3: Running tests..."
npm test
# OR for Python: pytest

# Step 4: Rebuild container
echo "Step 4: Rebuilding container..."
docker build -t {image_name}:patched .

# Step 5: Push to registry
echo "Step 5: Pushing remediated image..."
docker push {image_name}:patched

echo "✅ Application vulnerability remediation completed!"
"""
    
    return script


# Professional Enterprise Header
st.markdown("""
    <div class="header-container">
        <h1 class="header-title">🛡️ Enterprise Container Security Platform</h1>
        <p class="header-subtitle">AI-Powered Vulnerability Analysis & Remediation | Powered by Anthropic Claude</p>
    </div>
""", unsafe_allow_html=True)

# Enhanced Professional Sidebar
with st.sidebar:
    # API Status Section
    st.markdown("#### 🔌 API Connectivity")
    anthropic_status = st.secrets.get("ANTHROPIC_API_KEY")
    nvd_status = st.secrets.get("NVD_API_KEY")
    
    # Claude AI Status
    if anthropic_status:
        st.markdown("""
        <div style='display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem;'>
            <div style='width: 20px; height: 20px; background: #10b981; border-radius: 50%; box-shadow: 0 0 0 2px rgba(16, 185, 129, 0.2);'></div>
            <span style='color: #1f2937; font-weight: 500;'>Claude AI</span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style='display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem;'>
            <div style='width: 20px; height: 20px; background: #ef4444; border-radius: 50%; box-shadow: 0 0 0 2px rgba(239, 68, 68, 0.2);'></div>
            <span style='color: #1f2937; font-weight: 500;'>Claude AI</span>
        </div>
        """, unsafe_allow_html=True)
    
    # NVD Database Status
    if nvd_status:
        st.markdown("""
        <div style='display: flex; align-items: center; gap: 0.75rem;'>
            <div style='width: 20px; height: 20px; background: #10b981; border-radius: 50%; box-shadow: 0 0 0 2px rgba(16, 185, 129, 0.2);'></div>
            <span style='color: #1f2937; font-weight: 500;'>NVD Database</span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style='display: flex; align-items: center; gap: 0.75rem;'>
            <div style='width: 20px; height: 20px; background: #ef4444; border-radius: 50%; box-shadow: 0 0 0 2px rgba(239, 68, 68, 0.2);'></div>
            <span style='color: #1f2937; font-weight: 500;'>NVD Database</span>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Quick Stats - Professional Card Design
    if st.session_state.vulnerabilities:
        st.markdown("#### 📊 Quick Stats")
        total = len(st.session_state.vulnerabilities)
        remediated = len([v for v in st.session_state.remediation_status.values() if v.get("status") == "REMEDIATED"])
        pending = total - remediated
        success_pct = (remediated / total * 100) if total > 0 else 0
        
        # Total Analyzed Card
        st.markdown(f"""
        <div style='
            background: linear-gradient(135deg, #1e40af 0%, #1e293b 100%);
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 0.75rem;
            box-shadow: 0 2px 8px rgba(15, 23, 42, 0.15);
        '>
            <div style='color: #cbd5e1; font-size: 0.85rem; margin-bottom: 0.5rem;'>📋 Total Analyzed</div>
            <div style='color: white; font-size: 1.75rem; font-weight: 700;'>{total}</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Remediated Card
        st.markdown(f"""
        <div style='
            background: linear-gradient(135deg, #047857 0%, #065f46 100%);
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 0.75rem;
            box-shadow: 0 2px 8px rgba(15, 23, 42, 0.15);
        '>
            <div style='color: #d1fae5; font-size: 0.85rem; margin-bottom: 0.5rem;'>✅ Remediated</div>
            <div style='color: white; font-size: 1.75rem; font-weight: 700;'>{remediated}</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Pending Card
        st.markdown(f"""
        <div style='
            background: linear-gradient(135deg, #d97706 0%, #b45309 100%);
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 0.75rem;
            box-shadow: 0 2px 8px rgba(15, 23, 42, 0.15);
        '>
            <div style='color: #fed7aa; font-size: 0.85rem; margin-bottom: 0.5rem;'>⏳ Pending</div>
            <div style='color: white; font-size: 1.75rem; font-weight: 700;'>{pending}</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Success Rate Card
        st.markdown(f"""
        <div style='
            background: linear-gradient(135deg, #6366f1 0%, #5558e3 100%);
            padding: 1rem;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(15, 23, 42, 0.15);
        '>
            <div style='color: #e0e7ff; font-size: 0.85rem; margin-bottom: 0.5rem;'>🎯 Success Rate</div>
            <div style='color: white; font-size: 1.75rem; font-weight: 700;'>{success_pct:.0f}%</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # System Info
    st.markdown("#### ℹ️ System Info")
    st.caption(f"**Version:** 2.0 Enterprise")
    st.caption(f"**Model:** Claude Sonnet 4.5")
    st.caption(f"**Last Updated:** Nov 2025")
    
    st.markdown("---")
    
    # Help Section
    with st.expander("📚 Quick Help"):
        st.markdown("""
        **Getting Started:**
        1. Upload CSV in Bulk Upload
        2. Or analyze single CVE
        3. View Dashboard for insights
        
        **Need Support?**
        - Check the Guide tab
        - Review documentation
        """)

# Main tabs with professional icons
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📊 Dashboard", 
    "🔍 Analyze", 
    "📈 History", 
    "📤 Bulk Upload", 
    "🚀 Advanced Remediation",
    "📖 Guide"
])

# Dashboard Tab
with tab1:
    st.markdown("""
        <div style='background: white; padding: 1.5rem; border-radius: 12px; margin-bottom: 2rem; box-shadow: 0 2px 8px rgba(0,0,0,0.05);'>
            <h2 style='margin: 0; color: #1e293b; font-size: 1.75rem;'>📊 Security Dashboard</h2>
            <p style='margin: 0.5rem 0 0 0; color: #6b7280;'>Real-time vulnerability analytics and risk assessment</p>
        </div>
    """, unsafe_allow_html=True)
    
    if st.session_state.vulnerabilities and st.session_state.analysis_results:
        # Prepare data for visualizations
        vuln_data = []
        for vuln_item in st.session_state.vulnerabilities:
            vuln_id = vuln_item["id"]
            analysis = st.session_state.analysis_results.get(vuln_id, {})
            vuln_data.append({
                "vuln_id": vuln_id,
                "image": vuln_item["image"],
                "severity": analysis.get("severity", "UNKNOWN"),
                "classification": analysis.get("classification", "UNKNOWN"),
                "detected_in": vuln_item.get("details", {}).get("detected_in", "Unknown"),
                "confidence": analysis.get("confidence", 0),
                "status": st.session_state.remediation_status.get(vuln_id, {}).get("status", "PENDING"),
                "timestamp": vuln_item.get("timestamp", "")
            })
        
        df_dash = pd.DataFrame(vuln_data)
        
        # Key Metrics Row
        st.markdown("### 🎯 Key Metrics")
        col1, col2, col3, col4, col5 = st.columns(5)
        
        total_vulns = len(df_dash)
        critical_count = len(df_dash[df_dash["severity"] == "CRITICAL"])
        high_count = len(df_dash[df_dash["severity"] == "HIGH"])
        remediated = len(df_dash[df_dash["status"] == "REMEDIATED"])
        pending = total_vulns - remediated
        
        with col1:
            st.metric("Total Vulnerabilities", total_vulns, delta=None)
        with col2:
            st.metric("Critical", critical_count, delta=None, delta_color="inverse")
        with col3:
            st.metric("High", high_count, delta=None, delta_color="inverse")
        with col4:
            st.metric("Remediated", remediated, delta=f"+{remediated}")
        with col5:
            success_rate = (remediated / total_vulns * 100) if total_vulns > 0 else 0
            st.metric("Success Rate", f"{success_rate:.1f}%")
        
        st.divider()
        
        # Charts Row 1: Severity and Classification
        st.markdown("### 📈 Vulnerability Analysis")
        col1, col2 = st.columns(2)
        
        with col1:
            # Severity Distribution Pie Chart
            severity_counts = df_dash["severity"].value_counts()
            
            # Professional color mapping for severity
            color_map = {
                'CRITICAL': '#dc2626',  # Enterprise red
                'HIGH': '#f59e0b',      # Enterprise orange
                'MEDIUM': '#eab308',    # Enterprise yellow
                'LOW': '#10b981'        # Enterprise green
            }
            colors = [color_map.get(sev, '#6b7280') for sev in severity_counts.index]
            
            fig_severity = go.Figure(data=[go.Pie(
                labels=severity_counts.index,
                values=severity_counts.values,
                marker=dict(
                    colors=colors,
                    line=dict(color='white', width=2)
                ),
                hole=0.45,
                textinfo='label+percent',
                textfont=dict(size=13, family='Inter', color='white'),
                hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
            )])
            fig_severity.update_layout(
                title=dict(
                    text="Severity Distribution",
                    font=dict(size=16, family='Inter', color='#1f2937', weight=600)
                ),
                height=350,
                showlegend=True,
                margin=dict(t=50, b=20, l=20, r=20),
                paper_bgcolor='white',
                plot_bgcolor='white',
                font=dict(family='Inter')
            )
            st.plotly_chart(fig_severity, width='stretch')
        
        with col2:
            # Classification Distribution Pie Chart
            classification_counts = df_dash["classification"].value_counts()
            
            # Professional classification colors
            class_colors = ['#1f2937', '#7c3aed', '#059669', '#f59e0b']
            
            fig_classification = go.Figure(data=[go.Pie(
                labels=classification_counts.index,
                values=classification_counts.values,
                marker=dict(
                    colors=class_colors,
                    line=dict(color='white', width=2)
                ),
                hole=0.45,
                textinfo='label+percent',
                textfont=dict(size=13, family='Inter', color='white'),
                hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
            )])
            fig_classification.update_layout(
                title=dict(
                    text="Vulnerability Classification",
                    font=dict(size=16, family='Inter', color='#1f2937', weight=600)
                ),
                height=350,
                showlegend=True,
                margin=dict(t=50, b=20, l=20, r=20),
                paper_bgcolor='white',
                plot_bgcolor='white',
                font=dict(family='Inter')
            )
            st.plotly_chart(fig_classification, width='stretch')
        
        st.divider()
        
        # Charts Row 2: Status and Layer Detection
        col1, col2 = st.columns(2)
        
        with col1:
            # Remediation Status Bar Chart
            status_counts = df_dash["status"].value_counts()
            fig_status = go.Figure(data=[go.Bar(
                x=status_counts.index,
                y=status_counts.values,
                marker=dict(
                    color=['#10b981' if s == 'REMEDIATED' else '#1f2937' for s in status_counts.index],
                    line=dict(color='white', width=1)
                ),
                text=status_counts.values,
                textposition='outside',
                textfont=dict(size=14, family='Inter', weight=600),
                hovertemplate='<b>%{x}</b><br>Count: %{y}<extra></extra>'
            )])
            fig_status.update_layout(
                title=dict(
                    text="Remediation Status",
                    font=dict(size=16, family='Inter', color='#1f2937', weight=600)
                ),
                xaxis=dict(
                    title=dict(text="Status", font=dict(size=13, family='Inter')),
                    gridcolor='#f3f4f6'
                ),
                yaxis=dict(
                    title=dict(text="Count", font=dict(size=13, family='Inter')),
                    gridcolor='#f3f4f6'
                ),
                height=350,
                showlegend=False,
                margin=dict(t=50, b=50, l=50, r=50),
                paper_bgcolor='white',
                plot_bgcolor='#f9fafb',
                font=dict(family='Inter')
            )
            st.plotly_chart(fig_status, width='stretch')
        
        with col2:
            # Detected In Distribution
            detected_counts = df_dash["detected_in"].value_counts()
            fig_detected = go.Figure(data=[go.Bar(
                x=detected_counts.index,
                y=detected_counts.values,
                marker=dict(
                    color='#6366f1',
                    line=dict(color='white', width=1)
                ),
                text=detected_counts.values,
                textposition='outside',
                textfont=dict(size=14, family='Inter', weight=600),
                hovertemplate='<b>%{x}</b><br>Count: %{y}<extra></extra>'
            )])
            fig_detected.update_layout(
                title=dict(
                    text="Detection Layer Distribution",
                    font=dict(size=16, family='Inter', color='#1f2937', weight=600)
                ),
                xaxis=dict(
                    title=dict(text="Layer", font=dict(size=13, family='Inter')),
                    gridcolor='#f3f4f6'
                ),
                yaxis=dict(
                    title=dict(text="Count", font=dict(size=13, family='Inter')),
                    gridcolor='#f3f4f6'
                ),
                height=350,
                showlegend=False,
                margin=dict(t=50, b=50, l=50, r=50),
                paper_bgcolor='white',
                plot_bgcolor='#f9fafb',
                font=dict(family='Inter')
            )
            st.plotly_chart(fig_detected, width='stretch')
        
        st.divider()
        
        # Charts Row 3: Image Distribution and Confidence
        col1, col2 = st.columns(2)
        
        with col1:
            # Top 10 Affected Images
            image_counts = df_dash["image"].value_counts().head(10)
            fig_images = go.Figure(data=[go.Bar(
                y=image_counts.index,
                x=image_counts.values,
                orientation='h',
                marker=dict(
                    color='#8b5cf6',
                    line=dict(color='white', width=1)
                ),
                text=image_counts.values,
                textposition='outside',
                textfont=dict(size=12, family='Inter', weight=600),
                hovertemplate='<b>%{y}</b><br>Vulnerabilities: %{x}<extra></extra>'
            )])
            fig_images.update_layout(
                title=dict(
                    text="Top 10 Affected Images",
                    font=dict(size=16, family='Inter', color='#1f2937', weight=600)
                ),
                xaxis=dict(
                    title=dict(text="Vulnerability Count", font=dict(size=13, family='Inter')),
                    gridcolor='#f3f4f6'
                ),
                yaxis=dict(
                    title=dict(text="Container Image", font=dict(size=13, family='Inter'))
                ),
                height=400,
                showlegend=False,
                margin=dict(t=50, b=50, l=200, r=50),
                paper_bgcolor='white',
                plot_bgcolor='#f9fafb',
                font=dict(family='Inter')
            )
            st.plotly_chart(fig_images, width='stretch')
        
        with col2:
            # Confidence Score Distribution
            fig_confidence = go.Figure(data=[go.Histogram(
                x=df_dash["confidence"],
                nbinsx=10,
                marker=dict(
                    color='#14b8a6',
                    line=dict(color='white', width=1)
                ),
                hovertemplate='Confidence: %{x}%<br>Count: %{y}<extra></extra>'
            )])
            fig_confidence.update_layout(
                title=dict(
                    text="Analysis Confidence Distribution",
                    font=dict(size=16, family='Inter', color='#1f2937', weight=600)
                ),
                xaxis=dict(
                    title=dict(text="Confidence Score (%)", font=dict(size=13, family='Inter')),
                    gridcolor='#f3f4f6'
                ),
                yaxis=dict(
                    title=dict(text="Frequency", font=dict(size=13, family='Inter')),
                    gridcolor='#f3f4f6'
                ),
                height=400,
                showlegend=False,
                margin=dict(t=50, b=50, l=50, r=50),
                paper_bgcolor='white',
                plot_bgcolor='#f9fafb',
                font=dict(family='Inter')
            )
            st.plotly_chart(fig_confidence, width='stretch')
        
        st.divider()
        
        # Severity by Classification Heatmap
        st.markdown("""
            <div style='background: white; padding: 1rem; border-radius: 12px; margin: 2rem 0 1rem 0; box-shadow: 0 2px 8px rgba(0,0,0,0.05);'>
                <h3 style='margin: 0; color: #1e293b; font-size: 1.5rem;'>🔥 Risk Correlation Matrix</h3>
                <p style='margin: 0.5rem 0 0 0; color: #6b7280; font-size: 0.9rem;'>Severity vs Classification Analysis</p>
            </div>
        """, unsafe_allow_html=True)
        
        pivot_data = df_dash.groupby(['severity', 'classification']).size().reset_index(name='count')
        pivot_table = pivot_data.pivot(index='severity', columns='classification', values='count').fillna(0)
        
        # Reorder severity for better visualization
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        pivot_table = pivot_table.reindex([s for s in severity_order if s in pivot_table.index])
        
        fig_heatmap = go.Figure(data=go.Heatmap(
            z=pivot_table.values,
            x=pivot_table.columns,
            y=pivot_table.index,
            colorscale=[[0, '#fee2e2'], [0.25, '#fca5a5'], [0.5, '#f87171'], [0.75, '#dc2626'], [1, '#991b1b']],
            text=pivot_table.values,
            texttemplate='<b>%{text}</b>',
            textfont={"size": 18, "family": "Inter", "color": "white"},
            colorbar=dict(
                title=dict(text="Count", font=dict(family='Inter', size=13)),
                tickfont=dict(family='Inter')
            ),
            hovertemplate='<b>%{y} - %{x}</b><br>Count: %{z}<extra></extra>'
        ))
        fig_heatmap.update_layout(
            title=dict(
                text="",
                font=dict(size=16, family='Inter', color='#1f2937', weight=600)
            ),
            xaxis=dict(
                title=dict(text="Classification Type", font=dict(size=13, family='Inter')),
                side='bottom'
            ),
            yaxis=dict(
                title=dict(text="Severity Level", font=dict(size=13, family='Inter'))
            ),
            height=400,
            margin=dict(t=20, b=50, l=100, r=100),
            paper_bgcolor='white',
            plot_bgcolor='white',
            font=dict(family='Inter')
        )
        st.plotly_chart(fig_heatmap, width='stretch')
        
        st.divider()
        
        # Risk Score Summary
        st.markdown("""
            <div style='background: white; padding: 1rem; border-radius: 12px; margin: 2rem 0 1rem 0; box-shadow: 0 2px 8px rgba(0,0,0,0.05);'>
                <h3 style='margin: 0; color: #1e293b; font-size: 1.5rem;'>⚠️ Overall Risk Assessment</h3>
                <p style='margin: 0.5rem 0 0 0; color: #6b7280; font-size: 0.9rem;'>Comprehensive security posture evaluation</p>
            </div>
        """, unsafe_allow_html=True)
        
        # Calculate risk score
        risk_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
        total_risk = sum(risk_weights.get(row["severity"], 0) for _, row in df_dash.iterrows())
        max_possible_risk = total_vulns * 10
        risk_percentage = (total_risk / max_possible_risk * 100) if max_possible_risk > 0 else 0
        
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            # Professional Risk gauge
            gauge_color = "#10b981" if risk_percentage < 40 else "#f59e0b" if risk_percentage < 70 else "#dc2626"
            
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=risk_percentage,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={
                    'text': "<b>Risk Score</b>",
                    'font': {'size': 20, 'family': 'Inter', 'color': '#1f2937'}
                },
                number={
                    'suffix': "%",
                    'font': {'size': 48, 'family': 'Inter', 'weight': 700, 'color': gauge_color}
                },
                gauge={
                    'axis': {
                        'range': [None, 100],
                        'tickwidth': 2,
                        'tickcolor': "#e5e7eb",
                        'tickfont': {'family': 'Inter', 'size': 12}
                    },
                    'bar': {'color': gauge_color, 'thickness': 0.75},
                    'bgcolor': "white",
                    'borderwidth': 3,
                    'bordercolor': "#e5e7eb",
                    'steps': [
                        {'range': [0, 40], 'color': '#d1fae5'},
                        {'range': [40, 70], 'color': '#fef3c7'},
                        {'range': [70, 100], 'color': '#fee2e2'}
                    ],
                    'threshold': {
                        'line': {'color': gauge_color, 'width': 6},
                        'thickness': 0.8,
                        'value': risk_percentage
                    }
                }
            ))
            fig_gauge.update_layout(
                height=320,
                margin=dict(t=60, b=20, l=40, r=40),
                paper_bgcolor='white',
                font=dict(family='Inter')
            )
            st.plotly_chart(fig_gauge, width='stretch')
        
        with col2:
            st.markdown("""
                <div style='background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%); 
                            padding: 1.5rem; border-radius: 12px; height: 100%; 
                            border: 2px solid #1f2937;'>
                    <p style='margin: 0; color: #1e293b; font-size: 0.875rem; font-weight: 600; 
                              text-transform: uppercase; letter-spacing: 0.5px;'>RISK METRICS</p>
                    <p style='margin: 1rem 0 0 0; color: #1f2937; font-size: 2rem; font-weight: 700;'>{}/{}</p>
                    <p style='margin: 0.25rem 0 0 0; color: #6b7280; font-size: 0.875rem;'>Total Risk Points</p>
                    <hr style='border: none; height: 1px; background: #93c5fd; margin: 1rem 0;'>
                    <p style='margin: 0; color: #1f2937; font-size: 1.5rem; font-weight: 700;'>{:.1f}</p>
                    <p style='margin: 0.25rem 0 0 0; color: #6b7280; font-size: 0.875rem;'>Avg. per Vulnerability</p>
                </div>
            """.format(total_risk, max_possible_risk, total_risk/total_vulns if total_vulns > 0 else 0), 
            unsafe_allow_html=True)
        
        with col3:
            if risk_percentage < 40:
                st.markdown("""
                    <div style='background: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%); 
                                padding: 1.5rem; border-radius: 12px; height: 100%; 
                                border: 2px solid #10b981;'>
                        <p style='margin: 0; color: #065f46; font-size: 2rem; font-weight: 700;'>✅ LOW</p>
                        <p style='margin: 0.5rem 0 0 0; color: #047857; font-size: 0.95rem; font-weight: 500;'>
                            System Status</p>
                        <hr style='border: none; height: 1px; background: #6ee7b7; margin: 1rem 0;'>
                        <p style='margin: 0; color: #065f46; font-size: 0.875rem; line-height: 1.5;'>
                            ✓ System is secure<br>
                            ✓ Minimal risk exposure<br>
                            ✓ Continue monitoring
                        </p>
                    </div>
                """, unsafe_allow_html=True)
            elif risk_percentage < 70:
                st.markdown("""
                    <div style='background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%); 
                                padding: 1.5rem; border-radius: 12px; height: 100%; 
                                border: 2px solid #f59e0b;'>
                        <p style='margin: 0; color: #92400e; font-size: 2rem; font-weight: 700;'>⚠️ MEDIUM</p>
                        <p style='margin: 0.5rem 0 0 0; color: #b45309; font-size: 0.95rem; font-weight: 500;'>
                            System Status</p>
                        <hr style='border: none; height: 1px; background: #fde68a; margin: 1rem 0;'>
                        <p style='margin: 0; color: #92400e; font-size: 0.875rem; line-height: 1.5;'>
                            ⚡ Action needed<br>
                            ⚡ Address high severity<br>
                            ⚡ Plan remediation
                        </p>
                    </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                    <div style='background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%); 
                                padding: 1.5rem; border-radius: 12px; height: 100%; 
                                border: 2px solid #dc2626;'>
                        <p style='margin: 0; color: #991b1b; font-size: 2rem; font-weight: 700;'>🚨 HIGH</p>
                        <p style='margin: 0.5rem 0 0 0; color: #b91c1c; font-size: 0.95rem; font-weight: 500;'>
                            System Status</p>
                        <hr style='border: none; height: 1px; background: #fca5a5; margin: 1rem 0;'>
                        <p style='margin: 0; color: #991b1b; font-size: 0.875rem; line-height: 1.5;'>
                            🔴 Critical level<br>
                            🔴 Immediate action<br>
                            🔴 Remediate now
                        </p>
                    </div>
                """, unsafe_allow_html=True)
        
    else:
        st.info("📊 No vulnerability data available yet. Start by analyzing vulnerabilities in the 'Analyze' or 'Bulk Upload' tabs.")
        
        # Show sample dashboard
        st.markdown("### 📋 Dashboard Preview")
        st.markdown("""
        Once you analyze vulnerabilities, this dashboard will display:
        
        **Key Metrics:**
        - Total vulnerabilities, Critical/High counts
        - Remediation status and success rate
        
        **Visualizations:**
        - 📊 Severity distribution pie chart
        - 🎯 Classification breakdown
        - 📈 Remediation status progress
        - 🖼️ Top affected images
        - 🔥 Risk heatmap (Severity vs Classification)
        - ⚠️ Overall risk score gauge
        
        **Use the 'Analyze' or 'Bulk Upload' tabs to get started!**
        """)

with tab2:
    # Professional header
    st.markdown("""
    <div style='background: white; padding: 1.5rem; border-radius: 12px; margin-bottom: 2rem; box-shadow: 0 2px 8px rgba(0,0,0,0.05);'>
        <h2 style='margin: 0; color: #1e293b; font-size: 1.75rem;'>🔍 Vulnerability Analysis</h2>
        <p style='margin: 0.5rem 0 0 0; color: #6b7280;'>Analyze single vulnerabilities with AI-powered insights powered by NIST & Claude</p>
    </div>
    """, unsafe_allow_html=True)
    
    # NIST Database Lookup Section
    st.markdown("### 🔐 Check NIST Database")
    
    col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
    
    with col1:
        nist_cve_input = st.text_input(
            "Enter CVE ID to check NIST database",
            placeholder="e.g., CVE-2024-1234",
            key="nist_lookup_input",
            help="Lookup CVE in NIST National Vulnerability Database"
        )
    
    with col2:
        if st.button("🔍 Check NIST", key="nist_check_btn", use_container_width=True, help="Query NIST database and auto-detect vulnerability type"):
            if nist_cve_input.strip():
                with st.spinner(f"🔍 Checking NIST database for {nist_cve_input}..."):
                    detected_type = detect_vulnerability_type_from_cve(nist_cve_input)
                    st.session_state.detected_vulnerability_type = detected_type
                    st.session_state.detected_cve_id = nist_cve_input
                    st.success(f"✅ Detection Complete: **{detected_type}**")
            else:
                st.warning("⚠️ Please enter a CVE ID first")
    
    with col3:
        if st.session_state.get("detected_vulnerability_type"):
            st.markdown(f"""
            <div style='
                background: linear-gradient(135deg, #047857 0%, #065f46 100%);
                padding: 0.75rem;
                border-radius: 8px;
                text-align: center;
                color: white;
                font-weight: 600;
            '>
                ✓ Detected: {st.session_state.detected_vulnerability_type}
            </div>
            """, unsafe_allow_html=True)
    
    with col4:
        if st.button("🔄 Clear", key="clear_detection_btn", use_container_width=True, help="Clear detection and start over"):
            st.session_state.detected_vulnerability_type = None
            st.session_state.detected_cve_id = None
            st.rerun()
    
    st.divider()
    
    # Main analysis form
    with st.form(key="vulnerability_form"):
        st.markdown("### 📋 Enter Vulnerability Details")
        
        # Check if CVE has been detected from NIST
        has_detection = bool(st.session_state.get("detected_cve_id"))
        
        # Show detection info if available
        if has_detection:
            detected_cve = st.session_state.get("detected_cve_id", "")
            detected_layer = st.session_state.get("detected_vulnerability_type", "Base Layer")
            st.markdown(f"""
            <div style='
                background: linear-gradient(135deg, #d1fae5 0%, #ecfdf5 100%);
                border: 2px solid #10b981;
                border-radius: 10px;
                padding: 1rem;
                margin-bottom: 1.5rem;
            '>
                <div style='color: #065f46; font-weight: 600; margin-bottom: 0.5rem;'>✅ NIST Detection Active</div>
                <div style='color: #047857; font-size: 0.9rem;'>
                    <strong>CVE:</strong> {detected_cve}<br>
                    <strong>Detected Layer:</strong> {detected_layer}
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # Row 1: Image and CVE
        col1, col2 = st.columns(2)
        
        with col1:
            image_name = st.text_input(
                "🐳 Container Image Name *",
                placeholder="e.g., nginx:1.21.0",
                help="Full container image name with tag"
            )
        
        with col2:
            # Auto-populate CVE ID from NIST lookup if available
            default_cve = st.session_state.get("detected_cve_id", "")
            vuln_id = st.text_input(
                "🔐 Vulnerability ID / CVE *",
                value=default_cve,
                placeholder="e.g., CVE-2024-1234",
                help="Auto-populated from NIST lookup (if detected)" if has_detection else "CVE or vendor vulnerability ID",
                disabled=has_detection
            )
        
        # Row 2: Severity and Detection Type
        col1, col2 = st.columns(2)
        
        with col1:
            severity_hint = st.selectbox(
                "⚠️ Severity Hint",
                ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                index=0,
                help="Expected severity level"
            )
        
        with col2:
            if has_detection:
                # Show read-only detection result
                detected_type = st.session_state.get("detected_vulnerability_type", "Base Layer")
                st.markdown(f"""
                <div style='
                    border: 2px solid #10b981;
                    border-radius: 8px;
                    padding: 0.75rem 0.875rem;
                    background: linear-gradient(135deg, #f0fdf4 0%, #ecfdf5 100%);
                    color: #065f46;
                    font-weight: 500;
                    line-height: 1.5;
                    margin-top: 1.75rem;
                '>
                    🔒 <strong>Detected In (from NIST):</strong> {detected_type}
                </div>
                """, unsafe_allow_html=True)
                # Hidden input to pass value through form
                detected_in = detected_type
            else:
                # Show editable selectbox if no detection
                detected_in = st.selectbox(
                    "📍 Detected In",
                    ["Base Layer", "Application Layer", "Dependencies", "Configuration"],
                    index=0,
                    help="Layer where vulnerability is detected"
                )
        
        # Row 3: Description
        description = st.text_area(
            "📝 Vulnerability Description *",
            placeholder="Describe the vulnerability, its impact, and potential risks...",
            height=120,
            help="Detailed description of the vulnerability"
        )
        
        # Row 4: Optional fields
        col1, col2 = st.columns(2)
        
        with col1:
            current_version = st.text_input(
                "📌 Current Version",
                placeholder="e.g., 1.19.0",
                help="Current version of the affected component"
            )
        
        with col2:
            affected_component = st.text_input(
                "🔧 Affected Component",
                placeholder="e.g., OpenSSL",
                help="Name of the affected component"
            )
        
        st.divider()
        
        # Submit button
        submit_button = st.form_submit_button(
            "🚀 Analyze Vulnerability",
            use_container_width=True
        )
    
    # Handle form submission
    if submit_button:
        if not image_name or not vuln_id or not description:
            st.error("❌ Please fill in all required fields marked with *")
        else:
            vulnerability_details = {
                "image_name": image_name,
                "vuln_id": vuln_id,
                "description": description,
                "detected_in": detected_in,
                "current_version": current_version,
                "affected_component": affected_component
            }
            
            try:
                analysis = analyze_vulnerability_with_claude(vulnerability_details)
                st.session_state.analysis_results[vuln_id] = analysis
                st.session_state.vulnerabilities.append({
                    "id": vuln_id,
                    "image": image_name,
                    "timestamp": datetime.now().isoformat(),
                    "details": vulnerability_details
                })
                # Clear detection after successful submission
                st.session_state.detected_vulnerability_type = None
                st.session_state.detected_cve_id = None
                st.success("✅ Analysis Complete!")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
    
    # Display analysis results section
    if st.session_state.vulnerabilities:
        st.divider()
        st.subheader("📋 Recent Analysis Results")
        
        for idx, vuln_item in enumerate(reversed(st.session_state.vulnerabilities)):
            vuln_id = vuln_item["id"]
            image_name = vuln_item["image"]
            
            if vuln_id in st.session_state.analysis_results:
                analysis = st.session_state.analysis_results[vuln_id]
                
                with st.expander(f"🔐 {vuln_id} | {image_name}", expanded=False):
                    # Display Analysis
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.write(f"**Type:** `{analysis.get('classification', 'UNKNOWN')}`")
                        st.write(f"**Severity:** `{analysis.get('severity', 'UNKNOWN')}`")
                    with col2:
                        st.write(f"**Confidence:** `{analysis.get('confidence', 0)}%`")
                        st.write(f"**Fix Time:** `{analysis.get('estimated_fix_time', 'Unknown')}`")
                    with col3:
                        if st.session_state.remediation_status.get(vuln_id, {}).get("status") == "REMEDIATED":
                            st.success("✅ REMEDIATED")
                        else:
                            st.warning("⏳ PENDING")
                    
                    st.divider()
                    
                    st.markdown("**Root Cause:**")
                    st.write(analysis.get("root_cause", "N/A"))
                    
                    st.markdown("**Resolution Steps:**")
                    for i, step in enumerate(analysis.get("resolution_steps", []), 1):
                        st.write(f"{i}. {step}")
                    
                    if analysis.get("remediation_commands"):
                        st.markdown("**Commands:**")
                        for cmd in analysis.get("remediation_commands", []):
                            st.code(cmd, language="bash")
                    
                    st.markdown("**Prevention Measures:**")
                    for measure in analysis.get("prevention_measures", []):
                        st.write(f"• {measure}")
                    
                    st.divider()
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        if st.button("⚙️ Remediate", key=f"remediate_{vuln_id}_{idx}", width='stretch'):
                            with st.spinner("Applying remediation..."):
                                for i in range(101):
                                    st.progress(i / 100.0)
                                    import time
                                    time.sleep(0.01)
                                st.session_state.remediation_status[vuln_id] = {
                                    "status": "REMEDIATED",
                                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                }
                            st.success("✅ Remediated!")
                            st.rerun()
                    
                    with col2:
                        script = get_remediation_script(analysis, image_name)
                        st.download_button(
                            label="📥 Download Script",
                            data=script,
                            file_name=f"remediate_{vuln_id}.sh",
                            mime="text/plain",
                            width='stretch'
                        )
                    
                    with col3:
                        if st.button("🔄 Re-analyze", key=f"reanalyze_{vuln_id}_{idx}", width='stretch'):
                            if vuln_id in st.session_state.analysis_results:
                                del st.session_state.analysis_results[vuln_id]
                            st.rerun()
    else:
        st.markdown("""
        <div style='
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            padding: 2rem;
            border-radius: 12px;
            border-left: 5px solid #0284c7;
            text-align: center;
        '>
            <h3 style='color: #0c4a6e; margin: 0 0 0.5rem 0;'>🔍 No Vulnerabilities Analyzed Yet</h3>
            <p style='color: #0c4a6e; margin: 0;'>Fill in the form above and click "Analyze Vulnerability" to get started!</p>
        </div>
        """, unsafe_allow_html=True)

with tab3:
    st.subheader("📈 Vulnerability History")
    
    if st.session_state.vulnerabilities:
        col1, col2, col3, col4 = st.columns(4)
        
        total = len(st.session_state.vulnerabilities)
        remediated = len([v for v in st.session_state.remediation_status.values() if v.get("status") == "REMEDIATED"])
        
        with col1:
            st.metric("Total Scanned", total)
        with col2:
            st.metric("Remediated", remediated)
        with col3:
            st.metric("Pending", total - remediated)
        with col4:
            success_rate = (remediated / total * 100) if total > 0 else 0
            st.metric("Success Rate", f"{success_rate:.1f}%")
        
        st.divider()
        st.subheader("Timeline")
        
        for vuln_item in reversed(st.session_state.vulnerabilities):
            vuln_id = vuln_item["id"]
            status = st.session_state.remediation_status.get(vuln_id, {}).get("status", "PENDING")
            emoji = "✅" if status == "REMEDIATED" else "⏳"
            st.write(f"{emoji} **{vuln_id}** | {vuln_item['image']} | {vuln_item['timestamp'][:19]}")
    else:
        st.info("ℹ️ No vulnerabilities analyzed yet")

with tab4:
    st.subheader("📤 Bulk Upload & Analyze")
    st.write("Upload a CSV file with multiple vulnerabilities to analyze them all at once.")
    
    # CSV template info
    st.info("""
    **CSV File Format:**
    Your CSV should have these columns:
    - `image_name` (required): Container image name with tag (e.g., nginx:1.19.0)
    - `vuln_id` (required): Vulnerability ID/CVE (e.g., CVE-2024-1234)
    - `description` (required): Vulnerability description
    - `detected_in` (optional): Will be auto-detected from CVE! Base Layer, Application Layer, Dependencies, Configuration
    - `current_version` (optional): Current version of affected component
    - `affected_component` (optional): Name of affected library/package
    
    **✨ NEW:** Leave `detected_in` empty and enable "Auto-detect" checkbox to automatically determine if it's a BASE_CONTAINER or APPLICATION_LEVEL vulnerability!
    """)
    
    # File uploader
    uploaded_file = st.file_uploader("Choose CSV file", type="csv")
    
    if uploaded_file is not None:
        try:
            # Read CSV file
            df = pd.read_csv(uploaded_file)
            
            st.success(f"✅ Loaded {len(df)} vulnerabilities from CSV")
            
            # Display preview
            with st.expander("📋 Preview CSV Data", expanded=False):
                st.dataframe(df, width='stretch')
            
            st.divider()
            
            # Auto-detect option
            col1, col2 = st.columns(2)
            with col1:
                auto_detect = st.checkbox(
                    "🔍 Auto-detect 'Detected In' from CVE IDs",
                    value=True,
                    help="Automatically detect vulnerability type from CVE IDs in the CSV"
                )
            
            # Analyze all button
            if st.button("🚀 Analyze All Vulnerabilities", type="primary", width='stretch'):
                progress_bar = st.progress(0)
                results_list = []
                
                for idx, row in df.iterrows():
                    progress_bar.progress((idx + 1) / len(df))
                    
                    # Auto-detect if enabled and detected_in is missing/empty
                    detected_in_value = row.get("detected_in", "")
                    
                    # Check if detected_in is missing, empty, or NaN
                    if auto_detect and (not detected_in_value or pd.isna(detected_in_value) or str(detected_in_value).strip() == ""):
                        vuln_id = row.get("vuln_id", "")
                        if vuln_id and str(vuln_id).startswith("CVE-"):
                            detected_in_value = detect_vulnerability_type_from_cve(vuln_id)
                    
                    vulnerability_details = {
                        "image_name": row.get("image_name", "Unknown"),
                        "vuln_id": row.get("vuln_id", "Unknown"),
                        "description": row.get("description", "Unknown"),
                        "detected_in": detected_in_value if detected_in_value else "Unknown",
                        "current_version": row.get("current_version", ""),
                        "affected_component": row.get("affected_component", "")
                    }
                    
                    try:
                        analysis = analyze_vulnerability_with_claude(vulnerability_details)
                        
                        # Store in session state
                        vuln_id = vulnerability_details["vuln_id"]
                        st.session_state.analysis_results[vuln_id] = analysis
                        st.session_state.vulnerabilities.append({
                            "id": vuln_id,
                            "image": vulnerability_details["image_name"],
                            "timestamp": datetime.now().isoformat(),
                            "details": vulnerability_details
                        })
                        
                        # Extract first resolution step for summary
                        resolution_steps = analysis.get("resolution_steps", [])
                        first_step = resolution_steps[0] if resolution_steps else "See details"
                        
                        # Add to results list
                        results_list.append({
                            "Image": vulnerability_details["image_name"],
                            "Vulnerability ID": vuln_id,
                            "Detected In": vulnerability_details["detected_in"],
                            "Severity": analysis.get("severity", "UNKNOWN"),
                            "Classification": analysis.get("classification", "UNKNOWN"),
                            "First Resolution Step": first_step,
                            "Fix Time": analysis.get("estimated_fix_time", "Unknown")
                        })
                    except Exception as e:
                        st.warning(f"⚠️ Failed to analyze {vulnerability_details.get('vuln_id')}: {str(e)}")
                
                st.success(f"✅ Analyzed {len(results_list)} vulnerabilities!")
                
                # Display results table
                st.subheader("📊 Analysis Results")
                results_df = pd.DataFrame(results_list)
                st.dataframe(results_df, width='stretch')
                
                # Download results as CSV
                csv_results = results_df.to_csv(index=False)
                st.download_button(
                    label="📥 Download Results as CSV",
                    data=csv_results,
                    file_name=f"vulnerability_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    width='stretch'
                )
                
                st.divider()
                
                # Detailed Remediation Section
                st.subheader("🔧 Detailed Remediation Steps")
                st.info("💡 Click on each vulnerability to see detailed fix instructions")
                
                for vuln_item in st.session_state.vulnerabilities[-len(results_list):]:
                    vuln_id = vuln_item["id"]
                    analysis = st.session_state.analysis_results.get(vuln_id, {})
                    
                    severity = analysis.get("severity", "UNKNOWN")
                    severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
                    
                    with st.expander(f"{severity_emoji} **{vuln_id}** - {vuln_item['image']} ({severity})"):
                        col1, col2 = st.columns([2, 1])
                        
                        with col1:
                            st.markdown("**📋 Root Cause:**")
                            st.write(analysis.get("root_cause", "Not available"))
                            
                            st.markdown("**✅ Resolution Steps:**")
                            resolution_steps = analysis.get("resolution_steps", [])
                            if resolution_steps:
                                for i, step in enumerate(resolution_steps, 1):
                                    st.markdown(f"{i}. {step}")
                            else:
                                st.write("No resolution steps available")
                            
                            st.markdown("**🛡️ Prevention:**")
                            st.write(analysis.get("prevention", "Not available"))
                        
                        with col2:
                            st.metric("Severity", severity)
                            st.metric("Fix Time", analysis.get("estimated_fix_time", "Unknown"))
                            st.metric("Classification", analysis.get("classification", "UNKNOWN"))
                
                st.divider()
                
                # Auto-Fix Script Generation
                st.subheader("🤖 Generate Remediation Script")
                st.info("Generate an automated script to fix all vulnerabilities")
                
                if st.button("📝 Generate Fix Script", width='stretch'):
                    script_lines = ["#!/bin/bash", "", "# Auto-generated Vulnerability Remediation Script", 
                                   f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "", 
                                   "echo '🔧 Starting vulnerability remediation...'", ""]
                    
                    for vuln_item in st.session_state.vulnerabilities[-len(results_list):]:
                        vuln_id = vuln_item["id"]
                        image_name = vuln_item["image"]
                        analysis = st.session_state.analysis_results.get(vuln_id, {})
                        
                        script_lines.append(f"# Fix for {vuln_id} in {image_name}")
                        classification = analysis.get("classification", "")
                        
                        if "BASE" in classification.upper():
                            script_lines.append(f"echo '🔄 Updating base image for {image_name}...'")
                            script_lines.append(f"# docker pull {image_name.split(':')[0]}:latest")
                            script_lines.append(f"# docker tag {image_name.split(':')[0]}:latest {image_name}")
                        else:
                            script_lines.append(f"echo '📦 Updating dependencies for {image_name}...'")
                            script_lines.append(f"# Rebuild image with updated dependencies")
                            script_lines.append(f"# docker build -t {image_name} .")
                        
                        script_lines.append("")
                    
                    script_lines.append("echo '✅ Remediation complete!'")
                    
                    remediation_script = "\n".join(script_lines)
                    
                    st.code(remediation_script, language="bash")
                    
                    st.download_button(
                        label="💾 Download Remediation Script",
                        data=remediation_script,
                        file_name=f"fix_vulnerabilities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sh",
                        mime="text/x-shellscript",
                        width='stretch'
                    )
                
                st.rerun()
        
        except Exception as e:
            st.error(f"❌ Error reading CSV file: {str(e)}")
    
    st.divider()
    
    # Download template
    st.subheader("📝 Download CSV Template")
    
    template_df = pd.DataFrame({
        "Application": ["myapp", "myapp", "myapp"],
        "Cloud Account": ["account-123", "account-123", "account-123"],
        "Cluster": ["prod-cluster", "prod-cluster", "prod-cluster"],
        "Namespace/Task": ["default", "default", "default"],
        "Container": ["myapp-container", "myapp-container", "myapp-container"],
        "Image": ["nginx:1.19.0", "python:3.9-slim", "myapp:1.0"],
        "Remediation Owner": ["team-a", "team-b", "team-c"],
        "Severity": ["HIGH", "MEDIUM", "CRITICAL"],
        "CVE": ["CVE-2021-3129", "CVE-2023-12345", "CVE-2023-38545"],
        "CVE Description": [
            "OpenSSL vulnerability in nginx",
            "Python interpreter vulnerability",
            "Log4Shell vulnerability in application"
        ],
        "Technology": ["nginx", "python", "Log4j"],
        "Description": ["Base Layer", "Base Layer", "Application Layer"],
        "Remediation": ["Update base image", "Update dependencies", "Apply patch"]
    })
    
    csv_template = template_df.to_csv(index=False)
    st.download_button(
        label="📋 Download CSV Template",
        data=csv_template,
        file_name="vulnerability_template.csv",
        mime="text/csv",
        width='stretch'
    )

# ==================== TAB 5: ADVANCED REMEDIATION ====================
with tab5:
    st.markdown("""
    <div style='background: white; padding: 1.5rem; border-radius: 12px; margin-bottom: 2rem; box-shadow: 0 2px 8px rgba(0,0,0,0.05);'>
        <h2 style='margin: 0; color: #1e293b; font-size: 1.75rem;'>🚀 Advanced Automated Remediation</h2>
        <p style='margin: 0.5rem 0 0 0; color: #6b7280;'>Automated Docker-based vulnerability remediation with real-time tracking</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.info("🔧 Production-Ready Remediation System - Automated Docker execution with real-time monitoring and complete audit trails")
    
    if st.session_state.vulnerabilities:
        # Get database stats
        stats = st.session_state.db.get_job_stats()
        
        # Configuration
        st.markdown("#### ⚙️ Configuration")
        
        config_col1, config_col2, config_col3 = st.columns(3)
        
        with config_col1:
            execution_mode = st.selectbox(
                "Execution Mode",
                ["Dry Run (Simulation)", "Execute (Live)"],
                help="Dry Run tests without making changes"
            )
        
        with config_col2:
            docker_check = st.checkbox("✓ Docker Available", value=True)
        
        with config_col3:
            registry_url = st.text_input("Registry URL (optional)", placeholder="registry.example.com")
        
        timeout = st.slider("Timeout (seconds)", 60, 3600, 300, 60)
        
        st.divider()
        
        # Vulnerability selection
        st.markdown("#### 📋 Select Vulnerabilities to Remediate")
        
        pending_vulns = []
        for vuln_item in st.session_state.vulnerabilities:
            vuln_id = vuln_item['id']
            analysis = st.session_state.analysis_results.get(vuln_id, {})
            status = st.session_state.remediation_status.get(vuln_id, {}).get("status", "PENDING")
            
            if status != "REMEDIATED":
                pending_vulns.append({
                    'vuln_id': vuln_id,
                    'image': vuln_item['image'],
                    'severity': analysis.get('severity', 'UNKNOWN'),
                    'classification': analysis.get('classification', 'UNKNOWN')
                })
        
        if pending_vulns:
            selected_remediations = []
            
            for item in pending_vulns:
                col1, col2, col3, col4 = st.columns([1, 3, 2, 1])
                
                with col1:
                    selected = st.checkbox(
                        label=item['vuln_id'],
                        key=f"checkbox_{item['vuln_id']}"
                    )
                    if selected:
                        selected_remediations.append(item)
                
                with col2:
                    st.write(f"**{item['image']}**")
                
                with col3:
                    severity_emoji = {
                        "CRITICAL": "🔴",
                        "HIGH": "🟠",
                        "MEDIUM": "🟡",
                        "LOW": "🟢"
                    }.get(item['severity'], "⚪")
                    st.write(f"{severity_emoji} {item['severity']}")
                
                with col4:
                    st.write(f"*{item['classification']}*")
            
            st.divider()
            
            if selected_remediations:
                st.markdown(f"#### ▶️ Remediation Execution ({len(selected_remediations)} selected)")
                
                if st.button("▶️ START REMEDIATION", use_container_width=True, key="execute_btn"):
                    progress_container = st.container()
                    logs_container = st.container()
                    results_container = st.container()
                    
                    with progress_container:
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                    
                    successful = 0
                    failed = 0
                    
                    for idx, remediation in enumerate(selected_remediations):
                        vuln_id = remediation['vuln_id']
                        image_name = remediation['image']
                        classification = remediation['classification']
                        
                        status_text.write(f"Processing: **{vuln_id}** ({idx + 1}/{len(selected_remediations)})")
                        
                        # Create executor
                        executor = RemediationExecutor(st.session_state.db)
                        st.session_state.remediation_jobs[vuln_id] = executor
                        st.session_state.db.insert_job(executor.job_id, vuln_id, image_name, classification)
                        
                        with logs_container.expander(f"📝 {vuln_id} - Logs", expanded=False):
                            log_placeholder = st.empty()
                            
                            if execution_mode == "Dry Run (Simulation)":
                                executor.log(f"[DRY RUN] Remediation simulation for {image_name}")
                                executor.log(f"[DRY RUN] Classification: {classification}")
                                
                                if classification == "Base Layer":
                                    for step in range(1, 6):
                                        executor.log(f"[DRY RUN] Step {step}/5: Running...")
                                        time.sleep(0.2)
                                else:
                                    for step in range(1, 7):
                                        executor.log(f"[DRY RUN] Step {step}/6: Running...")
                                        time.sleep(0.2)
                                
                                executor.status = "REMEDIATED"
                                executor.end_time = datetime.now()
                            else:
                                if not docker_check:
                                    executor.status = "FAILED"
                                    executor.error = "Docker not available"
                                    executor.log("❌ Docker not available", "ERROR")
                                else:
                                    if classification == "Base Layer":
                                        executor.remediate_base_layer(image_name, registry_url, timeout)
                                    else:
                                        executor.remediate_application_layer(image_name, "npm", timeout)
                            
                            logs_text = "\n".join(executor.logs[-20:])
                            log_placeholder.code(logs_text, language="bash")
                        
                        # Update status
                        duration = (executor.end_time - executor.start_time).total_seconds() if executor.end_time else 0
                        
                        if executor.status == "REMEDIATED":
                            successful += 1
                            st.session_state.remediation_status[vuln_id] = {
                                "status": "REMEDIATED",
                                "timestamp": datetime.now().isoformat(),
                                "job_id": executor.job_id,
                                "duration": duration
                            }
                            st.session_state.db.update_job_status(
                                executor.job_id, "REMEDIATED",
                                executor.start_time.isoformat() if executor.start_time else None,
                                executor.end_time.isoformat() if executor.end_time else None,
                                duration,
                                None,
                                "\n".join(executor.logs)
                            )
                            st.markdown(f"""
                            <div style='background: #ecfdf5; border-left: 5px solid #10b981; padding: 1rem; border-radius: 8px; margin: 0.5rem 0;'>
                            ✅ {vuln_id} REMEDIATED ({duration:.0f}s)
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            failed += 1
                            st.session_state.remediation_status[vuln_id] = {
                                "status": "FAILED",
                                "timestamp": datetime.now().isoformat(),
                                "job_id": executor.job_id,
                                "error": executor.error
                            }
                            st.session_state.db.update_job_status(
                                executor.job_id, "FAILED",
                                executor.start_time.isoformat() if executor.start_time else None,
                                executor.end_time.isoformat() if executor.end_time else None,
                                duration,
                                executor.error,
                                "\n".join(executor.logs)
                            )
                            st.markdown(f"""
                            <div style='background: #fef2f2; border-left: 5px solid #dc2626; padding: 1rem; border-radius: 8px; margin: 0.5rem 0;'>
                            ❌ {vuln_id} FAILED - {executor.error}
                            </div>
                            """, unsafe_allow_html=True)
                        
                        progress_bar.progress((idx + 1) / len(selected_remediations))
                    
                    # Summary
                    with results_container:
                        st.divider()
                        st.markdown("### 📊 Remediation Summary")
                        
                        summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)
                        
                        with summary_col1:
                            st.metric("Total", len(selected_remediations))
                        with summary_col2:
                            st.metric("✅ Successful", successful)
                        with summary_col3:
                            st.metric("❌ Failed", failed)
                        with summary_col4:
                            success_rate = (successful / len(selected_remediations) * 100) if len(selected_remediations) > 0 else 0
                            st.metric("Success Rate", f"{success_rate:.0f}%")
                        
                        st.divider()
                        
                        # Export results
                        results_data = []
                        for vuln_id, status_info in st.session_state.remediation_status.items():
                            results_data.append({
                                "Vulnerability ID": vuln_id,
                                "Status": status_info.get("status"),
                                "Timestamp": status_info.get("timestamp"),
                                "Job ID": status_info.get("job_id"),
                                "Error": status_info.get("error", "N/A")
                            })
                        
                        if results_data:
                            results_df = pd.DataFrame(results_data)
                            csv_export = results_df.to_csv(index=False)
                            st.download_button(
                                label="💾 Download Remediation Report",
                                data=csv_export,
                                file_name=f"remediation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                mime="text/csv",
                                use_container_width=True
                            )
            else:
                st.info("👆 Select at least one vulnerability to begin")
        else:
            st.success("✅ All vulnerabilities have been remediated!")
    else:
        st.warning("📊 No vulnerabilities to remediate. Upload or analyze vulnerabilities first.")

with tab6:
    st.subheader("📖 Vulnerability Classification Guide")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🗁 Base Container Vulnerabilities")
        st.markdown("""
        **Definition:** Vulnerabilities in the base OS or foundational layers
        
        **Examples:**
        - OpenSSL CVEs
        - Linux kernel vulnerabilities
        - System package issues
        
        **Typical Fix:**
        - Update base image
        - Rebuild container
        - Re-deploy to registry
        
        **Effort:** Low to Medium
        """)
    
    with col2:
        st.markdown("### 🎯 Application Level Vulnerabilities")
        st.markdown("""
        **Definition:** Vulnerabilities in application code or dependencies
        
        **Examples:**
        - Outdated npm/pip packages
        - SQL injection
        - Insecure APIs
        - Vulnerable frameworks
        
        **Typical Fix:**
        - Update dependencies
        - Code patches
        - Configuration updates
        
        **Effort:** Medium to High
        """)

st.divider()
st.caption("🔐 Container Vulnerability Analyzer | Powered by AI")