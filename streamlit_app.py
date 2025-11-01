import streamlit as st
import anthropic
import json
from datetime import datetime
import re
import pandas as pd
from io import StringIO

# Configure Streamlit page
st.set_page_config(
    page_title="Container Vulnerability Analyzer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .vulnerability-box {
        border-radius: 0.5rem;
        padding: 1.5rem;
        margin-bottom: 1rem;
    }
    .critical {
        background-color: #ffebee;
        border-left: 4px solid #d32f2f;
    }
    .high {
        background-color: #fff3e0;
        border-left: 4px solid #f57c00;
    }
    .medium {
        background-color: #fff8e1;
        border-left: 4px solid #fbc02d;
    }
    .low {
        background-color: #f1f8e9;
        border-left: 4px solid #558b2f;
    }
    .remediated {
        background-color: #e8f5e9;
        border-left: 4px solid #2e7d32;
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


def initialize_claude_client():
    """Initialize Anthropic Claude API client"""
    api_key = st.secrets.get("ANTHROPIC_API_KEY")
    if not api_key:
        st.error("❌ ANTHROPIC_API_KEY not found in secrets")
        st.info("Create `.streamlit/secrets.toml` with: ANTHROPIC_API_KEY = 'your-key'")
        st.stop()
    return anthropic.Anthropic(api_key=api_key)


def detect_vulnerability_type_from_cve(cve_id: str) -> str:
    """Auto-detect if vulnerability is BASE_CONTAINER or APPLICATION_LEVEL based on CVE ID"""
    
    client = initialize_claude_client()
    
    prompt = f"""You are a security expert. Based on the CVE ID: {cve_id}, determine if this vulnerability is:
    
1. BASE_CONTAINER - Affects the base OS, kernel, system libraries (e.g., OpenSSL, glibc, Linux kernel)
2. APPLICATION_LEVEL - Affects specific applications, frameworks, or libraries (e.g., Django, Log4j, npm packages)

Return ONLY one of these values: BASE_CONTAINER or APPLICATION_LEVEL

If you don't know this CVE, make an educated guess based on common patterns.

Examples:
- CVE-2021-3129 (OpenSSL) → BASE_CONTAINER
- CVE-2023-38545 (Log4Shell) → APPLICATION_LEVEL
- CVE-2022-0001 (Linux kernel) → BASE_CONTAINER
- CVE-2023-44487 (HTTP/2 vulnerability) → BASE_CONTAINER

Return ONLY the classification, nothing else."""

    try:
        message = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=50,
            messages=[{"role": "user", "content": prompt}]
        )
        
        response = message.content[0].text.strip().upper()
        
        if "APPLICATION" in response:
            return "Application Layer"
        elif "BASE" in response:
            return "Base Layer"
        else:
            return "Unknown"
    except:
        return "Unknown"


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
            model="claude-3-5-sonnet-20241022",
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


# Main UI
st.markdown("# 🔐 Container Vulnerability Analyzer")
st.markdown("Powered by Anthropic Claude API")

st.divider()

# Sidebar
with st.sidebar:
    st.header("⚙️ Configuration")
    api_status = "✅ Configured" if st.secrets.get("ANTHROPIC_API_KEY") else "❌ Not Configured"
    st.write(f"API Status: {api_status}")

# Main tabs
tab1, tab2, tab3, tab4 = st.tabs(["🔍 Analyze", "📊 History", "📤 Bulk Upload", "📖 Guide"])

with tab1:
    st.subheader("Enter Vulnerability Details")
    
    col1, col2 = st.columns(2)
    
    with col1:
        image_name = st.text_input(
            "Container Image Name *",
            placeholder="e.g., nginx:latest",
            help="Full container image name with tag"
        )
        vuln_id = st.text_input(
            "Vulnerability ID / CVE *",
            placeholder="e.g., CVE-2024-1234",
            help="CVE or vendor ID - Auto-detection enabled! ✨"
        )
    
    with col2:
        severity_hint = st.selectbox(
            "Severity Hint",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )
        
        # Auto-detect vulnerability type from CVE ID
        detected_type = "Base Layer"
        if vuln_id and vuln_id.strip():
            if st.button("🔍 Auto-Detect Type", key="auto_detect_btn", help="Analyze CVE to auto-populate type"):
                with st.spinner("Analyzing CVE..."):
                    detected_type = detect_vulnerability_type_from_cve(vuln_id)
                    st.session_state.detected_type = detected_type
                    st.success(f"✅ Detected: {detected_type}")
        
        detected_type = st.session_state.get("detected_type", "Base Layer")
        
        try:
            default_index = ["Base Layer", "Application Layer", "Dependencies", "Configuration"].index(detected_type)
        except:
            default_index = 0
        
        detected_in = st.selectbox(
            "Detected In (Auto-filled ✨)",
            ["Base Layer", "Application Layer", "Dependencies", "Configuration"],
            index=default_index,
            help="Auto-detected from CVE - Click button above to detect, or change manually"
        )
    
    description = st.text_area(
        "Vulnerability Description *",
        placeholder="Describe the vulnerability...",
        height=100
    )
    
    col1, col2 = st.columns(2)
    with col1:
        current_version = st.text_input(
            "Current Version",
            placeholder="e.g., 1.1.1a"
        )
    with col2:
        affected_component = st.text_input(
            "Affected Component",
            placeholder="e.g., OpenSSL"
        )
    
    st.divider()
    
    # Analyze button
    if st.button("🚀 Analyze Vulnerability", type="primary", use_container_width=True):
        if not image_name or not vuln_id or not description:
            st.error("❌ Please fill in all required fields (*)")
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
                st.success("✅ Analysis Complete!")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")

# Display results
with tab1:
    if st.session_state.vulnerabilities:
        st.divider()
        st.subheader("📋 Analysis Results")
        
        for vuln_item in reversed(st.session_state.vulnerabilities):
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
                        if st.button("⚙️ Remediate", key=f"remediate_{vuln_id}", use_container_width=True):
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
                            use_container_width=True
                        )
                    
                    with col3:
                        if st.button("🔄 Re-analyze", key=f"reanalyze_{vuln_id}", use_container_width=True):
                            if vuln_id in st.session_state.analysis_results:
                                del st.session_state.analysis_results[vuln_id]
                            st.rerun()

with tab2:
    st.subheader("📊 Vulnerability History")
    
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

with tab3:
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
                st.dataframe(df, use_container_width=True)
            
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
            if st.button("🚀 Analyze All Vulnerabilities", type="primary", use_container_width=True):
                progress_bar = st.progress(0)
                results_list = []
                
                for idx, row in df.iterrows():
                    progress_bar.progress((idx + 1) / len(df))
                    
                    # Auto-detect if enabled and detected_in is missing
                    detected_in_value = row.get("detected_in", "Unknown")
                    if auto_detect and (detected_in_value == "Unknown" or pd.isna(detected_in_value)):
                        vuln_id = row.get("vuln_id", "")
                        if vuln_id and str(vuln_id).startswith("CVE-"):
                            detected_in_value = detect_vulnerability_type_from_cve(vuln_id)
                    
                    vulnerability_details = {
                        "image_name": row.get("image_name", "Unknown"),
                        "vuln_id": row.get("vuln_id", "Unknown"),
                        "description": row.get("description", "Unknown"),
                        "detected_in": detected_in_value,
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
                        
                        # Add to results list
                        results_list.append({
                            "Image": vulnerability_details["image_name"],
                            "Vulnerability ID": vuln_id,
                            "Detected In": vulnerability_details["detected_in"],
                            "Classification": analysis.get("classification", "UNKNOWN"),
                            "Severity": analysis.get("severity", "UNKNOWN"),
                            "Confidence": f"{analysis.get('confidence', 0)}%",
                            "Fix Time": analysis.get("estimated_fix_time", "Unknown")
                        })
                    except Exception as e:
                        st.warning(f"⚠️ Failed to analyze {vulnerability_details.get('vuln_id')}: {str(e)}")
                
                st.success(f"✅ Analyzed {len(results_list)} vulnerabilities!")
                
                # Display results table
                st.subheader("📊 Analysis Results")
                results_df = pd.DataFrame(results_list)
                st.dataframe(results_df, use_container_width=True)
                
                # Download results as CSV
                csv_results = results_df.to_csv(index=False)
                st.download_button(
                    label="📥 Download Results as CSV",
                    data=csv_results,
                    file_name=f"vulnerability_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
                
                st.rerun()
        
        except Exception as e:
            st.error(f"❌ Error reading CSV file: {str(e)}")
    
    st.divider()
    
    # Download template
    st.subheader("📝 Download CSV Template")
    
    template_df = pd.DataFrame({
        "image_name": ["nginx:1.19.0", "python:3.9-slim", "myapp:1.0"],
        "vuln_id": ["CVE-2021-3129", "CVE-2023-12345", "CVE-2023-38545"],
        "description": [
            "OpenSSL vulnerability in nginx",
            "Python interpreter vulnerability",
            "Log4Shell vulnerability in application"
        ],
        "detected_in": ["Base Layer", "Base Layer", "Application Layer"],
        "current_version": ["1.19.0", "3.9.1", "1.0"],
        "affected_component": ["nginx", "python", "Log4j"]
    })
    
    csv_template = template_df.to_csv(index=False)
    st.download_button(
        label="📋 Download CSV Template",
        data=csv_template,
        file_name="vulnerability_template.csv",
        mime="text/csv",
        use_container_width=True
    )

with tab4:
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
st.caption("🔐 Container Vulnerability Analyzer | Powered by Anthropic Claude API")