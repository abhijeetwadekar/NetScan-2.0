import streamlit as st
import pandas as pd
from scanner import scan_network
from report import generate_report
from emailer import send_email
import time

# Page configuration
st.set_page_config(
    page_title="NetScan 2.0 - Vulnerability Scanner",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={"About": "NetScan 2.0 - Network Vulnerability Scanner"}
)

# Custom CSS for better UI
st.markdown("""
<style>
    * {
        font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
    }
    
    .header-container {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 30px;
        border-radius: 10px;
        color: white;
        margin-bottom: 20px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    
    .header-container h1 {
        margin: 0;
        font-size: 2.5em;
        font-weight: 600;
        font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
    }
    
    .header-container p {
        margin: 5px 0 0 0;
        font-size: 1.1em;
        font-weight: 300;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
    }
    
    .logs-box {
        background-color: #1e1e1e;
        color: #e0e0e0;
        padding: 15px;
        border-radius: 6px;
        font-family: 'Courier New', monospace;
        font-size: 13px;
        max-height: 250px;
        overflow-y: auto;
        border: 1px solid #333;
        line-height: 1.5;
    }
    
    .info-box {
        background-color: #e8f4f8;
        border-left: 4px solid #2196F3;
        padding: 12px;
        border-radius: 4px;
        margin: 10px 0;
    }
    
    .warning-box {
        background-color: #fff3cd;
        border-left: 4px solid #ffc107;
        padding: 12px;
        border-radius: 4px;
        margin: 10px 0;
    }
    
    .success-box {
        background-color: #d4edda;
        border-left: 4px solid #28a745;
        padding: 12px;
        border-radius: 4px;
        margin: 10px 0;
    }
    
    .error-box {
        background-color: #f8d7da;
        border-left: 4px solid #dc3545;
        padding: 12px;
        border-radius: 4px;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if "scan_results" not in st.session_state:
    st.session_state.scan_results = None
if "scan_completed" not in st.session_state:
    st.session_state.scan_completed = False
if "scan_logs" not in st.session_state:
    st.session_state.scan_logs = []

# Header
st.markdown("""
<div class="header-container">
    <h1>NetScan 2.0</h1>
    <p>Network Vulnerability Scanner & CVE Mapper</p>
</div>
""", unsafe_allow_html=True)

# Sidebar for configuration
with st.sidebar:
    st.image("https://via.placeholder.com/200x100?text=NetScan", use_container_width=True)
    st.markdown("---")
    
    st.subheader("Configuration")
    
    # Scan Configuration Section
    with st.expander("Scan Settings", expanded=True):
        target = st.text_input(
            "Target Network",
            value="192.168.1.0/24",
            placeholder="e.g., 192.168.1.0/24",
            help="Enter IP range in CIDR notation"
        )
        
        scan_depth = st.selectbox(
            "Scan Depth",
            ["Quick", "Standard", "Deep"],
            help="Quick: Common ports | Standard: Extended | Deep: Comprehensive"
        )
    
    # Email Configuration Section
    with st.expander("Email Settings", expanded=True):
        sender_email = st.text_input(
            "Sender Gmail",
            placeholder="your-email@gmail.com",
            help="Your Gmail address for sending reports"
        )
        sender_password = st.text_input(
            "Gmail App Password",
            type="password",
            placeholder="••••••••••••••••",
            help="Use 16-character Gmail App Password (not regular password)"
        )
        receiver_email = st.text_input(
            "Receiver Email",
            placeholder="recipient@example.com",
            help="Email address to receive the vulnerability report"
        )
        
        st.markdown("---")
        
        # Email sending button inside settings
        email_ready = sender_email and sender_password and receiver_email
        send_email_btn = st.button(
            "Send Report via Email",
            use_container_width=True,
            disabled=not (email_ready and st.session_state.scan_completed),
            help="Configure email settings and complete a scan first" if not email_ready else "Send the latest scan report"
        )
        
        if send_email_btn and st.session_state.scan_results:
            try:
                report = generate_report(st.session_state.scan_results)
                send_email(sender_email, sender_password, receiver_email, report)
                st.success(f"Report sent successfully to {receiver_email}")
            except Exception as e:
                st.error(f"Email failed: {str(e)}")
    
    st.markdown("---")
    st.info("Tip: Use App Password from Google Account Security settings")

# Main content area
tab1, tab2, tab3 = st.tabs(["Scanner", "Results", "Report"])

with tab1:
    st.subheader("Network Vulnerability Scanner")
    
    # Input validation and scan execution
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        st.markdown("### Target Network Configuration")
        
        # Network input validation
        if target:
            st.markdown(f"**Target:** `{target}`")
        else:
            st.warning("Please enter a target network in the sidebar")
    
    with col2:
        st.markdown("### Scan Depth")
        st.info(f"**{scan_depth}** scan selected")
    
    with col3:
        st.markdown("### Status")
        if st.session_state.scan_completed:
            st.success("Scan completed")
        else:
            st.info("Ready to scan")
    
    st.markdown("---")
    
    # Start Scan Button
    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        start_scan = st.button("Start Scan", use_container_width=True, type="primary")
    with col2:
        clear_results = st.button("Clear", use_container_width=True)
    
    if clear_results:
        st.session_state.scan_results = None
        st.session_state.scan_completed = False
        st.session_state.scan_logs = []
        st.rerun()
    
    if start_scan:
        # Validation - Email NOT required for scanning
        if not target:
            st.error("Please enter a target network")
        else:
            st.markdown("---")
            st.subheader("Scanning in Progress...")
            
            # Progress tracking
            progress_bar = st.progress(0)
            status_text = st.empty()
            progress_details = st.empty()
            logs_box = st.empty()
            
            # Clear logs at start
            st.session_state.scan_logs = []
            
            results = []
            try:
                for percent, data in scan_network(target):
                    results = data
                    progress_bar.progress(min(percent, 100))
                    
                    hosts_found = len(set([r["host"] for r in data]))
                    ports_found = len(data)
                    
                    # Update status
                    status_text.write(f"**Progress:** {percent}%")
                    progress_details.metric("Found", f"{hosts_found} hosts | {ports_found} ports")
                    
                    # Add log entry
                    log_entry = f"[{percent}%] Discovered {hosts_found} hosts with {ports_found} open ports"
                    st.session_state.scan_logs.append(log_entry)
                    
                    # Display live logs
                    logs_content = "\n".join(st.session_state.scan_logs[-20:])  # Show last 20 logs
                    logs_box.markdown(f'<div class="logs-box">{logs_content}</div>', unsafe_allow_html=True)
                
                # Final status
                st.session_state.scan_results = results
                st.session_state.scan_completed = True
                
                progress_bar.progress(100)
                status_text.success("Scan Completed Successfully!")
                
                # Add final log
                st.session_state.scan_logs.append("[100%] Scan finished")
                logs_content = "\n".join(st.session_state.scan_logs[-20:])
                logs_box.markdown(f'<div class="logs-box">{logs_content}</div>', unsafe_allow_html=True)
                
                # Display summary metrics
                st.markdown("---")
                st.subheader("Scan Summary")
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    hosts_count = len(set([r["host"] for r in results]))
                    st.metric("Hosts Found", hosts_count)
                with col2:
                    ports_count = len(results)
                    st.metric("Open Ports", ports_count)
                with col3:
                    services = len(set([r["service"] for r in results if r["service"]]))
                    st.metric("Services", services)
                with col4:
                    st.metric("Duration", "~30s")
                
                st.markdown("---")
                st.info("Email sending is optional. Configure email in the sidebar and click 'Send Report via Email' to send this report.")
                
            except Exception as e:
                st.error(f"Scan Error: {str(e)}")
                st.info("Check your network range and try again")
                st.session_state.scan_logs.append(f"Error: {str(e)}")
                logs_content = "\n".join(st.session_state.scan_logs[-20:])
                logs_box.markdown(f'<div class="logs-box">{logs_content}</div>', unsafe_allow_html=True)

with tab2:
    st.subheader("Scan Results")
    
    if st.session_state.scan_results is None:
        st.info("Run a scan from the 'Scanner' tab to view results")
    else:
        results = st.session_state.scan_results
        
        # Results filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            filter_host = st.text_input("Filter by Host IP", placeholder="192.168.1.x")
        with col2:
            filter_service = st.text_input("Filter by Service", placeholder="http, ssh, etc")
        with col3:
            show_all = st.toggle("Show All Entries", value=True)
        
        # Apply filters
        filtered_results = results.copy()
        if filter_host:
            filtered_results = [r for r in filtered_results if filter_host in r["host"]]
        if filter_service:
            filtered_results = [r for r in filtered_results if filter_service.lower() in r["service"].lower()]
        
        # Display results table
        if filtered_results:
            df = pd.DataFrame(filtered_results)
            
            # Statistics
            st.markdown("### Statistics")
            stat_col1, stat_col2, stat_col3 = st.columns(3)
            with stat_col1:
                st.metric("Entries", len(filtered_results))
            with stat_col2:
                st.metric("Unique Hosts", len(set([r["host"] for r in filtered_results])))
            with stat_col3:
                st.metric("Unique Services", len(set([r["service"] for r in filtered_results if r["service"]])))
            
            st.markdown("---")
            
            # Results table
            st.markdown("### Detailed Results")
            st.dataframe(
                df,
                use_container_width=True,
                height=400,
                column_config={
                    "host": st.column_config.TextColumn("Host", width="medium"),
                    "port": st.column_config.NumberColumn("Port", width="small"),
                    "service": st.column_config.TextColumn("Service", width="medium"),
                    "version": st.column_config.TextColumn("Version", width="large"),
                }
            )
            
            # Download option
            st.markdown("---")
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download as CSV",
                data=csv,
                file_name="netscan_results.csv",
                mime="text/csv",
                use_container_width=True
            )
        else:
            st.warning("No results match your filters")

with tab3:
    st.subheader("Generated Report")
    
    if st.session_state.scan_results is None:
        st.info("Run a scan from the 'Scanner' tab to generate a report")
    else:
        try:
            report = generate_report(st.session_state.scan_results)
            
            st.markdown("### Vulnerability Report")
            st.dataframe(report, use_container_width=True, height=400)
            
            st.markdown("---")
            
            # Report download
            report_csv = report.to_csv(index=False)
            st.download_button(
                label="Download Report as CSV",
                data=report_csv,
                file_name="vulnerability_report.csv",
                mime="text/csv",
                use_container_width=True
            )
            
        except Exception as e:
            st.error(f"Error generating report: {str(e)}")

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; padding: 20px;">
    <p><strong>NetScan 2.0</strong> | Network Vulnerability Scanner</p>
    <p>Security | Performance | Insights</p>
</div>
""", unsafe_allow_html=True)
