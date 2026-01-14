import streamlit as st
from scanner import scan_network
from report import generate_report
from emailer import send_email

st.set_page_config(page_title="Startup Vulnerability Scanner", layout="wide")
st.title("Startup-Friendly Vulnerability Scanner")

st.subheader("Email Configuration (Gmail App Password Required)")

sender_email = st.text_input("Sender Gmail")
sender_password = st.text_input(
    "Gmail App Password",
    type="password",
    help="Use Gmail App Password, not your normal password"
)

receiver_email = st.text_input("Send Report To (Receiver Email)")
target = st.text_input("Target Network (e.g. 192.168.1.0/24)")

if st.button("Start Scan"):
    if not sender_email or not sender_password or not receiver_email:
        st.error("Please enter sender email, app password, and receiver email")
    else:
        progress = st.progress(0)
        status = st.empty()
        results = []

        for percent, data in scan_network(target):
            results = data
            progress.progress(percent)
            status.text(f"Scanning... {percent}% completed")

        status.text("Scan completed ✅")

        report = generate_report(results)
        st.dataframe(report)

        try:
            send_email(sender_email, sender_password, receiver_email, report)
            st.success("Report emailed successfully 📧")
        except Exception as e:
            st.error(f"Email failed: {e}")
