import smtplib
from email.mime.text import MIMEText

def send_email(sender_email, sender_password, receiver_email, report_df):
    body = report_df.to_string(index=False)

    msg = MIMEText(body)
    msg["Subject"] = "Vulnerability Scan Report"
    msg["From"] = sender_email
    msg["To"] = receiver_email

    server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
    server.login(sender_email, sender_password)
    server.send_message(msg)
    server.quit()
