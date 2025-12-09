import smtplib
from email.message import EmailMessage

SMTP_HOST = "192.168.234.10"
SMTP_PORT = 1025

msg = EmailMessage()
msg["From"] = "lab-sender@example.local"
msg["To"] = "lab-receiver@example.local"
msg["Subject"] = "LAB: SMTP test"
msg["X-Lab-Tag"] = "EmailTest"
msg.set_content("Ovo je test poruka (dummy sadržaj) za projektni lab.")

msg.add_attachment(b"dummy attachment\n", maintype="text", subtype="plain", filename="dummy.txt")

with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
    s.send_message(msg)

print("Poslano.")
