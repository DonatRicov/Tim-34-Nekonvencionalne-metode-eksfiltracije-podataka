import argparse
import smtplib
from email.message import EmailMessage
from datetime import datetime
import random
import time

def build_header_value(mode: str, base_text: str, i: int) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    if mode == "counter":
        return f"{base_text}-{i:03d}"
    if mode == "timestamp":
        return f"{base_text}-{ts}"
    if mode == "random":
        suffix = random.randint(100000, 999999)
        return f"{base_text}-{suffix}"
    if mode == "list":
        # base_text se tretira kao CSV lista: "A,B,C"
        items = [x.strip() for x in base_text.split(",") if x.strip()]
        pick = random.choice(items) if items else f"Item-{i:03d}"
        return f"{pick}-{ts}"
    return f"{base_text}-{i:03d}"

def main():
    ap = argparse.ArgumentParser(description="Send test emails to a local SMTP server (lab).")
    ap.add_argument("--smtp-host", default="192.168.234.10")
    ap.add_argument("--smtp-port", type=int, default=1025)
    ap.add_argument("--from-addr", default="lab-sender@example.local")
    ap.add_argument("--to-addr", default="lab-receiver@example.local")
    ap.add_argument("--subject", default="LAB: SMTP header visibility test")
    ap.add_argument("--header-name", default="X-Lab-Tag")
    ap.add_argument("--text", default="EmailHeaderDemo")
    ap.add_argument("--mode", choices=["counter", "timestamp", "random", "list"], default="timestamp")
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--delay", type=float, default=0.2, help="Delay between emails (seconds)")
    args = ap.parse_args()

    with smtplib.SMTP(args.smtp_host, args.smtp_port) as s:
        for i in range(1, args.count + 1):
            msg = EmailMessage()
            msg["From"] = args.from_addr
            msg["To"] = args.to_addr
            msg["Subject"] = args.subject

            header_value = build_header_value(args.mode, args.text, i)
            msg[args.header_name] = header_value

            msg.set_content(
                f"Ovo je test poruka #{i}.\n"
                f"{args.header_name}: {header_value}\n"
                f"(Lab okruženje – dummy sadržaj.)\n"
            )

            # Opcionalni privitak (dummy)
            msg.add_attachment(
                f"dummy attachment for message {i}\n".encode("utf-8"),
                maintype="text",
                subtype="plain",
                filename=f"dummy_{i:03d}.txt",
            )

            s.send_message(msg)
            print(f"Poslano #{i} ({args.header_name}: {header_value})")
            time.sleep(args.delay)

if __name__ == "__main__":
    main()

