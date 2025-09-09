# Password Cracker (Dictionary Attack)

A simple Python script to attempt cracking **MD5, SHA1, and SHA256** password hashes using a dictionary attack.  

## Features

- Supports **MD5**, **SHA1**, and **SHA256** hashes.
- Uses the `rockyou.txt` dictionary file for guessing passwords.
- Advanced hash detection with the `hashid` module.
- Option to fall back to basic hash length-based detection.
- Debug mode to see all password attempts (optional).

## Requirements

- Python 3.x
- Optional: `hashid` module for advanced hash detection  
  ```bash
  pip install hashid
A dictionary file, e.g., rockyou.txt


Usage

Place the rockyou.txt file in the same folder as the script.

Run the script:
python password_cracker.py

Enter the hash you want to crack when prompted.

The script will try to identify the hash type and perform a dictionary attack.

Type exit to quit the script.


Notes

Only simple dictionary attacks are supported; no brute-force functionality yet.

Only MD5, SHA1, and SHA256 hashes are supported.


Disclaimer

This tool is for educational purposes only. Do not use it on unauthorized systems or passwords.
