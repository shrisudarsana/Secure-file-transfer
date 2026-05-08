# AI-Powered Secure File Transfer System

A high-performance, multi-threaded secure file transfer protocol built with Python, featuring real-time AI threat detection and RSA-4096 / SHA-256 cryptographic security.

## 🚀 Overview
This project implements a custom secure communication protocol designed to protect file transfers against eavesdropping and tampering. It integrates a machine learning model to analyze file metadata and block suspicious transfers (e.g., malware masquerading as documents).

## ✨ Key Features
- **Custom Security Protocol**: Handshake using RSA-4096 and integrity protection via SHA-256 keyed hashes.
- **AI Threat Detection**: Pre-trained Random Forest model for real-time risk assessment.
- **Interactive Dashboard**: Modern Flask-based UI for managing uploads, downloads, and monitoring logs.
- **Robust Socket Communication**: Reliable multi-threaded server handling concurrent transfers.

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/shrisudarsana/Secure-file-transfer.git
   cd Secure-file-transfer
   ```

2. **Set up virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Start the system**:
   ```bash
   sh start_all.sh
   ```

## 📋 Security Specs
- **Authentication**: Client authenticates server via RSA public key.
- **Integrity**: Every packet is verified using SHA-256 keyed HMAC.
- **Confidentiality**: Custom stream encryption derived from SHA-256 state XORing.

## 👥 Original Team Members
- Chandra Kiran Saladi
- Sourik Dhua

---
*Developed for Academic Project — Enhanced by AI*