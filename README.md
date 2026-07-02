# 🛡️ SCADA Baseline IDS

> 🚀 A Python-based SCADA Intrusion Detection System (IDS) for Modbus TCP traffic analysis, asset discovery, anomaly detection, and industrial network monitoring.

![Status](https://img.shields.io/badge/Status-Active%20Development-blue)
![Python](https://img.shields.io/badge/Python-3.x-yellow)
![SCADA](https://img.shields.io/badge/SCADA-Security-red)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📖 Overview

SCADA Baseline IDS is a cybersecurity project focused on Industrial Control Systems (ICS) and SCADA environments.

The project analyzes Modbus TCP traffic from PCAP files, automatically discovers industrial assets, builds communication baselines, and detects suspicious activities that may indicate unauthorized access or industrial attacks.

### 🎯 Learning Areas

* 🌐 Network Security
* 🏭 Industrial Cybersecurity
* ⚙️ SCADA Security
* 📡 Modbus TCP Analysis
* 🚨 Intrusion Detection Systems
* 🐍 Python Security Tools

---

## ✨ Features

### 🔍 Asset Discovery

* Discover PLCs, HMIs, and Modbus devices
* Build asset inventory automatically
* Identify unknown devices

### 📊 Modbus Traffic Analysis

* Analyze Modbus TCP packets
* Extract Function Codes
* Monitor industrial communication patterns

### 🚨 Detection Engine

* Unauthorized PLC Access Detection
* Dangerous Modbus Write Detection
* Register Scanning Detection
* Abnormal Communication Detection

### 📋 Logging & Alerts

* INFO Alerts
* WARNING Alerts
* CRITICAL Alerts
* Event Logging

---

## 🏗️ Architecture

```text
PCAP File
    ↓
Packet Capture
    ↓
Protocol Parser
    ↓
Asset Discovery
    ↓
Baseline Engine
    ↓
Detection Engine
    ↓
Alert System
```

---

### 🚧 Current Progress

#### ✅ Phase 1 - PCAP Processing

* [x] PCAP Loading
* [x] Packet Summary Analysis

#### ✅ Phase 2 - Asset Discovery

* [x] Asset Discovery Engine
* [x] PLC Identification
* [x] HMI Identification
* [x] Asset Inventory Generation

#### ✅ Phase 3 - Modbus Analysis

* [x] Modbus Function Parser
* [x] Function Code Identification
* [x] Read/Write Operation Detection

#### ✅ Phase 4 - Detection Engine

* [x] Unknown Device Detection
* [x] Dangerous Modbus Write Detection
* [x] Register Scan Detection

#### 🚧 Phase 5 - LSTM Autoencoder

* [x] Dataset Loading
* [x] Data Normalization
* [x] Sequence Generation
* [x] Tensor Conversion
* [x] LSTM Autoencoder Implementation
* [x] Model Training
* [x] Reconstruction Error Analysis
* [x] Threshold Selection
* [ ] Real-time Anomaly Detection
* [ ] Alert Generation
* [ ] Model Evaluation
* [ ] Integration with IDS

#### 📈 Future Work
* [x] Timing and frequency profiling
* [x] Risk Scoring
* [x] Event Logging
* [x] Enhanced security for config file 
* [x] Report generation
* [ ] Baseline Learning
* [ ] Dashboard
* [x] Real-Time Monitoring
---
## ⚡ Installation

```bash
git clone https://github.com/Nithish2kumar/SCADA-Baseline-IDS.git

cd SCADA-Baseline-IDS

pip install -r requirements.txt
```

---

## ▶️ Running the Project

```bash
sudo python3 main.py #Run the main file with privileged to capture the live traffic
```

---

## 🎯 Detection Goals

The IDS aims to detect:

* 🚨 Unauthorized Device Access
* 🖥️ Unknown Asset Discovery
* ✍️ Modbus Write Operations
* 🔎 Register Scanning Attempts
* 📡 Abnormal Industrial Traffic
* 📉 Baseline Deviations

---

## 📚 Learning Objectives

* 🏭 SCADA Security
* ⚙️ Industrial Control Systems
* 📡 Modbus Protocol
* 📦 Packet Analysis
* 🌐 Network Monitoring
* 🚨 Intrusion Detection Systems
* 🛡️ Industrial Threat Detection

---

## 🚀 Future Enhancements

* 📡 Live Traffic Monitoring
* 🎨 Pyside Dashboard
* 🔔 Real-Time Alerts
* 📊 Threat Scoring System
* 🕒 Attack Timeline Visualization
* 🔗 Multi-Protocol Support
* 📈 Historical Analysis

---

## 👨‍💻 Author

**Nithish Kumar (NK)**

Cybersecurity & Blockchain Technology Student

### 🔥 Interests

* 🛡️ Intrusion Detection Systems
* 🏭 Industrial Cybersecurity
* ⚙️ SCADA Security
* 🌐 Network Security
* 🐍 Python Security Tools

---

## ⚠️ Disclaimer

This project is developed strictly for educational, research, and defensive cybersecurity purposes.

Do not use any part of this project against systems without proper authorization.
