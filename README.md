# Secure Clinic Management Portal & Live Analytics Pipeline

An end-to-end full-stack data application featuring an automated JSON logging pipeline, role-based security gateways, and a business intelligence monitoring interface.

## Skills Demonstrated
* **Identity & Access Management (IAM):** Implemented Role-Based Access Control (RBAC) and cryptographic password hashing.
* **Security Telemetry Automation:** Designed an asynchronous logging pipeline using `Loguru` to capture and structure system logs into raw serialized JSON.
* **Business Intelligence & Incident Triage:** Built an interactive executive compliance dashboard utilizing continuous time-series analytics.

## Telemetry System Architecture
* **Application Core:** Written in **Python** using the **Flask** web framework.
* **Transactional Ledger:** Managed via an embedded relational **SQLite** database database engine.
* **Audit Pipeline Target:** Outputs real-time telemetry to `app_security.json` for automated security operations ingestion.

## Local Deployment Runbook
To deploy and monitor this environment locally on your workstation:
1. Standardize dependencies: `pip3 install -r requirements.txt`
2. Initialize the secure server instance: `python3 app.py`
3. Route your local web browser to the security gateway: `http://127.0.0.1:8000`
