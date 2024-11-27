
# **CyberSentinel: Threat Detection Workflows**

## **Overview**
CyberSentinel is a Splunk-powered threat detection framework designed to identify anomalies and mitigate security risks proactively. This project showcases the power of **SPL queries** to analyze DNS, HTTP, and SSL/TLS traffic, focusing on detecting DNS tunneling, rare user agents, and insecure SSL configurations.

---

## **Threat Detection Workflows**

### **1️⃣ Detecting DNS Tunneling**
- **Objective**: Identify high-frequency DNS queries often used for data exfiltration or command-and-control (C2) communication.
- **SPL Query**:
  ```spl
  index=threat_hunting_logs sourcetype=dns | stats count by query | where count > 100
  ```
- **Insight**: Domains like `client.wns.windows.com` and `us-v20.events.data.microsoft.com` with over 100 queries were flagged for further investigation.
- **Image**:  
  ![Detecting DNS Tunneling](https://github.com/user-attachments/assets/8598726d-009f-4ffd-94e1-8adc9bfc2d46)

---

### **2️⃣ High-Frequency DNS Queries from a Single Source**
- **Objective**: Detect excessive DNS activity from a single internal IP, which could indicate tunneling or botnet behavior.
- **SPL Query**:
  ```spl
  index=threat_hunting_logs sourcetype=dns | stats count by src_ip | where count > 1000
  ```
- **Insight**: IP `10.1.10.5` generated over 1,000 DNS queries, triggering a real-time alert.
- **Image**:  
  ![High-Frequency DNS Queries from a Single Source](https://github.com/user-attachments/assets/726e8f90-41e5-4545-9ba1-f11a200df70d)

---

### **3️⃣ Spotting Suspicious HTTP POST Requests**
- **Objective**: Monitor repeated or large HTTP POST requests that could signify unauthorized data uploads.
- **SPL Query**:
  ```spl
  index=threat_hunting_logs sourcetype=http method="POST" | stats count, avg(content_length) by clientip
  ```
- **Insight**: A suspicious client IP, `10.1.10.200`, was flagged for large POST payloads to a non-standard endpoint.
- **Image**:  
  ![Spotting Suspicious HTTP POST Requests](https://github.com/user-attachments/assets/103bef2a-9da7-4edf-ab9b-206f12c4224c)

---

### **4️⃣ Identifying Rare HTTP User Agents**
- **Objective**: Highlight uncommon or suspicious user agents in HTTP traffic.
- **SPL Query**:
  ```spl
  index=threat_hunting_logs sourcetype=http | stats count by user_agent | where count < 10
  ```
- **Insight**: Rare user agents like `Microsoft-CryptoAPI/10.0` accessed sensitive endpoints.
- **Image**:  
  ![Identifying Rare HTTP User Agents](https://github.com/user-attachments/assets/a82a42b9-ccdd-43c3-9aaa-e01c8d23d662)

---

### **5️⃣ Uncovering Self-Signed SSL Certificates**
- **Objective**: Detect insecure or self-signed SSL certificates used in encrypted traffic.
- **SPL Query**:
  ```spl
  index=threat_hunting_logs sourcetype=ssl validation_status="self signed certificate" | stats count by server_name
  ```
- **Insight**: The server `daserekolut.top` was flagged for using a self-signed certificate.
- **Image**:  
  ![Uncovering Self-Signed SSL Certificates](https://github.com/user-attachments/assets/8104a7c6-538a-45af-b7d3-0e6e5400ea05)

---

## **Project Deliverables**
1. **Detailed SPL Queries**:
   - Ready-to-use queries for detecting anomalies in DNS, HTTP, and SSL/TLS traffic.
2. **Insights and Visualizations**:
   - Screenshots showcasing query results for real-world application.
3. **Documentation**:
   - Step-by-step guide to replicate workflows in your Splunk environment.

---

## **How to Use**
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/YourGitHub/YourRepo.git
   ```
2. **Import SPL Queries**:
   - Copy the provided queries into your Splunk environment.
3. **Analyze Your Data**:
   - Replace `index=threat_hunting_logs` with your specific index.
4. **Generate Alerts**:
   - Configure alerts using these queries for real-time monitoring.

---

## **Key Learnings**
- Proactively detecting DNS anomalies and HTTP irregularities can prevent major security incidents.
- Integrating SPL queries with workflows streamlines threat hunting.
- CyberSentinel empowers security teams with actionable insights and automated monitoring.

---

