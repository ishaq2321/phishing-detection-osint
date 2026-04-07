# PhishGuard — User Guide

Welcome to the PhishGuard User Guide! This guide will help you understand how to use the PhishGuard application to detect phishing threats in URLs, emails, and free-text content.

## 1. Getting Started

PhishGuard is designed to be intuitive and fast. To get started:
1. Navigate to the live demo at: [PhishGuard Live](https://project-4soy4.vercel.app)
2. Or, if running locally, open `http://localhost:3000` in your web browser.

## 2. Modes of Analysis

PhishGuard offers three distinct modes of analysis depending on the content you want to investigate:

### 2.1 URL Analysis Mode
Use this mode when you have a specific link you want to check before clicking.
- **How to use:** Paste the complete URL (e.g., `https://example-secure-login.com/auth`) into the input box and click **Analyze**.
- **What it does:** The system extracts 17 structural features, performs live OSINT lookups (WHOIS registration age, DNS records), and passes this data to the XGBoost Machine Learning model.

### 2.2 Email Analysis Mode
Use this mode when you receive a suspicious email.
- **How to use:** Paste the email's Subject, the Sender's address, and the Body of the email into the respective fields.
- **What it does:** The system uses Natural Language Processing (NLP) to detect urgent language, financial requests, and coercion tactics. Any URLs found within the email body are also automatically extracted and analyzed using the URL Machine Learning pipeline.

### 2.3 Free-Text Analysis Mode
Use this mode for SMS messages, social media posts, or instant messages.
- **How to use:** Paste the raw text into the input field.
- **What it does:** Uses the NLP engine to analyze the sentiment and intent of the message, looking for typical social engineering tactics.

## 3. Understanding the Results

Once an analysis is complete, you will be presented with a **Threat Score** ranging from 0 to 100%.

### 3.1 Threat Levels
*   ✅ **Safe (0% - 29%)**: The content appears benign. No obvious phishing indicators were detected.
*   ⚠️ **Suspicious (30% - 49%)**: Some unusual patterns were detected (e.g., young domain age). Exercise caution.
*   🔴 **Dangerous (50% - 69%)**: Strong phishing indicators are present. Do not click links or provide personal information.
*   🚨 **Critical (70% - 100%)**: Confirmed malicious patterns. Highly likely to be a phishing attempt.

### 3.2 Feature Breakdown
Below the main score, you can explore the **Feature Extractors** to understand *why* the model made its decision:
*   **URL Structure:** Flags if the URL uses IP addresses instead of domains, has too many subdomains, or abnormal length.
*   **OSINT Data:** Shows real-world context, such as if the domain was registered extremely recently (a common phishing tactic) or lacks stable DNS records.
*   **NLP Intent:** Highlights specific sentences or phrases in the text that show urgency or requests for credentials.

## 4. History and Past Analyses

All your recent analyses are saved locally in your session. 
- You can access past results by clicking the **History** tab in the navigation menu.
- From there, you can re-view the detailed report of any previously analyzed URL or email.
- You also have the option to clear your history if you are working on a shared device.

## 5. Troubleshooting & FAQs

**Q: The analysis is stuck loading for a long time. What's wrong?**
A: Sometimes, Live OSINT lookups on dead or unresponsive domains can take a few seconds. The system has built-in timeouts (max 15 seconds) to prevent infinite hanging. Wait a few moments, and the ML model will provide a result even if the OSINT servers fail to respond.

**Q: Why was a legitimate website flagged as 'Suspicious'?**
A: If a legitimate website was registered very recently or uses abnormal subdomains, it might trigger cautionary flags. Always evaluate the context alongside the tool's score.

---
*For technical support or issues, please refer to the Developer/README documentation or contact the project supervisor.*
