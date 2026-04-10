# 📖 PhishGuard Thesis: Where to Insert Your Diagrams

This is your master guide to replacing **every single placeholder** in your final thesis document (`docs/THESIS_COMPLETE_DOCUMENT.md`). If you follow this checklist, there will be **zero leftovers** and you will not be embarrassed.

---

## ❓ HOW DOES IT WORK? (Your Questions Answered)

**"How do I insert diagrams to the .md file, and when I convert to PDF, will they be there?"**

Here is exactly how it works when you convert a Markdown (`.md`) file to a PDF:

1. **For the Mermaid Diagrams (The `.mmd` files we just created):**
   - You **DO NOT** use links or the `assets` folder! 
   - You literally copy the text code from the `.mmd` file and paste it directly into your thesis document inside a code block (` ```mermaid ... ``` `).
   - When you click "Convert to PDF", the converter reads that text and **automatically draws the diagram into the PDF**. You don't need any image files for these!

2. **For Screenshots and Photos (`.png` / `.jpg` files from your UI):**
   - You **MUST** save the image file into your `docs/assets/` folder.
   - You write a link in your markdown like this: `![Description of Image](assets/my_screenshot.png)`
   - When you click "Convert to PDF", the converter looks inside the `assets` folder on your computer, grabs the picture, and **glues it permanently into the PDF**.
   - **Important:** Once the PDF is created, the images are permanently inside the PDF file. You can email the PDF to your professor, and they will see the images even if they don't have your `assets` folder!

3. **What about the Tables?**
   - You might notice text like `[TABLE 2-1: Types of Phishing Attacks]` in your thesis. **Do not delete these!** 
   - If you look right below those labels, the actual tables are already written in Markdown code (using `| --- | --- |`). When you convert to PDF, those automatically turn into beautiful, fully-formatted academic tables. No images needed!

---

## 🔍 The Exact 4 Placeholders to Replace

I scanned your entire 19,500-word thesis document. There are exactly **four** `[FIGURE...]` placeholders that need your attention. Here is exactly how to replace each one:

### 1. Phishing Attack Taxonomy
- **Find this in document:** `**[FIGURE 2-1: Phishing Attack Taxonomy Diagram]**` (Around Line 408)
- **What to do:** Delete this text. You should find a diagram online showing phishing types (Email, SMS, Spear Phishing) or make a quick one. Save it to your `assets` folder as `taxonomy.png` and type:
  `![Figure 2.1: Phishing Attack Taxonomy](assets/taxonomy.png)`

### 2. OSINT Data Collection Pipeline
- **Find this in document:** `**[FIGURE 2-2: OSINT Data Collection and Feature Engineering Pipeline]**` (Around Line 818)
- **What to do:** Delete this text and paste the Mermaid code from `docs/diagrams/mermaid/ml-pipeline.mmd`:
  ```mermaid
  (paste the code from ml-pipeline.mmd here)
  ```

### 3. High-Level System Data Flow
- **Find this in document:** `**[FIGURE 3-1: High-Level System Data Flow]**` (Around Line 956)
- **What to do:** Delete this text and the 3 bullet points below it. Paste the Mermaid code from `docs/diagrams/mermaid/system-architecture.mmd`:
  ```mermaid
  (paste the code from system-architecture.mmd here)
  ```

### 4. SHAP Feature Importance Plot
- **Find this in document:** `**[FIGURE 4-1: SHAP Feature Importance (Beeswarm Plot)]**` (Around Line 1133)
- **What to do:** Delete this text. Take a screenshot of the actual SHAP graph your Python backend generates. Save it to the `assets` folder as `shap_plot.png` and type:
  `![Figure 4.1: SHAP Feature Importance (Beeswarm Plot)](assets/shap_plot.png)`

---

## ➕ Where to add the extra diagrams (For maximum grades)

To make your thesis look even better, add the remaining 3 Mermaid diagrams we created in the following places:

1. **The Sequence Diagram (Request Lifecycle)**
   - **Where:** Chapter 3, under section **3.2.2 Asynchronous OSINT Orchestration**
   - **How:** Paste the code from `sequence-diagram.mmd` inside a \`\`\`mermaid block.

2. **Class Diagram (Data Models)**
   - **Where:** Chapter 3, under section **3.3.3 Pydantic Schema Contracts**
   - **How:** Paste the code from `class-diagram.mmd` inside a \`\`\`mermaid block.

3. **User Journey Diagram**
   - **Where:** Chapter 6, under the introduction to **Chapter 6: User Interface and Experience**
   - **How:** Paste the code from `user-journey.mmd` inside a \`\`\`mermaid block.
