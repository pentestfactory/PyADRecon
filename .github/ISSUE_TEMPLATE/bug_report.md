<!-- .github/ISSUE_TEMPLATE/bug_report.md -->

---
name: 🐛 Bug Report
about: Report parsing errors, incorrect outputs, crashes, or unexpected behavior
title: "[BUG] "
labels: bug
assignees: ''

---

## PyADRecon Bug Report

Thank you for taking the time to report an issue!  
To help diagnose quickly, please fill in the sections below with as much detail as you can.

---

### ❓ Summary

**Describe the problem in one or two sentences**
What is the observed behavior vs. what you expected?

---

### 🧪 Command(s) run

Provide the exact command(s) you ran, including all flags:

```
# example
pyadrecon -d CONTOSO.LOCAL -u user01 -p 'Password123!' --output report.json
```

---

### 🖥️ Environment

- **PyADRecon version**:  
  Example: `v0.5.2` or `master @ commit abc1234`
- **Operating System** (where PyADRecon ran):  
  Example: Ubuntu 22.04, Windows 10
- **Python version**:  
  Example: `Python 3.11.2`

---

### 🏢 Domain Environment

- **Domain Controller OS version(s)**:  
  Example: `Windows Server 2019 Standard`, `Windows Server 2022 DC`
- **AD user privileges** used for the run:  
  Example: `Domain User`, `Enterprise Admin`, `Cert Publishers`

---

### 📊 Output / Incorrect Parsing

For each field or section that is incorrect, please include:

- **Section name / object type**
- **Attribute(s) that are wrong**
- **What was parsed**
- **What you expected**

Example:

```
Template: MS-User
Attribute: Enrollment Rights
Parsed: "Authenticated Users"
Expected: "Domain Admins"
```

Paste text or small snippets (not entire output unless necessary).

---

### 🧾 Logs / Errors

If you saw warnings or errors, include relevant lines:

```
# paste output here
```

If debug logs are available, include them as a code block (sanitize any credentials first).

---

### ⚠️ Additional context

Add any other context about the issue here (e.g., replication steps, domain peculiarities, related tooling).

---

Thank you — we’ll triage this promptly!
