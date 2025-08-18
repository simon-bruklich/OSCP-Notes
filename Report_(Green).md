
# Quickstart
Locally hosted Sysreptor in Docker to be used for exam reporting. 

In code blocks: add `highlight-manual` (beside the language, before the fenced code block); then wrap words in `§§` to highlight them. This is NOT a double-dollar sign.

- Start: `docker compose -p sysreptor start`
- Stop:  `docker compose -p sysreptor stop`
- Access: http://localhost:8000
	- `kali:kalikali`

# Disable image compression and PDF compression
- https://docs.sysreptor.com/setup/configuration/#compress-images

# Checklist
- For each action:
	- Explain
	- Give code block
	- Give screenshot
- If using exploits
	- Link to exploit
	- Put source code for exploit in report
	- Highlight any changes made to the exploit (if applicable)

Is there a way to draw a small black border around all images?
# Tips
- In `pre code` CSS section, add `break-inside: avoid;` in order to avoid page-breaks on code blocks
```CSS
pre code {
    border: 1px solid black;
    padding: 0.2em !important;
    break-inside: avoid;
}
```
- Leverage mermaid diagrams to showcase lateral movement
- Be sure to use `<pagebreak />` component in HTML where needed
- Change `width="auto"` change to `width="75%"` where pasting image ref to keep images from being too tall and going off-page
- To ensure images stay with their preceding text, add this to CSS:
```CSS
figure {
    break-before: avoid;
}
```
- Reference for image captions and more
	- https://docs.sysreptor.com/designer/figures/

# CVSS Scoring Example

![[Pasted image 20250316211725.png]]

Let's break down the **CVSS v3.1** score for **OS Credential Dumping: LSASS Memory** into **Temporal** and **Environmental** scoring components.

---

## **CVSS v3.1 Base Score Recap (High Severity)**
Based on our previous breakdown:

| **Metric**              | **Value** | **Justification** |
|------------------------|----------|------------------|
| **Attack Vector (AV)**  | **L** (Local) | Requires local access or remote code execution |
| **Attack Complexity (AC)** | **L** (Low) | Tools like Mimikatz make it straightforward |
| **Privileges Required (PR)** | **H** (High) | Requires administrative or SYSTEM-level access |
| **User Interaction (UI)** | **N** (None) | No user interaction required once access is obtained |
| **Scope (S)** | **C** (Changed) | Credential exposure can lead to lateral movement |
| **Confidentiality (C)** | **H** (High) | Full credential exposure allows full domain compromise |
| **Integrity (I)** | **L** (Low) | Attack itself does not alter system integrity |
| **Availability (A)** | **L** (Low) | Minimal impact on system stability |

**Base Score: ~8.2 (High Severity)**

---

## **Temporal Score**
The **Temporal Score** considers exploit availability, remediation, and confidence in the exploitability of the vulnerability.

| **Metric**                | **Value** | **Justification** |
|--------------------------|----------|------------------|
| **Exploit Code Maturity (E)** | **H** (High) | Public tools like Mimikatz, ProcDump, and direct LSASS dumping methods are well-documented and widely used |
| **Remediation Level (RL)** | **O** (Official Fix) | Microsoft offers mitigations such as Credential Guard, LSASS protection, and Event Monitoring |
| **Report Confidence (RC)** | **C** (Confirmed) | LSASS credential dumping is a well-known and documented attack technique |

### **Temporal Score Adjustment: ~7.6 - 8.0 (High Severity)**

---

## **Environmental Score**
The **Environmental Score** accounts for how the vulnerability affects a specific environment, including mitigations and asset value.

| **Metric**                | **Value** | **Justification** |
|--------------------------|----------|------------------|
| **Confidentiality Requirement (CR)** | **H** (High) | Credentials are critical for domain security |
| **Integrity Requirement (IR)** | **M** (Medium) | Integrity impact is moderate as credentials can be misused but do not directly alter system files |
| **Availability Requirement (AR)** | **M** (Medium) | LSASS crashes may cause system reboots, but impact is usually limited |
| **Modified Attack Vector (MAV)** | **L** (Local) | Same as base, unless LSASS dumping is done via remote code execution |
| **Modified Attack Complexity (MAC)** | **L** (Low) | No additional complexity in most environments |
| **Modified Privileges Required (MPR)** | **H** (High) | Admin/SYSTEM rights still required |
| **Modified User Interaction (MUI)** | **N** (None) | No user interaction needed |
| **Modified Scope (MS)** | **C** (Changed) | Attack enables lateral movement |
| **Modified Confidentiality (MC)** | **H** (High) | Full credential exposure |
| **Modified Integrity (MI)** | **L** (Low) | Integrity impact remains low |
| **Modified Availability (MA)** | **L** (Low) | Limited impact on system uptime |

### **Environmental Score Adjustment:**
- **If well-mitigated (e.g., Credential Guard, LSASS protections, proper monitoring):** ~6.5 - 7.0 (**Medium-High**)  
- **If poorly mitigated (e.g., no monitoring, easy access to LSASS):** ~8.5 - 9.0 (**Critical**)  

---

### **Final Scores Summary**
| **Score Type**  | **Value** | **Severity** |
|---------------|---------|------------|
| **Base Score** | **8.2** | High |
| **Temporal Score** | **7.6 - 8.0** | High |
| **Environmental Score** | **6.5 - 9.0** | Medium to Critical (depends on mitigations) |

# Submission
- [ ] PDF file name `OSCP-OS-XXXXXXX-Exam-Report.pdf`
- [ ] PDF file archived into 7z; archive file name is `OSCP-OS-XXXXX-Exam-Report.7z`
	- [ ] `sudo 7z a OSCP-OS-XXXXX-Exam-Report.7z OSCP-OS-XXXXX-Exam-Report.pdf`
- [ ] Not exceeding 200MB
- [ ] Upload to https://upload.offsec.com
- [ ] MD5sum to confirm integrity
