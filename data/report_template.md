# Threat Hunting Report

## General Information

- **Hunt Name:** [Descriptive name for the hunt]
- **Date of Hunt:** [YYYY-MM-DD]
- **Lead Hunter:** [Name and Role]
- **Contributors:** [List of contributors]
- **Approver:** [Name of approver]

---

## Hunt Overview

- **Hypothesis:** [A clear, testable hypothesis]
- **Objective:** [What this hunt aims to uncover or validate]
- **Scope:**
  - **Systems/Network Areas:** [E.g., endpoints, servers, specific subnet]
  - **Timeframe:** [E.g., last 30 days]
  - **Data Sources:** [E.g., DNS logs, SIEM, endpoint telemetry]
- **Methodology:** [Brief summary of hunting approach]
- **Expected Outcomes:** [Brief summary of outcomes]

---

## Preparation Phase

- **Topic Selection:** [Chosen topic or tactic, e.g., data exfiltration]
- **Research Conducted:** [Summary of threat actor TTPs, gaps identified, or prior detections reviewed]
- **Source of Intelligence:** [CTI team, open-source, vendor reports]
- **Feedback on Intelligence Inputs:**
  - **Quality of Intelligence:** [Comprehensive / Partially Missing / Unclear]
  - **Strengths:** [What was actionable or valuable.]
  - **Weaknesses:** [Any gaps or ambiguities.]
  - **Suggestions:** [How to enhance future intelligence inputs.]
- **Hunting Plan:**
  - **Tools and Techniques:** [E.g., log parsing, clustering, stack counting]
  - **Key Metrics:** [E.g., frequency anomalies, deviation thresholds]
  - **MITRE ATT&CK Mapping:**
    - **Tactics:** [E.g., Exfiltration (TA0010)]
    - **Techniques:** [E.g., T1071.001 (Application Layer Protocol: Web Protocols)]
    - **Sub-Techniques:** [E.g., T1071.004 (DNS)]

---

## Execution Phase

- **Data Gathering:**
  - **Data Sources Accessed:** [List data sources]
  - **Challenges in Data Collection:** [E.g., incomplete logs, latency issues]
- **Data Preprocessing:** [Steps like normalization, timestamp conversion]
- **Analysis Techniques:**
  - [E.g., clustering, anomaly detection]
- **Findings During Analysis:**
  - **Validated/Refuted Hypothesis:** [Explain how findings support/refute]
  - **Evidence Summary:** [Highlight significant anomalies or patterns]
  - **Critical Findings Escalated:** [Details of incidents or suspicious activity escalated]
  - **MITRE ATT&CK Mapping:**
    - **Tactics:** [E.g., Initial Access (TA0001)]
    - **Techniques:** [E.g., T1190 (Exploit Public-Facing Application)]
    - **Sub-Techniques:** [E.g., T1190.001 (Web Shell)]

---

## Act Phase

- **Documented Findings:** [Summarized results with key details]
- **Knowledge Preservation:**
  - **Documentation Location:** [E.g., internal wiki, ticketing system]
  - **Hunt Artifacts:** [List relevant scripts, queries, and datasets archived]
- **Gaps Identified:**
  - **People/Processes/Tools/Data:** [Describe gaps]
  - **Recommendations for Closing Gaps:** [Provide actionable advice]
- **Recommendations:**
  - **Operational Improvements:** [Suggestions for tools, workflows]
  - **Future Hunts:** [Ideas for related hunts based on findings]

---

## Outputs

- **Detections Created or Improved:** [List new detection rules or improved ones]
- **Metrics from Hunt:**
  - **Incidents Opened:** [Number of escalated findings]
  - **Gaps Identified and Closed:** [Details]
  - **Techniques Hunted:** [Mapped to MITRE ATT&CK or similar frameworks]

---

## Communication

- **Stakeholder Briefing:** [Summary of the briefing and attendees]
- **Findings Shared With:** [E.g., SOC, detection engineering, threat intel teams]
- **Future Enhancements:** [Any proposed improvements to detection or processes]

---

## Approval

- **Approver Comments:** [Feedback or notes]
- **Approval Date:** [YYYY-MM-DD]
