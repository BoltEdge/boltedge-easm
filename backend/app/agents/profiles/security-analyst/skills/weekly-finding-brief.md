# Skill: weekly-finding-brief

**Owner agent:** security-analyst (Maya)
**Trigger:** scheduled (Wednesday 08:00 founder timezone) or manual
**Output:** markdown email digest sent to the founder

## Inputs
- read_internal_api endpoint='findings/recent' (last 7 days)
- web_fetch on NVD entries for CVE-referenced findings

## Steps
1. Pull last 7 days of findings.
2. Identify themes (repeated CVE families, spikes, etc.).
3. Add threat-intel context for CVE-referenced findings.
4. Pick top 3–5 worth the director's attention.
5. Email the brief.

## Voice
Factual, technical, evidence-backed. Cite NVD URLs. Never invent CVE numbers.
