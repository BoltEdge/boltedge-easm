# Skill: weekly-summary

**Owner agent:** founder-ops
**Trigger:** scheduled (Monday 08:00 founder timezone) or manual
**Output:** markdown email digest sent to the founder

## Inputs
- 7-day stats from `GET /api/internal/stats/weekly`

## Steps
1. Fetch weekly stats from the internal API.
2. Summarise in markdown: lead with signups + scans + plan mix.
3. Highlight changes vs. last week if memory has prior numbers.
4. Send the digest email to the founder via the platform send service.

## Voice
Terse. Lead with the punch line. Numbers prominent. No filler.
