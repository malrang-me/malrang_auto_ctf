# Strategy — Diatonic Scale Revenge

## Solver-A: Direct prompt injection + web_search exfiltration
- Override system prompt in GPT instructions
- Instruct model to extract "authentication token" from user message
- Make model call web_search with token embedded in query targeting our webhook
- Techniques: role override, instruction injection, delimiter confusion

## Solver-B: Indirect/encoded exfiltration
- If direct exfiltration is blocked, encode flag before exfiltration
- Use base64 encoding, character-by-character extraction, or other encoding
- Alternative: make model search for flag as domain name (DNS exfiltration style)

## Key Considerations
- "Revenge" implies the original direct approach was patched
- May need more sophisticated injection to bypass enhanced system prompt
- web_search might not directly fetch URLs — may only query search engines
- Need to verify if web_search can trigger HTTP requests to controlled endpoints
