---
name: ship-safe-deep
description: Run a deep security audit with LLM-powered taint analysis — regex scan nominates findings, then an LLM verifies taint reachability and exploitability. Use when the user wants thorough, high-confidence results with fewer false positives.
argument-hint: "[path] [--local] [--budget <cents>]"
---

# Ship Safe — Deep Analysis (LLM-Powered)

You are a senior security engineer running Ship Safe's deep analysis mode, which combines regex-based scanning with LLM-powered taint verification.

## Step 1: Check for LLM provider

Deep analysis requires either:
- An API key: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GOOGLE_API_KEY`
- Ollama running locally (use `--local` flag)

Check if the user has a provider available:

```bash
echo "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:+set}" "OPENAI_API_KEY=${OPENAI_API_KEY:+set}" "GOOGLE_API_KEY=${GOOGLE_API_KEY:+set}"
```

If no key is set, ask the user if they want to use `--local` (requires Ollama) or set an API key.

## Step 2: Run the deep audit

```bash
npx ship-safe@latest audit $ARGUMENTS --deep --json --no-ai 2>/dev/null
```

For local Ollama:
```bash
npx ship-safe@latest audit $ARGUMENTS --deep --local --json --no-ai 2>/dev/null
```

With budget control:
```bash
npx ship-safe@latest audit $ARGUMENTS --deep --budget 100 --json --no-ai 2>/dev/null
```

## Step 3: Interpret deep analysis results

Findings with `deepAnalysis` have LLM-verified taint information:

```json
{
  "deepAnalysis": {
    "tainted": true,
    "sanitized": false,
    "exploitability": "confirmed",
    "reasoning": "User input from req.body flows to SQL query without parameterization"
  }
}
```

Exploitability levels:
- **confirmed**: Clear, unsanitized path from user input to dangerous sink — fix immediately
- **likely**: Probable taint path but LLM could not fully trace it — investigate
- **unlikely**: Taint path exists but sanitization or context makes exploitation difficult
- **false_positive**: No real vulnerability — static value, test code, or properly sanitized

## Step 4: Present results

For each finding with deep analysis:
1. Show the exploitability verdict prominently
2. Include the LLM's reasoning
3. For "confirmed" findings, read the source file and offer a specific fix
4. For "false_positive" findings, note they can be baselined

Group findings by exploitability (confirmed first, then likely, then unlikely).

## Step 5: Cost summary

Show the deep analysis cost:
- Number of findings analyzed
- Approximate cost in cents
- Provider used

## Important Notes

- The `--deep` flag only analyzes critical and high severity findings (cost optimization)
- Default budget is 50 cents — use `--budget` to adjust
- Without an API key or `--local`, deep analysis is silently skipped and you get standard results
- The `--no-ai` flag is intentional — Claude Code is the AI layer; ship-safe's built-in classification is separate from deep taint analysis
