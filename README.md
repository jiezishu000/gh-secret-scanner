# GitHub Secret Scanner

Scan any public GitHub repository for leaked API keys, tokens, and secrets.

## Supported Patterns
- OpenAI API Keys (sk-proj-, sk-)
- Anthropic API Keys (sk-ant-api03-)
- AWS Access Keys (AKIA...)
- GitHub Tokens (ghp_, gho_, ghu_)
- Ethereum Private Keys (0x...)
- Google API Keys (AIzaSy...)
- Discord Bot Tokens
- Telegram Bot Tokens

## Usage

```bash
# Set your GitHub token (optional, increases rate limit)
export GH_TOKEN="your_github_token"

# Scan a repository
python3 gh-secret-scanner.py https://github.com/username/repo
```

## Why?

API keys get accidentally committed to public repos every day. GitHub's secret scanning only covers repos with 100+ stars. Smaller repos are not scanned automatically — this tool helps fill that gap.

## Donate

If this tool found a leak in your repo and saved you from a security incident, consider donating 1 USDT to support development:

TRC20: TEwbbfoUtQTTfQFFD6fbLcnSD7tdrdpRx6

Or EVM chains: 0xa66c92bcb095533ed878fc30a4cbd24dc8edde93

