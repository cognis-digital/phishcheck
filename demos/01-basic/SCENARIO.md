# Demo 01 - Basic phishing triage

This demo shows PHISHCHECK scoring real-world phishing patterns. Everything is
offline and stdlib-only; no network calls are made.

## Files

- `sample_phish.eml` - a synthetic PayPal-impersonation email that fails DMARC,
  spoofs the display name, uses a Return-Path on a throwaway domain, and links
  to a brand typosquat over plain http.

## Run it

Score the email (reads the .eml file):

```bash
python -m phishcheck email demos/01-basic/sample_phish.eml
```

Get machine-readable output for piping into a SOAR/SIEM pipeline:

```bash
python -m phishcheck --format json email demos/01-basic/sample_phish.eml
```

Score just the malicious link:

```bash
python -m phishcheck url "http://paypal-secure-login.account-verify.xyz/verify?id=1"
```

## Expected outcome

- The email scores in the **HIGH** band and exits with code `3`.
- Reported signals include `dmarc-fail`, `displayname-spoof`,
  `returnpath-mismatch`, `intent-language`, and an `embedded-url` finding for
  the typosquatted PayPal link.
- The bare URL scores HIGH on `brand-lookalike`, `risky-tld`, `no-tls`, and
  `intent-keyword`.

## Triage workflow

Non-zero exit codes let you wire this into an inbox-triage script:

```bash
for eml in quarantine/*.eml; do
  python -m phishcheck --format json email "$eml" > "$eml.verdict.json" || \
    echo "FLAGGED: $eml"
done
```
