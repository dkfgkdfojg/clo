# clo — OSINT toolkit

A desktop OSINT tool that runs a set of public-source lookups from one place:
phone numbers, usernames, emails, domains, IP addresses, Discord accounts and
image metadata. Written in Python with a Tkinter/CustomTkinter interface.

Built for authorised research — due diligence, verifying who you are dealing
with, checking your own exposure before someone else does.

## What it looks up

| Module | What it checks |
|---|---|
| `phone.py` | carrier, region, format validity, presence in public directories |
| `username.py` | the same handle across many public sites |
| `email.py` | appearance in known public breach indexes |
| `domain.py` | WHOIS, DNS records, subdomains |
| `ip.py` | geolocation, ASN, open-port information |
| `discord.py` | public profile data, account age, username history |
| `photo.py` | EXIF metadata, including embedded coordinates |

Each analyser is independent and degrades gracefully: a source that is down or
rate-limited is reported and skipped, not fatal to the run.

## Design notes

**Everything is a module.** `core/osint_runner.py` orchestrates external CLI
tools and internal analysers behind one interface, so adding a source means
writing one file, not touching the core.

**Input is validated before it leaves the process.** `core/validator.py` checks
every target — a malformed phone number or domain never reaches an outbound
request, which keeps both noise and accidental scanning of the wrong host down.

**Output never leaks secrets.** API keys live in `.env` and are stripped from
printed results and saved reports; there is a regression test for this, because
it was a real bug once.

**The GUI is thread-safe.** Analysers run in worker threads, and Tkinter may only
be touched from the thread running its main loop. Worker output therefore goes
into a `queue.Queue`, drained by the main thread on a timer — writing to the
widget directly from a worker is what caused freezes before. `stdout` is restored
and timers are cancelled on close, so nothing outlives the window.

## Tests

73 tests covering validators, HTTP helpers, the analyser orchestrator, secret
redaction, deduplication of history, and GUI thread-safety.

```bash
uv venv && uv pip install -r requirements.txt
python -m pytest -q
python main.py
```

## Scope

Public sources only. No credential stuffing, no exploitation, no bypassing
access controls — everything here is information that is already published.
Check the law in your jurisdiction before using it on anyone but yourself.
