# WHOOP connector for Claude (your own private server)

This lets Claude read your own WHOOP data (recovery, HRV, resting heart rate, sleep, strain, workouts) so you can ask questions like "Am I ready to train hard today?" and get an answer based on your real numbers.

You run it yourself on Railway. No third-party company sits between your WHOOP account and Claude.

## What it can and cannot do

- Read only. It cannot change anything in your WHOOP account.
- Uses the official WHOOP developer API only.
- It does not see sets, reps or weights from WHOOP Strength Trainer. WHOOP does not share those through its official API.

## What you need

- A WHOOP membership
- A Claude Pro or Max plan (personal accounts are easiest; on Team or Enterprise plans only an admin can add custom connectors)
- A free GitHub account
- A Railway account (free trial, then about USD 5 a month)
- About 45 minutes the first time
- No coding. Every step is copy and paste.

## Setup in short

1. Click **Use this template** at the top of this page and create a **private** copy in your GitHub account.
2. Create two secret keys (see below). Save them in a password manager or a private note.
3. In Railway: New Project, then Deploy from GitHub repo, then pick your copy.
4. In Railway: Settings, Networking, Generate Domain, port **8080**.
5. In Railway: attach a Volume with mount path **/data**.
6. At developer.whoop.com: create an app. Redirect URI is `https://YOUR-DOMAIN/callback`. Tick read:recovery, read:cycles, read:workout, read:sleep, read:profile, read:body_measurement.
7. In Railway, Variables, Raw Editor, paste and fill in:
   ```
   WHOOP_CLIENT_ID=
   WHOOP_CLIENT_SECRET=
   MCP_KEY=
   TOKEN_SECRET=
   PUBLIC_URL=https://YOUR-DOMAIN
   ```
   Then Deploy.
8. Open `https://YOUR-DOMAIN/health`. You should see `{"ok":true}`.
9. Open `https://YOUR-DOMAIN/auth/start?key=YOUR_MCP_KEY` and approve on WHOOP's page.
10. In Claude: Settings, Connectors, Add custom connector.
    - URL: `https://YOUR-DOMAIN/mcp`
    - Authentication: No sign-in
    - Request header: name `X-API-Key`, value your MCP_KEY
11. Fully quit and reopen Claude. Start a new chat, switch the connector on, and ask for your readiness.

## Creating the two secret keys

Windows (PowerShell), run this twice:
```
$b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); ($b | ForEach-Object { $_.ToString("x2") }) -join ""
```

Mac (Terminal), run this twice:
```
openssl rand -hex 32
```

Use one result as `MCP_KEY` and the other as `TOKEN_SECRET`. Never share them, never put them in GitHub, and never show them in a screenshot.

## Tools Claude gets

| Tool | What it returns |
|---|---|
| get_readiness | Latest recovery and last night's sleep compared with your previous 14 days, plus recent day strain |
| get_recovery | Daily recovery %, HRV, resting heart rate, SpO2, skin temperature |
| get_sleep | Hours, deep, REM, light, restorative %, consistency, efficiency, respiratory rate |
| get_workouts | Strain, heart rate, calories and minutes in each heart rate zone |
| get_daily_strain | Day strain per WHOOP day |
| get_body_profile | Height, weight, max heart rate |

## How it protects your data

- The Claude connection needs your secret key in a header. Without it the server answers 401.
- Your WHOOP login tokens are encrypted (AES-256-GCM) with `TOKEN_SECRET` and stored only on your Railway volume.
- The WHOOP login only starts from a link that carries your key.
- The server never writes your keys or health data to its logs.

## If something goes wrong

| What you see | What to do |
|---|---|
| "Application failed to respond" | The domain port must be 8080. Settings, Networking, edit the domain. |
| WHOOP shows an error after login | The redirect URI in your WHOOP app must match `https://YOUR-DOMAIN/callback` exactly. |
| Claude says the connector is not signed in | Fully quit and reopen Claude, then start a new chat. |
| "WHOOP is not authorised yet" | Open the `/auth/start?key=...` link again and approve. |
| "could not be decrypted" | `TOKEN_SECRET` changed. Open the `/auth/start` link again. |
| You leaked your MCP_KEY | Make a new key, update it in Railway, redeploy, update the header in Claude. The old key stops working right away. |

## Licence

MIT. Use at your own risk. Not affiliated with WHOOP or Anthropic.
