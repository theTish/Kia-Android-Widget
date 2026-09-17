# Running the API on the Oracle box

The API was written for Vercel, which is a poor fit: every cold start built a
new `VehicleManager` and logged in to Kia again. In production that meant six
logins in forty-five minutes, responses between 3s and 24s, and a 504 whenever
the car was slow enough to exceed the function timeout. It also made the
7901 rate-limit guard useless, since each instance starts blank and cannot see
what the others have done.

On a long-lived process the token, the vehicle list and the 30s cache survive
between requests, so a login happens roughly once a day and responses are fast.

## Layout

| Thing | Where |
|-------|-------|
| Host | `opc@100.78.17.30` (Tailscale only; port 22 is not public) |
| Key | `C:/Users/leeti/benchbot.key` |
| Checkout | `/home/opc/kia-android-widget` |
| Secrets | `/home/opc/kia.env` (not in git, not in the image) |
| Deploy script | `/home/opc/bin/kia-deploy.sh` (copy of `deploy/kia-deploy.sh`) |
| Container | `kia-api`, published on `127.0.0.1:5000` only |
| Public URL | `https://kia.tishman.ca` |

The container binds to loopback deliberately: nginx is the only way in, so the
app is never exposed directly even if the firewall changes.

## Deploy

```bash
ssh -i "C:/Users/leeti/benchbot.key" opc@100.78.17.30 "/home/opc/bin/kia-deploy.sh"
```

Builds with the old container still serving, health checks the new one, and
rolls back to `kia-api:previous` if it does not come up. Logs to
`/home/opc/kia-deploy.log`.

After editing `deploy/kia-deploy.sh`, push the host copy - the script cannot
deploy itself, because `git pull` updates the checkout and not `/home/opc/bin`:

```bash
scp -i "C:/Users/leeti/benchbot.key" deploy/kia-deploy.sh opc@100.78.17.30:/home/opc/bin/kia-deploy.sh
```

## Environment

`/home/opc/kia.env` holds the same variables Vercel had, plus one:

```
KIA_USERNAME=...
KIA_PASSWORD=...
KIA_PIN=...
SECRET_KEY=...
KIA_REGION=2
BATTERY_CAPACITY_KWH=77.4
KIA_KEEPALIVE_SECONDS=300
```

`KIA_KEEPALIVE_SECONDS` is the only new one. It runs the library's cheap
"get vehicle list" call every five minutes, which keeps the access token alive
so the app re-logs-in about once a day. Leave it unset on Vercel, where the
process does not live long enough for it to mean anything.

## Why one gunicorn worker

Each worker is a separate process with its own `VehicleManager`, token and
vehicle list. Four workers would mean four logins and four independent 35-minute
cooldowns that cannot see each other. Threads give concurrency without that, and
`_init_lock` in `api/index.py` stops two simultaneous requests both starting a
login.

## Vercel

Still deployed and still works, as a standby. If this box is down, point the
clients back at `https://kia-android-widget.vercel.app` - which is why the
Android app reads its base URL from settings rather than having it compiled in.
