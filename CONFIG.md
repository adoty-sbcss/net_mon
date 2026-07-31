# Configuring NetMon for your organization

This is the **public NetMon collector** (the "sensor"). It runs on a small Linux
box on a school/site network, discovers what's on that network, and reports to a
**NetMon dashboard** over outbound HTTPS only (it opens no inbound ports).

The code here contains **no organization-specific values and no secrets** — every
site/org value is injected at deploy time. This guide lists what to set.

## Two ways to run a sensor

### A. Onboard to an existing NetMon dashboard (recommended for COEs)
If a County Office of Education already hosts a NetMon dashboard, you're a
**tenant** (a "district") in it. The easiest path:

1. In the dashboard, an admin creates your **district + school** landing spot.
2. Open that spot's **"Deploy a sensor here"** page on a fresh Ubuntu box.
3. Run the one-line installer it gives you. It sets every value below for you,
   runs a CIS hardening check, and auto-enrolls the box into that exact spot.

No manual config needed — the installer injects it all.

### B. Manual / golden-image setup
Run `./setup.sh` (interactive first-boot wizard) or pre-place a provisioning
file. Values come from, in order of precedence:

1. the process environment / `/etc/netmon/netmon.env`
2. `config/provisioning.env`        (git-ignored; per-site)
3. `/etc/netmon/provisioning.env`   (golden image / config mgmt)

Copy `config/provisioning.env.example` → `config/provisioning.env` and fill it
in. **Never commit `config/provisioning.env`** (it's git-ignored).

## What you set (per deployment)

| Variable | What it is |
|----------|-----------|
| `NETMON_DASHBOARD_URL` | Your NetMon dashboard's base URL (e.g. `https://netmon.yourcoe.org`). Blank = no control plane, and nowhere to ship bundles. |
| `NETMON_BOOTSTRAP_KEY` | Shared self-enrollment key from the dashboard (or use a per-spot token from the deploy page). Secret — never committed. |
| `NETMON_DISTRICT` / `NETMON_SCHOOL` / `NETMON_DEVICE` | Human names; auto-slugged. They tag every scan and organize uploads into `<district>/<school>/<device>/`. |
| `NETMON_BUNDLE_TRANSPORT` | `blob` = ship bundles over HTTPS to the dashboard. Anything else = the pre-install staging state, uploads OFF. Set remotely by the dashboard when a sensor is marked installed; you shouldn't need to touch it. |
| `NETMON_DNS_TEST_NAMES` | Public names probed for DNS health. Append your own domain to verify internal resolution. |

See `.env.example` for the full set of optional knobs (scan cadence, SNMP
communities, crawl scope, etc.). All have safe defaults.

## What stays out of the repo
- The dashboard URL and bootstrap key (injected per deploy).
- Any org/internal domain names.
- The dashboard application + Azure infrastructure (a separate, privately-hosted
  app — sensors only need its URL).
