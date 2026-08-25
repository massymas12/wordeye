# Running the console on an Azure VM

The goal: a console on a VM you control, and WordPress hosts anywhere reporting
into it.

Traffic only ever flows **outbound from agents to the console**. Nothing
connects inbound to a client's web server, so no customer has to open a port or
make a firewall exception — which is usually the difference between a rollout
that happens and one that stalls in a change-approval queue.

---

## The two listeners

They have deliberately different exposure, and conflating them is the one
mistake that matters here.

| | port | who reaches it | exposure |
|---|---|---|---|
| **console** | 8443 | you | **loopback only — never the internet** |
| **ingest** | 8444 | agents | public, TLS |

The console can order containment — deleting files and killing processes — on
every site in the estate. It has password auth with mandatory MFA, but an
internet-facing containment API is not a risk worth taking for the convenience
of skipping an SSH tunnel. `docker-compose.yml` binds it to `127.0.0.1` on the
host for that reason.

---

## 1. VM and network

An Ubuntu 22.04/24.04 VM, `Standard_B2s` or larger. The console is not
demanding — SQLite and a Go binary — but scanning reports arrive in bursts.

Open **only 8444** inbound, plus SSH:

```bash
az vm open-port --resource-group <rg> --name <vm> --port 8444 --priority 1010
```

Do **not** open 8443. If you do, the containment API faces the internet.

## 2. Install Docker

```bash
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2
sudo usermod -aG docker $USER && newgrp docker
```

## 3. Get the code and set the public address

```bash
git clone <your-repo> wordeye && cd wordeye

# How agents will reach this VM. Use the DNS name if you have one; the public
# IP works fine. This is stamped into every generated installer, so it must be
# reachable from client hosts.
export WORDEYE_PUBLIC_URL="https://$(curl -s ifconfig.me):8444"
export WORDEYE_HOSTS="$(curl -s ifconfig.me)"
```

If you have a DNS name, prefer it — an IP-only certificate has to be reissued
when Azure hands you a different address:

```bash
export WORDEYE_PUBLIC_URL="https://console.example.com:8444"
export WORDEYE_HOSTS="console.example.com"
```

Persist them so `docker compose` sees them on reboot:

```bash
cat >> .env <<EOF
WORDEYE_PUBLIC_URL=$WORDEYE_PUBLIC_URL
WORDEYE_HOSTS=$WORDEYE_HOSTS
EOF
```

## 4. Certificate

```bash
docker compose --profile tools run --rm certgen
```

This writes a self-signed certificate covering the names in `WORDEYE_HOSTS`.

**Self-signed is the right choice here, not a shortcut.** Generated installers
embed this certificate and *pin* it, so an agent verifies this exact console.
That is stronger than a public CA certificate used without pinning, which
trusts every CA on earth not to mis-issue for your name. The only thing you
give up is a browser padlock on the console UI — which you reach over an SSH
tunnel anyway.

To use a real certificate instead, drop `cert.pem`/`key.pem` into the
`wordeye-certs` volume and skip this step.

## 5. Start

```bash
docker compose up -d
docker compose logs wordeye | head -30
```

The first-run administrator password is printed **once**, to the log:

```
  username  admin
  password  DAs6qR-shnnA8-cEFSx3-NjYQJ9
```

Save it now. It is not stored in recoverable form — if you lose it before
signing in, delete the `wordeye-data` volume and start again.

## 6. Reach the console

From your workstation:

```bash
ssh -L 8443:127.0.0.1:8443 azureuser@<vm-address>
```

Then open <http://127.0.0.1:8443>. Sign in and enroll an authenticator app; MFA
is mandatory and cannot be skipped.

---

## Adding a customer and rolling out

1. **Create an estate** — one per customer. Every agent enrolled with an
   installer generated for it lands under that customer automatically.

2. **Generate an installer:**

   ```bash
   curl -sS -X POST https://127.0.0.1:8443/api/estates/1/installer \
     -H "X-WordEye-CSRF: $CSRF" -b cookies.txt \
     -d '{"platform":"linux-amd64","monitor":true}' \
     -o wordeye-acme-linux-amd64
   ```

3. **Send it to the site administrator.** They run one file, no arguments:

   ```
   ./wordeye-acme-linux-amd64
   ```

   It finds WordPress, enrolls, scans, and the host appears in the console.

### The installer is a credential

It carries a live enrollment token. The token is single-use and expires (72h by
default), so once a host has enrolled the file is inert — but until then,
anyone holding it can enroll a host into your console. Send it the way you would
send a password, and prefer short TTLs.

### What an installer cannot do

**It cannot grant remote containment.** Containment needs two independent keys:
the console's token must permit it, *and* the host must opt in locally. If a
generated file could carry both, the second key would be decorative and a
leaked installer would arrive pre-authorised to destroy whatever machine ran
it. So installers enroll and monitor; containment stays an explicit act on the
host, via `wordeye-agent enroll --allow-remote-contain`.

---

## Operations

**Back up** — everything is in one SQLite file:

```bash
docker compose exec wordeye /usr/local/bin/wordeye --version   # confirm running
docker run --rm -v wordeye-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/wordeye-$(date +%F).tar.gz -C /data .
```

That file contains hashed agent credentials, findings for real client sites,
and the audit log. Treat the backup as client-confidential.

**Upgrade:**

```bash
git pull && docker compose build && docker compose up -d
```

The schema migrates in place on start. Enrolled agents keep working — their
credentials live in the database, not in the image.

**Logs:** `docker compose logs -f wordeye`

**Health:** `docker compose ps` — the healthcheck probes the ingest listener
over TLS, so "healthy" means agents can actually check in, not merely that a
process is alive.

---

## Hardening notes

The runtime image is distroless: no shell, no package manager, no interpreter.
The container runs as uid 65532 with a read-only root filesystem and all
capabilities dropped, so code execution inside it has very little to work with.

Worth doing beyond that:

- Restrict the Azure NSG rule for 8444 to your customers' egress ranges if they
  are known and stable. Most managed hosts are not, so this is often
  impractical — it is listed because when it *is* possible it is the single
  most effective control available.
- Put the VM's disk on an encrypted volume; the database holds client findings.
- Forward to a SIEM with `--syslog tls://…` so console actions and detections
  are recorded somewhere the console cannot alter.

## Troubleshooting

**Agent says "could not reach the console"** — the VM's NSG is not allowing
8444, or `WORDEYE_PUBLIC_URL` does not match how the client host resolves the
VM. Check from the client host: `curl -k https://<public-url>/v1/ping`.

**Agent says "TLS certificate was not accepted"** — the address the agent uses
is not in the certificate. Regenerate with the right `WORDEYE_HOSTS` and issue
a new installer; the old one pins the old certificate.

**"this console has no public URL configured"** — `WORDEYE_PUBLIC_URL` was not
set when the container started. A generated agent would not know where to
report, so generation refuses rather than producing a broken installer.
