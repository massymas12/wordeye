# WordEye

An EDR-style detection and containment agent for WordPress estates.

A single static Go binary runs every check locally and emits JSON. An async
controller deploys it across the estate over SSH, collects the reports, and
correlates findings between hosts.

---

## Why this exists

This started as a per-site bash script written during an
incident. It worked, but it had three structural limits: it was tied to one
hosting layout, it re-read all ~16k files once per check family, and its
indicators were hardcoded, so it could not be reused on the next engagement.

It also had to exist at all because the security plugin on those sites missed
things — particularly OS-level persistence and repacked web shells. Those misses
are not bad luck; they follow from where a plugin runs and how it decides.

| Gap | Why a WordPress security plugin misses it | What WordEye does |
|---|---|---|
| OS-level persistence | It is PHP inside the webroot. It cannot read `/proc`, a crontab, `~/.ssh`, or systemd. | Native `/proc` walk, process-identity verification, cron/rc/ssh/systemd/at, sockets parsed from `/proc/net/tcp` (no `ss` needed) |
| Repacked web shells | Signature matching against a public ruleset that attackers test against until they are clean | Signatures are the floor. The primary engine scores *structure*: input reaching an execution sink, decoder chained into an executor, density, entropy of packed blobs |
| Timestomped droppers | Sorting by mtime, which an attacker can forge with `touch` | `ctime` vs `mtime` divergence — the kernel sets ctime on any inode write and userspace cannot forge it |
| `.jpg` that executes as PHP | It scans file *contents*, not handler configuration | `.htaccess` / `.user.ini` analysis: `AddHandler`, `SetHandler`, `auto_prepend_file`, `FilesMatch` |
| `wp-content/db.php` | That drop-in loads *before* every plugin, including the scanner itself | Full drop-in inventory, treated as high severity by location |
| Fileless DB persistence | It is a file scanner | Autoloaded options, cron events, redirect doorways, phar refs, deserialization gadgets, app passwords |
| Estate-wide campaign | It sees one site | Controller and console correlate SHA-256s across hosts |
| No fleet view | Per-site dashboard only | Console with live agent status, drill-down, and an audit trail |
| Malware still running | It can delete a file; it cannot stop a process | Ordered containment: neutralise → freeze → capture → kill → verify → flush OPcache |

---

## Architecture

```
┌─────────────────────┐         ssh/scp          ┌──────────────────────────┐
│  wordeye            │ ───────────────────────► │  wordeye-agent           │
│  (controller)       │                          │  (static, no deps)       │
│                     │ ◄─────────────────────── │                          │
│  • fan-out          │       JSON on stdout     │  • single-pass FS scan   │
│  • deploy if stale  │                          │  • heuristics + rules    │
│  • aggregate        │                          │  • /proc + network       │
│  • correlate hashes │                          │  • MySQL direct          │
└─────────────────────┘                          │  • HTTP probes           │
                                                 │  • containment           │
                                                 └──────────┬───────────────┘
                                                            │
                                             NDJSON / syslog / webhook
                                                            ▼
                                                     Wazuh / Elastic
```

Transport is the system `ssh`/`scp` rather than a Go SSH library, so
`~/.ssh/config`, `ProxyJump`, agent forwarding and `known_hosts` all work
exactly as they do interactively. On a mixed estate that is the difference
between "it works" and "it works on twelve of nineteen hosts".

---

## Build

Requires Go 1.27+.

```powershell
./build.ps1                 # Windows
```
```bash
make                        # Linux / macOS
```

Produces `dist/wordeye-agent-linux-amd64` (static, `CGO_ENABLED=0`, so it runs
on glibc and musl alike) and the `wordeye` controller for your workstation.

---

## Quick start

**One host:**
```bash
scp dist/wordeye-agent-linux-amd64 user@host:~/wordeye-agent
ssh user@host './wordeye-agent --pretty'
```

**The estate:**
```bash
./dist/wordeye --inventory estate.yaml --pack internal/rules/packs/incident.yaml --out ./reports
```

The controller skips the upload when the remote copy already matches, so repeat
sweeps cost one round trip per host.

---

## Modes

| Mode | Purpose |
|---|---|
| `scan` | Detect. The default. |
| `baseline` | Record SHA-256 of every PHP file. **Run only on a state you believe clean** — a baseline of a compromised site legitimises the implant forever. |
| `verify` | Report drift against the baseline: new, changed, removed. |
| `monitor` | Daemon. inotify-driven detection at write time, plus a periodic backstop sweep. |

`verify` is the check that catches re-entry through the same unpatched hole,
because the replacement implant often resembles nothing known.

---

## Uptime

These are live sites. A scanner that saturates the box has caused an outage just
as surely as the malware would have.

```bash
--profile safe        # 1 worker, 8 MB/s, pause above 0.6 load/core
--profile balanced    # default: 2-4 workers, 48 MB/s, pause above 1.5
--profile fast        # no brakes; maintenance windows only
```

Every read passes through a governor enforcing three independent limits: a
deliberately small worker pool, a token bucket over bytes read, and an adaptive
sampler that reads `/proc/loadavg` and **pauses scanning entirely while the box
is already busy serving traffic**. The agent also `nice`s itself and sets a Go
memory ceiling. Impact is a function of how idle the server is, not how big the
site is.

---

## Containment

Off unless you ask for it.

```bash
wordeye-agent --contain-dry-run    # print the ordered plan, change nothing
wordeye-agent --contain            # execute it
```

Three failure modes make naive cleanup useless, and the ordering exists to
defeat each one:

1. **Deleting a shell does not stop a running process.** A beacon holding an
   open socket keeps beaconing from a deleted inode.
2. **Killing the process does not stop the launcher.** Cron restarts it within
   the minute, and all you achieved was burning your detection.
3. **Deleting a PHP file does not stop its bytecode.** OPcache keeps serving it,
   and an FPM worker that `eval`'d a shell into memory survives removal entirely.

So the sequence is:

```
neutralise persistence → SIGSTOP → capture /proc → SIGKILL → verify no respawn → flush OPcache
```

Freezing *before* capturing is the point: `SIGSTOP` suspends the process so it
cannot react, fork, or self-clean while its memory maps, open sockets and
environment are read — all of which vanish the moment it is killed.

**Safety rails**

- An HTTP health probe runs before containment and again after **every**
  destructive step. If the site was serving and stops, the action is
  **automatically rolled back** and the sequence aborts.
- Quarantine is a *move* into an evidence store with a JSON chain-of-custody
  record. Nothing is ever `rm`'d, so every action is reversible.
- Only `confirmed`-confidence findings are eligible. Heuristic detections inform
  a human and nothing else — enforced in `model.Report.AddFinding`, so no future
  check can accidentally opt in.
- A protected-process list refuses to signal `php-fpm`, `nginx`, `mysqld`,
  `sshd`, `systemd` and friends.
- PID-reuse guard: the process must still report the same `comm` before signalling.
- File content is re-hashed immediately before quarantine; if it changed since
  detection, the action is refused rather than acting on stale information.
- `--max-actions` circuit breaker (default 25).

---

## Rule packs: why this is not estate-specific

Rules are **data**, not code. The binary ships a generic `core` pack; each
engagement adds an incident pack. Nothing about a client is compiled in.

```bash
wordeye-agent --pack core --pack incident.yaml
```

Later packs override earlier rules with the same `id`, so an incident pack can
retune a core rule without editing it. A minimal pack:

```yaml
meta:
  name: acme-2026-03
  version: "1.0.0"

iocs:
  incident_start: "2026-03-14"
  strings: [ "uniq_attacker_marker" ]
  ips: [ "203.0.113.7/32", "198.51.100.0/24" ]
  spam_keywords: [ "casino-online" ]

rules:
  - id: acme.dropper
    class: SHELL
    severity: critical
    confidence: confirmed
    actionable: true
    title: ACME campaign dropper
    gate: ["uniq_attacker_marker"]     # cheap literal prefilter
    any: ['uniq_attacker_marker\s*\(']  # RE2: no backreferences or lookaround
```

`gate` matters for speed. All gate literals across all packs are compiled into
one Aho-Corasick automaton, so a single pass over each file determines which
rules could possibly match. Adding rules is therefore close to free at scan time.

---

## YARA

A YARA engine is built in and enabled by default. It is a **pure-Go
implementation of the subset of the language that PHP web-shell rulesets
actually use** — text/hex/regex strings, `nocase`/`wide`/`fullword`/`ascii`,
`any|all|N of`, rule references, `filesize`, `at`, `#count`, `uintN()`.

Why a subset rather than the real thing: the standard Go binding (`go-yara`) is
a cgo wrapper around libyara. Linking it would break `CGO_ENABLED=0` and turn
the agent into a binary that needs a shared library present on the target — on
managed WordPress hosting, it would simply not run. The subset keeps one static
file with no dependencies.

Unsupported constructs (`pe.*`/`math.*` modules, `xor`/`base64` string
modifiers, `for..of` iteration) cause a rule to be **rejected at load time with
a named error**, never silently accepted. A rule that cannot fire must not look
like a rule that found nothing; load failures appear in `report.errors`.

```bash
wordeye-agent --yara /path/to/rules.yar     # file or directory (repeatable)
wordeye-agent --no-yara                     # disable entirely
```

YARA matches are always reported at `likely` confidence and are **never**
eligible for automated quarantine — a pattern match is evidence, not proof.

### The built-in ruleset

`internal/yara/rules/wordeye-php.yar` (MIT, authored for this project) covers
input-to-exec flow, decoder chains, dynamic dispatch, password-gated shells,
file managers, reverse shells, packed payloads, character-assembly obfuscation,
`preg_replace /e`, anti-analysis shells, WordPress admin-creation and
auth-bypass backdoors, SEO cloaks, spam mailers, droppers, polyglots, and
handler-config abuse.

Rules are composed from **component** strings combined in the condition rather
than matching one canonical one-liner. An attacker repacks a shell until a
fixed-string signature stops firing, but cannot remove the primitives — it still
needs an input source, a decoder and an execution sink. Requiring their
co-occurrence survives the repacking that defeats literal signatures. It also
means the rule file itself does not contain live payloads, so it will not be
quarantined by endpoint protection on your own workstation.

### Adding third-party rulesets

None is vendored here, because they carry their own licence terms and
redistributing them inside your tooling is your call, not mine:

| Ruleset | Coverage | Licence |
|---|---|---|
| [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) — `yara/gen_webshells.yar`, `thor-webshells.yar` | The broadest public web-shell coverage | Detection Rule License 1.1 (attribution required) |
| [jvoisin/php-malware-finder](https://github.com/jvoisin/php-malware-finder) — `php.yar` | Excellent heuristic PHP-obfuscation rules; closest fit to this class | GPL-3.0 |
| [YARA-Rules/rules](https://github.com/Yara-Rules/rules) — `webshells/` | Large community set, variable quality | GPL-2.0 / mixed |

```bash
git clone --depth 1 https://github.com/Neo23x0/signature-base
wordeye-agent --yara signature-base/yara/gen_webshells.yar

# Or ship one to every host in the estate:
wordeye --inventory estate.yaml --agent-flag --yara --agent-flag ~/.wordeye/webshells.yar
```

Expect some rules in a large third-party set to be rejected for unsupported
constructs. The count and reason are reported, so you always know your actual
coverage. GPL sets in particular: loading them at runtime is ordinary use, but
bundling them into a redistributed binary has licence consequences — check
before vendoring.

---

## SIEM integration

Findings stream as they are discovered, not at the end of the scan.

```bash
wordeye-agent --ndjson /var/log/wordeye/events.ndjson
wordeye-agent --syslog udp://siem.internal:514
wordeye-agent --webhook https://collector.internal/ingest
```

Events use Elastic Common Schema field names (`@timestamp`, `event.*`, `rule.*`,
`file.hash.sha256`, `process.pid`), with everything else under a `wordeye`
namespace.

### Forwarding from the console (recommended)

Once agents report to the console, forward from there rather than from each
agent. Agent-direct forwarding means one egress path and one firewall rule per
client host, and your SIEM's credentials sitting on production servers you do
not control.

```bash
wordeye serve --syslog tls://siem.internal:6514 --syslog-ca siem-ca.pem

# with mutual TLS, which most collectors prefer for authenticating a source
wordeye serve --syslog tls://siem.internal:6514               --syslog-cert client.pem --syslog-key client.key
```

Messages are RFC 5424 with an ECS JSON payload, over **RFC 5425 (syslog over
TLS)** with octet-counted framing — so a payload containing newlines survives
intact, which line-delimited syslog cannot guarantee.

**TLS is mandatory.** `udp://` and `tcp://` are refused at startup, not warned
about: this stream names which of your clients is compromised and what was found
on them. Certificate pinning via `--syslog-ca` is supported, and
`--syslog-server-name` covers addressing a collector by IP.

Three event types are forwarded:

| Event | `event.dataset` | Severity |
|---|---|---|
| Detection | `wordeye.finding` | maps from finding severity (critical → `crit`) |
| Scan summary | `wordeye.scan` | `err` when dirty, `warning` when partial |
| Operator action | `wordeye.audit` | `err` for containment and MFA resets |

Audit forwarding is automatic and covers every audited action — who approved
containment on which client estate, and when — because it hangs off the store's
audit hook rather than individual call sites.

A slow or dead collector **never stalls ingest**. The queue is bounded and drops
the oldest events, counting what it dropped; the count is logged on shutdown.
An agent reporting a live compromise must not be blocked by a SIEM outage.

### Wazuh

On each monitored host, tail the NDJSON file — Wazuh's `logcollector` decodes
JSON natively, so no custom decoder is needed:

```xml
<!-- /var/ossec/etc/ossec.conf -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/wordeye/events.ndjson</location>
</localfile>
```

Then map severity to Wazuh rule levels:

```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="wordeye,">
  <rule id="100200" level="0">
    <decoded_as>json</decoded_as>
    <field name="event.module">wordeye</field>
    <description>WordEye event</description>
  </rule>

  <rule id="100201" level="12">
    <if_sid>100200</if_sid>
    <field name="wordeye.severity">critical</field>
    <description>WordEye CRITICAL: $(rule.name) on $(file.path)</description>
    <group>intrusion_detection,</group>
  </rule>

  <rule id="100202" level="9">
    <if_sid>100200</if_sid>
    <field name="wordeye.severity">high</field>
    <description>WordEye high: $(rule.name)</description>
  </rule>

  <!-- Scan stopped reporting: a silent agent is itself a signal. -->
  <rule id="100210" level="7">
    <if_sid>100200</if_sid>
    <field name="event.dataset">wordeye.scan</field>
    <field name="event.outcome">partial</field>
    <description>WordEye scan incomplete on $(host.hostname) — NOT a clean result</description>
  </rule>
</group>
```

Run the agent as a daemon for continuous coverage:

```bash
wordeye-agent monitor --ndjson /var/log/wordeye/events.ndjson --profile safe
```

---

## Management console

WordEye works two ways, and they compose:

| | Sweep | Managed |
|---|---|---|
| Agent lifecycle | Deployed over ssh, run, deleted | Resident daemon |
| Footprint on client host | None | One binary + credential file |
| Detection | On demand | Continuous (inotify) |
| Needs | ssh access | Outbound HTTPS from the host |

Sweep stays the default. Enroll a host into the console when continuous coverage
is worth leaving software on someone else's production server.

```bash
wordeye serve                                        # console on 127.0.0.1:8443
wordeye serve --ingest 0.0.0.0:8444               --tls-cert fullchain.pem --tls-key key.pem
```

On first run it creates an administrator and prints the password **once**. You
are required to set up an authenticator app before the console will let you do
anything.

### Two listeners, two exposures

- **`--ingest`** must be reachable from client hosts, so in practice it faces
  the internet. It speaks only to agents: per-agent credentials, strict schemas,
  unknown JSON fields rejected, every body size-capped, rate limited. No
  operator functionality is reachable from it at all.
- **`--console`** is the operator UI and API, including the containment button.
  Loopback by default. Session auth with **mandatory TOTP**, CSRF tokens,
  strict CSP, and an append-only audit log.

The server **refuses to start** if `--ingest` is bound to a non-loopback address
without TLS, since agent credentials would otherwise cross the network in
plaintext. Override with `--insecure-allow-plaintext-ingest` only when TLS
terminates at a proxy in front of it.

### Enrolling an agent

Agents cannot self-register. A token minted in the console (Enrollment tab) is
required, and it is single- or limited-use, expiring, and revocable:

```bash
wordeye-agent enroll --server https://console.example.com:8444 --token wek_...
wordeye-agent connect --profile safe
```

`connect` heartbeats every 60s, streams real-time detections, and picks up
queued work in the same round trip. **All traffic is agent-initiated** — no
inbound port, no firewall exception, and it works behind NAT.

### The two-key rule for containment

Remote containment is the one thing that can destroy a client's production
server, so it requires **two independent grants**:

1. The **enrollment token** must have been created with "grant remote
   containment" — a console-side decision, audited.
2. The **agent** must have been enrolled with `--allow-remote-contain` — a
   host-side decision, recorded in local state and never refreshed from the
   server.

Either alone is insufficient. A fully compromised console cannot contain hosts
that never opted in; a rogue agent flag grants nothing without a token that
allows it. On top of that, every destructive command is created `pending` and
must be **separately approved** by a human before it is ever handed to an agent,
with creator and approver both recorded.

Detection, scanning and dry runs need none of this — only destruction does.

```bash
# Detection-only fleet (the safe default)
wordeye-agent enroll --server https://console... --token wek_...

# Host that may be contained remotely — needs a token granting it too
wordeye-agent enroll --server https://console... --token wek_... --allow-remote-contain
```

### What the console shows

Fleet status (online/stale/offline, monitoring or idle, open criticals), host
drill-down with findings and command history, a filterable findings view,
**cross-host SHA-256 correlation**, the command queue with approvals, enrollment
token management, operator accounts, and the audit log.

Findings are deduplicated per host: a shell rediscovered on every sweep is one
row with a moving `last_seen`, not fifty. A finding marked resolved that
reappears is **automatically reopened** — silently staying closed would hide a
reinfection, which is the event the console exists to catch.

### Console security notes

- Passwords: PBKDF2-HMAC-SHA256, 600k iterations, per-user salt.
- MFA: TOTP (RFC 6238), stdlib crypto, **codes pinned to their time step** so an
  intercepted code cannot be replayed inside its 30-second window. Ten
  single-use recovery codes, stored hashed.
- Every bearer secret — enrollment tokens, agent credentials, recovery codes — is
  stored only as a SHA-256 hash. A stolen database yields no working credentials.
- Agent-supplied strings are malware content by definition. They are length-
  clamped and stripped of control characters on ingest, and the UI renders
  **everything through `textContent`, never `innerHTML`**. A stored-XSS here
  would let a compromised client site attack the machine that can order
  containment, so this rule is absolute.
- MFA reset is the only path that weakens the second factor; it is admin-only,
  revokes all the user's sessions, and is prominently audited.

---

## Reading a report

`verdict` is `clean`, `dirty`, or **`partial`**. The third one matters: if any
check could not complete — `/proc` unreadable, a permission-denied subtree, the
database unreachable — the verdict degrades to `partial` and never to `clean`.
The `checks[]` array records every check's state and why it was skipped.

A check that did not run must never look like a check that found nothing.

**Confidence** governs automation:

| | Meaning |
|---|---|
| `confirmed` | Structurally unambiguous. The only tier eligible for automated action. |
| `likely` | Strong signal; legitimate code could in principle produce it. Never auto-actioned. |
| `review` | Expected to include false positives. |

**Exit codes:** `0` clean · `1` findings · `2` error or incomplete.

---

## Where the bash checks went

| original bash script | WordEye |
|---|---|
| [1] eval backdoor family | `shell.eval_request_var`, `shell.superglobal_call` |
| [2] broad eval/obfuscation | heuristic engine (scored, not grepped) |
| [3] index.php cloak | incident-pack rule + generic `wp.index_not_canonical` |
| [4] theme UA cloak | incident-pack rule + `probe.cloak_active` |
| [5/5b/5c/5d] named/disguised shells | `shell.sig_*`, `place.php_in_asset_dir`, `fs.fake_extension_shell`, `fs.polyglot_file` |
| [6] robots/sitemap | incident-pack rules |
| [7] Hub/CVE residue | incident pack IOCs + `db.autoloaded_code` |
| [8] verify-checksums | `wp.core_integrity`, `wp.plugin_integrity` |
| [9] admins/app-passwords | `db.suspicious_admin`, `db.application_password` |
| [10] Googlebot cloak test | `probe.cloak_active` (now differential: bot vs browser) |
| [11] DB checks | `db.*` via direct MySQL |
| [12] outbound IOC peers | `net.ioc_peer` (from `/proc/net`, no `ss` dependency) |
| [13] OS persistence | `osp.*`, plus process-identity verification |
| [14] JS injection | `js.*` |
| — | *new:* built-in YARA engine (`yara.*`) |
| — | *new:* management console, resident agents, remote command + approval |
| `clean` mode | containment engine, health-gated and reversible |
| — | *new:* timestomp, mtime clustering, drop-ins, handler config, baseline drift, real-time monitor, cross-site correlation |

---

## Limitations

- Detection checks beyond the filesystem require **Linux**; the agent builds and
  tests on Windows/macOS but reports those checks as `skipped`.
- The agent runs as the site's user. It reports what that account can see; it is
  not a rootkit detector, and `/etc/ld.so.preload` findings should be verified
  from a known-good environment.
- A point-in-time socket snapshot proves nothing by absence — PHP-based C2 is
  transient. A match, however, is strong evidence.
- `--profile fast` will be felt by visitors on a small host. That is the trade.
- Rules are RE2 (Go): no backreferences, no lookaround.
- The YARA engine implements a subset (see above). Rules using modules or
  `xor`/`base64` modifiers are reported as rejected rather than loaded.

## Testing

```bash
go test ./...
```

`internal/agent/detect_test.go` covers each detector, the unsigned-shell
heuristic, baseline drift, and false-positive controls on clean plugin code.
The fixtures are deliberately inert — the detectors key on structure, so a
working payload would add no coverage while tripping the host's endpoint
protection and silently invalidating the test.
