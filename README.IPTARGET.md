# IP-Based Targeting + Input Validation for RedAmon

> **Status: IMPLEMENTED** (v2.3.0 — 2026-03-05)

## Context

This document describes the design and implementation of IP/CIDR-based targeting. Originally a planning document, now serves as architectural reference. The feature adds:

1. **IP-based targeting mode**: Start from IP addresses (individual or CIDR ranges) instead of a domain. The pipeline attempts reverse DNS to discover hostnames, creates mock Domain/Subdomain graph nodes when none are found, then continues the normal pipeline.
2. **Input validation**: Add regex-based format validation before saving for all fields that expect specific formats (IPs, domains, ports, status codes, headers, etc.).

---

## Part A: IP-Based Targeting

### A1. Database Schema

**File**: `webapp/prisma/schema.prisma` — add after `subdomainList` (line ~35):

```prisma
ipMode                      Boolean  @default(false) @map("ip_mode")
targetIps                   String[] @default([]) @map("target_ips")
```

Run `npx prisma migrate dev`. Existing rows auto-get defaults.

### A2. Frontend — TargetSection.tsx

**File**: `webapp/src/components/projects/ProjectForm/sections/TargetSection.tsx`

- Add **"Start from IP"** toggle before Target Domain. Locked in edit mode.
- When `ipMode = true`:
  - **Hide**: Target Domain, Subdomain Prefixes, Include Root Domain, Domain Verification
  - **Show**: "Target IPs / CIDRs" textarea (comma or newline separated)
  - Accepts: individual IPs (`192.168.1.1`), IPv6 (`2001:db8::1`), and CIDR ranges (`10.0.0.0/24`, `192.168.1.0/28`) — max /24 (256 hosts)
  - On toggle `true`: clear `targetDomain` and `subdomainList`
  - On toggle `false`: clear `targetIps`
- Stealth Mode stays visible regardless of mode

### A3. Frontend — ProjectForm.tsx

**File**: `webapp/src/components/projects/ProjectForm/ProjectForm.tsx`

- Add `ipMode: false`, `targetIps: []` to `MINIMAL_DEFAULTS`
- **Validation in `handleSubmit`**: if `ipMode`, require at least one entry in `targetIps` and validate each is a valid IPv4, IPv6, or CIDR (see Part B validators)
- Skip domain conflict check when `ipMode === true`
- Pass `ipMode` and `targetIps` to conflict check API for IP-overlap detection

### A4. API Routes

**POST `/api/projects`** (`webapp/src/app/api/projects/route.ts`):
- Relax `targetDomain` requirement — only required when `ipMode` is falsy
- When `ipMode = true`, store `targetDomain` as empty string

**POST `/api/projects/check-conflict`** (`webapp/src/app/api/projects/check-conflict/route.ts`):
- Accept optional `ipMode` and `targetIps` in request body
- When `ipMode`: query other IP-mode projects, check for overlapping IPs/CIDRs
- For CIDR overlap: check if any individual IP or CIDR range overlaps with existing projects

### A5. Backend Settings

**File**: `recon/project_settings.py`

Add to `DEFAULT_SETTINGS`:
```python
'IP_MODE': False,
'TARGET_IPS': [],
```

Add to `fetch_project_settings()`:
```python
settings['IP_MODE'] = project.get('ipMode', DEFAULT_SETTINGS['IP_MODE'])
settings['TARGET_IPS'] = project.get('targetIps', DEFAULT_SETTINGS['TARGET_IPS'])
```

### A6. Recon Pipeline — main.py

**File**: `recon/main.py`

**New module-level variables**:
```python
IP_MODE = _settings['IP_MODE']
TARGET_IPS = _settings['TARGET_IPS']
```

**New function `run_ip_recon(target_ips, settings)`**:
1. **Expand CIDRs**: use Python's `ipaddress.ip_network(cidr, strict=False)` to expand CIDR ranges into individual host IPs (max /24 = 256 hosts, validated on frontend). The `ipaddress` module is in the standard library — no new imports needed in the container.
2. **Reverse DNS (PTR)** for each expanded IP using `dns.reversename` (dnspython already in container)
3. **Subdomain naming**: PTR resolves → use hostname; no PTR → use IP with dashes (e.g., `192-168-1-1`)
4. **Mock domain**: `ip-targets.{PROJECT_ID}` (unique per project)
5. **IP WHOIS**: per-IP WHOIS, stored under `whois.ip_whois`
6. **Output**: same JSON structure as `run_domain_recon()` with `metadata.ip_mode = True`

For CIDR ranges like `/24` (256 IPs), expand for reverse DNS but also store the original CIDR in metadata for naabu (which accepts CIDR natively and scans more efficiently than individual IPs).

**Modify `main()`**:
- Skip domain ownership verification when `IP_MODE`
- Build synthetic `target_info` dict for IP mode
- Branch: `IP_MODE and TARGET_IPS` → `run_ip_recon()` instead of `run_domain_recon()`

### A7. Reverse DNS Utility

**File**: `recon/domain_recon.py`

Add `reverse_dns_lookup(ip_address, max_retries=3) -> Optional[str]`:
- Uses `dns.reversename.from_address()` + `dns.resolver.resolve(rev_name, 'PTR')`
- Handles NoAnswer, NXDOMAIN, Timeout with retries
- No new pip packages (dnspython already imported at line 14)

### A8. Graph DB

**File**: `graph_db/neo4j_client.py`

Add `update_graph_from_ip_recon(recon_data, user_id, project_id)`:
- Mock **Domain** node (`ip-targets.{project_id}`) with `ip_mode: True`, `is_mock: True`
- **Subdomain** nodes (real hostnames from PTR or mock IP-based names) with `is_mock` flag
- **IP** nodes and `RESOLVES_TO` relationships
- `BELONGS_TO` relationships from subdomains to mock domain
- Per-IP WHOIS data (org, country) on IP nodes

### A9. Downstream Module Patches — CRITICAL

#### http_probe.py — `is_host_in_scope()` (line 893)
**BLOCKER**: Currently rejects ALL IPs because it checks `host.endswith(f".{root_domain}")` before checking `allowed_hosts`. An IP like `192.168.1.1` never matches mock domain `ip-targets.{PROJECT_ID}`.

**Fix**: Add IP bypass at the top of `is_host_in_scope()`:
```python
# IP addresses bypass domain scope check — validate against allowed list
if is_ip(host):  # is_ip() already exists at line 929
    if allowed_hosts:
        return host in {h.lower().strip() for h in allowed_hosts}
    return True
```

For this to work, `run_ip_recon()` MUST set `metadata.subdomain_filter` to the expanded IP list + any PTR-resolved hostnames. This becomes `allowed_hosts` in `parse_httpx_output()` (line 1465).

#### http_probe.py — `build_targets_from_dns()` (line 469)
Mock subdomain names like `192-168-1-1` are not valid hostnames for URLs. When `metadata.ip_mode = True`, extract actual IPs from `dns.subdomains.{sub}.ips` fields instead of using subdomain key as hostname.

#### resource_enum.py — GAU skip
When `metadata.ip_mode = True`, skip GAU (archives index by domain, not IP).

#### No changes needed: port_scan.py, vuln_scan.py, Katana, Kiterunner

### A10. Export/Import

**Export** (`webapp/src/app/api/projects/[id]/export/route.ts`): Works as-is — all fields including `ipMode` and `targetIps` are exported.

**Import** (`webapp/src/app/api/projects/import/route.ts`): Line 109 `if (targetDomain)` — for IP mode, `targetDomain` is empty → skips domain conflict check (correct). Add: after line 140, check if imported project has `ipMode = true` and verify no IP overlaps with existing IP-mode projects.

---

## Part B: Input Validation

### B1. Validation Utility Module

**New file**: `webapp/src/lib/validation.ts`

Create a centralized validation module with reusable regex validators and a `validateField(fieldName, value)` function:

```typescript
// === IP / Network ===
export const REGEX_IPV4 = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/
export const REGEX_IPV6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
export const REGEX_CIDR_V4 = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)\/(2[4-9]|3[0-2])$/  // /24 to /32 only
export const REGEX_CIDR_V6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\/(10[4-9]|1[12][0-9]|128)$/  // /104 to /128 (≤256 hosts)

export function isValidIpOrCidr(value: string): boolean  // validates format + CIDR max /24
export function isValidIpv4(value: string): boolean

// === Domain / Subdomain ===
export const REGEX_DOMAIN = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/
export const REGEX_SUBDOMAIN_PREFIX = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/

export function isValidDomain(value: string): boolean
export function isValidSubdomainPrefix(prefix: string): boolean

// === Ports / Status Codes ===
export const REGEX_PORT = /^([1-9]\d{0,4}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/
export const REGEX_PORT_RANGE = /^(\d{1,5})(-(\d{1,5}))?$/
export const REGEX_STATUS_CODE = /^[1-5]\d{2}$/

export function isValidPortList(value: string): boolean    // "80,443,8080-8090"
export function isValidStatusCodeList(value: string): boolean  // "200, 301, 404"

// === HTTP Headers ===
export const REGEX_HTTP_HEADER = /^[A-Za-z0-9-]+:\s*.+$/

export function isValidHeaderList(value: string): boolean  // one header per line

// === GitHub ===
export const REGEX_GITHUB_TOKEN = /^(ghp_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{82,})$/
export const REGEX_GITHUB_REPO = /^[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+$/
export const REGEX_GITHUB_ORG = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/
export const REGEX_GIT_BRANCH = /^[a-zA-Z0-9._\/-]+$/

// === URL Paths ===
export const REGEX_URL_PATH = /^\/[^\s]*$/

// === Naabu Top Ports ===
export function isValidTopPorts(value: string): boolean  // "100", "1000", "full", or integer

// === HTTP Methods ===
export const VALID_HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']

// === Validation result type ===
export interface ValidationError { field: string; message: string }
export function validateProjectForm(data: ProjectFormData): ValidationError[]
```

### B2. Fields to Validate (by section)

**TargetSection** (`TargetSection.tsx`):
| Field | Validator | Error message |
|-------|-----------|---------------|
| `targetDomain` | `REGEX_DOMAIN` | "Invalid domain format (e.g., example.com)" |
| `subdomainList` items | `REGEX_SUBDOMAIN_PREFIX` | "Invalid subdomain prefix: {value}" |
| `targetIps` items | `isValidIpOrCidr()` | "Invalid IP/CIDR: {value}. CIDR max /24 (256 hosts)." |

**NaabuSection** (`NaabuSection.tsx`):
| Field | Validator | Error message |
|-------|-----------|---------------|
| `naabuTopPorts` | `isValidTopPorts()` | "Must be 100, 1000, full, or a number" |
| `naabuCustomPorts` | `isValidPortList()` | "Invalid port format (e.g., 80,443,8080-8090)" |

**HttpxSection** (`HttpxSection.tsx`):
| Field | Validator | Error message |
|-------|-----------|---------------|
| `httpxPaths` items | `REGEX_URL_PATH` | "Paths must start with /" |
| `httpxCustomHeaders` items | `REGEX_HTTP_HEADER` | "Invalid header format (Name: Value)" |
| `httpxMatchCodes` items | `REGEX_STATUS_CODE` | "Invalid status code (100-599)" |
| `httpxFilterCodes` items | `REGEX_STATUS_CODE` | "Invalid status code (100-599)" |

**KatanaSection** (`KatanaSection.tsx`):
| Field | Validator | Error message |
|-------|-----------|---------------|
| `katanaCustomHeaders` items | `REGEX_HTTP_HEADER` | "Invalid header format (Name: Value)" |

**KiterunnerSection** (`KiterunnerSection.tsx`):
| Field | Validator | Error message |
|-------|-----------|---------------|
| `kiterunnerMatchStatus` items | `REGEX_STATUS_CODE` | "Invalid status code" |
| `kiterunnerIgnoreStatus` items | `REGEX_STATUS_CODE` | "Invalid status code" |
| `kiterunnerHeaders` items | `REGEX_HTTP_HEADER` | "Invalid header format" |
| `kiterunnerBruteforceMethods` items | `VALID_HTTP_METHODS` | "Invalid HTTP method" |

**GauSection** (`GauSection.tsx`):
| Field | Validator | Error message |
|-------|-----------|---------------|
| `gauVerifyAcceptStatus` items | `REGEX_STATUS_CODE` | "Invalid status code" |
| `gauYearRange` items | `/^\d{4}$/` | "Must be a 4-digit year" |

**GithubSection** (`GithubSection.tsx`):
| Field | Validator | Error message |
|-------|-----------|---------------|
| `githubAccessToken` | `REGEX_GITHUB_TOKEN` (if non-empty) | "Invalid GitHub token format" |
| `githubTargetOrg` | `REGEX_GITHUB_ORG` (if non-empty) | "Invalid organization name" |
| `githubTargetRepos` items | `REGEX_GITHUB_REPO` or just name | "Invalid repo name" |

**AgentBehaviourSection** (`AgentBehaviourSection.tsx`):
| Field | Validator | Error message |
|-------|-----------|---------------|
| `agentLhost` | `REGEX_IPV4` (if non-empty) | "Invalid IPv4 address" |

**CypherFixSettingsSection** (`CypherFixSettingsSection.tsx`):
| Field | Validator | Error message |
|-------|-----------|---------------|
| `cypherfixGithubToken` | `REGEX_GITHUB_TOKEN` (if non-empty) | "Invalid GitHub token" |
| `cypherfixDefaultRepo` | `REGEX_GITHUB_REPO` (if non-empty) | "Format: owner/repo" |
| `cypherfixDefaultBranch` | `REGEX_GIT_BRANCH` (if non-empty) | "Invalid branch name" |

### B3. Where Validation Runs

**On submit** — in `ProjectForm.tsx` `handleSubmit()`:
1. Call `validateProjectForm(formData)` which returns an array of `ValidationError`
2. If errors exist, display them (alert or inline) and block submission
3. Validation is permissive for optional/empty fields — only validates non-empty values

**Inline hints** (optional enhancement) — each section can show a red hint under the field when the value is invalid, using the same validators. This provides real-time feedback but doesn't block saving until submit.

---

## Files to Modify (ordered)

| # | File | Change |
|---|------|--------|
| 1 | `webapp/prisma/schema.prisma` | Add `ipMode`, `targetIps` fields |
| 2 | `webapp/src/lib/validation.ts` | **New** — validation regex + utility functions |
| 3 | `recon/project_settings.py` | Add `IP_MODE`, `TARGET_IPS` defaults + fetch mapping |
| 4 | `webapp/src/app/api/projects/route.ts` | Relax targetDomain requirement |
| 5 | `webapp/src/app/api/projects/check-conflict/route.ts` | Add IP conflict checking |
| 6 | `webapp/src/app/api/projects/import/route.ts` | Add IP-mode conflict check for imports |
| 7 | `webapp/src/components/projects/ProjectForm/ProjectForm.tsx` | Defaults, call validateProjectForm, conflict skip |
| 8 | `webapp/src/components/projects/ProjectForm/sections/TargetSection.tsx` | IP mode toggle + conditional fields |
| 9 | `recon/domain_recon.py` | Add `reverse_dns_lookup()` utility |
| 10 | `recon/main.py` | Add `run_ip_recon()`, modify `main()` branching |
| 11 | `graph_db/neo4j_client.py` | Add `update_graph_from_ip_recon()` |
| 12 | `recon/http_probe.py` | Fix `is_host_in_scope()` for IPs + IP-mode `build_targets_from_dns()` |
| 13 | `recon/resource_enum.py` | Skip GAU in IP mode |

---

## Verification

1. `npx prisma migrate dev` — schema compiles
2. Create new project with "Start from IP" enabled → form hides domain fields, shows IP textarea
3. Enter invalid values (bad IPs, bad domain, bad ports) → validation errors block save
4. Enter valid IPs + CIDRs (`8.8.8.8, 10.0.0.0/28`) → saves correctly
5. Start recon → pipeline runs `run_ip_recon()` with reverse DNS + CIDR expansion
6. Check Neo4j graph → mock Domain + Subdomain + IP nodes with correct relationships
7. Port scan, http probe, resource enum, vuln scan all complete without errors
8. Restart containers: `docker compose restart agent webapp recon_orchestrator`
