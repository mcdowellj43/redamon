// === IP / Network ===
export const REGEX_IPV4 = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/
export const REGEX_IPV6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
export const REGEX_CIDR_V4 = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)\/(2[4-9]|3[0-2])$/
export const REGEX_CIDR_V6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\/(10[4-9]|1[1][0-9]|12[0-8])$/

export function isValidIpv4(value: string): boolean {
  return REGEX_IPV4.test(value.trim())
}

export function isValidIpOrCidr(value: string): boolean {
  const v = value.trim()
  return REGEX_IPV4.test(v) || REGEX_IPV6.test(v) || REGEX_CIDR_V4.test(v) || REGEX_CIDR_V6.test(v)
}

// === Domain / Subdomain ===
export const REGEX_DOMAIN = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/
export const REGEX_SUBDOMAIN_PREFIX = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/

export function isValidDomain(value: string): boolean {
  return REGEX_DOMAIN.test(value.trim())
}

export function isValidSubdomainPrefix(prefix: string): boolean {
  return REGEX_SUBDOMAIN_PREFIX.test(prefix.trim())
}

// === Ports / Status Codes ===
export const REGEX_PORT = /^([1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/
export const REGEX_STATUS_CODE = /^[1-5]\d{2}$/

export function isValidPortList(value: string): boolean {
  if (!value.trim()) return true
  return value.split(',').every(part => {
    const trimmed = part.trim()
    if (trimmed.includes('-')) {
      const [start, end] = trimmed.split('-').map(s => s.trim())
      return REGEX_PORT.test(start) && REGEX_PORT.test(end) && parseInt(start) <= parseInt(end)
    }
    return REGEX_PORT.test(trimmed)
  })
}

export function isValidStatusCodeList(value: string): boolean {
  if (!value.trim()) return true
  return value.split(',').every(part => REGEX_STATUS_CODE.test(part.trim()))
}

// === HTTP Headers ===
export const REGEX_HTTP_HEADER = /^[A-Za-z0-9-]+:\s*.+$/

export function isValidHeaderList(headers: string[]): boolean {
  return headers.every(h => !h.trim() || REGEX_HTTP_HEADER.test(h.trim()))
}

// === GitHub ===
export const REGEX_GITHUB_TOKEN = /^(ghp_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{82,})$/
export const REGEX_GITHUB_REPO = /^[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+$/
export const REGEX_GITHUB_ORG = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/
export const REGEX_GIT_BRANCH = /^[a-zA-Z0-9._\/-]+$/

// === URL Paths ===
export const REGEX_URL_PATH = /^\/[^\s]*$/

// === Naabu Top Ports ===
export function isValidTopPorts(value: string): boolean {
  const v = value.trim().toLowerCase()
  if (v === 'full' || v === '100' || v === '1000') return true
  return /^\d+$/.test(v) && parseInt(v) > 0
}

// === HTTP Methods ===
export const VALID_HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']

// === Validation result ===
export interface ValidationError { field: string; message: string }

export function validateProjectForm(data: Record<string, unknown>): ValidationError[] {
  const errors: ValidationError[] = []
  const ipMode = data.ipMode as boolean

  // Target domain (required when not IP mode)
  if (!ipMode) {
    const domain = (data.targetDomain as string || '').trim()
    if (domain && !isValidDomain(domain)) {
      errors.push({ field: 'targetDomain', message: 'Invalid domain format (e.g., example.com)' })
    }
  }

  // Target IPs (required when IP mode)
  if (ipMode) {
    const ips = data.targetIps as string[] || []
    for (const ip of ips) {
      if (ip.trim() && !isValidIpOrCidr(ip)) {
        errors.push({ field: 'targetIps', message: `Invalid IP/CIDR: ${ip}. CIDR max /24 (256 hosts).` })
      }
    }
    if (ips.filter(ip => ip.trim()).length === 0) {
      errors.push({ field: 'targetIps', message: 'At least one IP or CIDR is required in IP mode' })
    }
  }

  // Subdomain prefixes
  const subdomainList = data.subdomainList as string[] || []
  for (const sub of subdomainList) {
    const clean = sub.replace(/\.$/, '')
    if (clean && !isValidSubdomainPrefix(clean)) {
      errors.push({ field: 'subdomainList', message: `Invalid subdomain prefix: ${clean}` })
    }
  }

  // Naabu ports
  const topPorts = data.naabuTopPorts as string
  if (topPorts && !isValidTopPorts(topPorts)) {
    errors.push({ field: 'naabuTopPorts', message: 'Must be 100, 1000, full, or a number' })
  }
  const customPorts = data.naabuCustomPorts as string
  if (customPorts && !isValidPortList(customPorts)) {
    errors.push({ field: 'naabuCustomPorts', message: 'Invalid port format (e.g., 80,443,8080-8090)' })
  }

  // httpx paths
  const httpxPaths = data.httpxPaths as string[] || []
  for (const p of httpxPaths) {
    if (p.trim() && !REGEX_URL_PATH.test(p.trim())) {
      errors.push({ field: 'httpxPaths', message: 'Paths must start with /' })
      break
    }
  }

  // httpx headers
  const httpxHeaders = data.httpxCustomHeaders as string[] || []
  if (!isValidHeaderList(httpxHeaders)) {
    errors.push({ field: 'httpxCustomHeaders', message: 'Invalid header format (Name: Value)' })
  }

  // httpx match/filter codes
  for (const field of ['httpxMatchCodes', 'httpxFilterCodes'] as const) {
    const codes = data[field] as string[] || []
    for (const code of codes) {
      if (code.trim() && !REGEX_STATUS_CODE.test(code.trim())) {
        errors.push({ field, message: `Invalid status code (100-599)` })
        break
      }
    }
  }

  // Katana headers
  const katanaHeaders = data.katanaCustomHeaders as string[] || []
  if (!isValidHeaderList(katanaHeaders)) {
    errors.push({ field: 'katanaCustomHeaders', message: 'Invalid header format (Name: Value)' })
  }

  // GitHub token
  const ghToken = data.githubAccessToken as string
  if (ghToken && !REGEX_GITHUB_TOKEN.test(ghToken)) {
    errors.push({ field: 'githubAccessToken', message: 'Invalid GitHub token format' })
  }

  // GitHub org
  const ghOrg = data.githubTargetOrg as string
  if (ghOrg && !REGEX_GITHUB_ORG.test(ghOrg)) {
    errors.push({ field: 'githubTargetOrg', message: 'Invalid organization name' })
  }

  // Agent LHOST
  const lhost = data.agentLhost as string
  if (lhost && !REGEX_IPV4.test(lhost)) {
    errors.push({ field: 'agentLhost', message: 'Invalid IPv4 address' })
  }

  // CypherFix
  const cfToken = data.cypherfixGithubToken as string
  if (cfToken && !REGEX_GITHUB_TOKEN.test(cfToken)) {
    errors.push({ field: 'cypherfixGithubToken', message: 'Invalid GitHub token' })
  }
  const cfRepo = data.cypherfixDefaultRepo as string
  if (cfRepo && !REGEX_GITHUB_REPO.test(cfRepo)) {
    errors.push({ field: 'cypherfixDefaultRepo', message: 'Format: owner/repo' })
  }
  const cfBranch = data.cypherfixDefaultBranch as string
  if (cfBranch && !REGEX_GIT_BRANCH.test(cfBranch)) {
    errors.push({ field: 'cypherfixDefaultBranch', message: 'Invalid branch name' })
  }

  return errors
}
