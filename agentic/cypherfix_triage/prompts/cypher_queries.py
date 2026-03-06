"""Hardcoded Cypher queries for the static collection phase of triage."""

TRIAGE_QUERIES = [
    {
        "name": "vulnerabilities",
        "phase": "collecting_vulnerabilities",
        "description": "All vulnerabilities with endpoints, parameters, and GVM fields",
        "query": """
MATCH (v:Vulnerability {user_id: $userId, project_id: $projectId})
OPTIONAL MATCH (v)-[:FOUND_AT]->(e:Endpoint)
OPTIONAL MATCH (v)-[:AFFECTS_PARAMETER]->(p:Parameter)
OPTIONAL MATCH (e)-[:BELONGS_TO]->(b:BaseURL)
RETURN v.id AS vuln_id, v.name AS name, v.severity AS severity,
       v.source AS source, v.category AS category,
       v.cvss_score AS cvss_score, v.description AS description,
       v.matched_at AS matched_at, v.template_id AS template_id,
       v.solution AS solution, v.solution_type AS solution_type,
       v.qod AS qod, v.qod_type AS qod_type,
       v.cisa_kev AS cisa_kev, v.cve_ids AS cve_ids,
       v.remediated AS remediated,
       v.target_ip AS target_ip, v.target_port AS target_port,
       v.target_hostname AS target_hostname,
       collect(DISTINCT {path: e.path, method: e.method, url: b.url}) AS endpoints,
       collect(DISTINCT {name: p.name, type: p.type, is_injectable: p.is_injectable}) AS parameters
""",
    },
    {
        "name": "cve_chains",
        "phase": "collecting_cve_chains",
        "description": "Technology to CVE to CWE to CAPEC chains",
        "query": """
MATCH (t:Technology {user_id: $userId, project_id: $projectId})
      -[:HAS_KNOWN_CVE]->(c:CVE)
OPTIONAL MATCH (c)-[:HAS_CWE]->(m:MitreData)
OPTIONAL MATCH (m)-[:HAS_CAPEC]->(cap:Capec)
OPTIONAL MATCH (ex:ExploitGvm)-[:EXPLOITED_CVE]->(c)
RETURN t.name AS technology, t.version AS version,
       collect(DISTINCT {cve: c.id, cvss: c.cvss_score, description: c.description}) AS cves,
       collect(DISTINCT m.cwe_id) AS cwes,
       collect(DISTINCT cap.capec_id) AS capecs,
       count(DISTINCT ex) AS exploit_count
""",
    },
    {
        "name": "secrets",
        "phase": "collecting_secrets",
        "description": "GitHub secrets and sensitive files",
        "query": """
MATCH (d:Domain {user_id: $userId, project_id: $projectId})
      -[:HAS_GITHUB_HUNT]->(hunt:GithubHunt)
      -[:HAS_REPOSITORY]->(repo:GithubRepository)
OPTIONAL MATCH (repo)-[:HAS_PATH]->(path:GithubPath)
      -[:CONTAINS_SECRET]->(secret:GithubSecret)
OPTIONAL MATCH (path)-[:CONTAINS_SENSITIVE_FILE]->(sf:GithubSensitiveFile)
RETURN repo.name AS repo, repo.full_name AS full_name,
       collect(DISTINCT {path: path.path, secret_type: secret.secret_type, sample: secret.sample}) AS secrets,
       collect(DISTINCT {path: sf.path, secret_type: sf.secret_type}) AS sensitive_files
""",
    },
    {
        "name": "exploits",
        "phase": "collecting_exploits",
        "description": "Exploitable CVEs with confirmed exploits",
        "query": """
MATCH (ex:ExploitGvm {user_id: $userId, project_id: $projectId})
      -[:EXPLOITED_CVE]->(c:CVE)
OPTIONAL MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c)
RETURN c.id AS cve, c.cvss_score AS cvss, c.description AS description,
       collect(DISTINCT t.name) AS affected_technologies,
       collect(DISTINCT {exploit_id: ex.id, source: ex.source}) AS exploits
""",
    },
    {
        "name": "assets",
        "phase": "collecting_assets",
        "description": "Asset context: services, ports, IPs, base URLs",
        "query": """
MATCH (d:Domain {user_id: $userId, project_id: $projectId})
      -[:HAS_SUBDOMAIN]->(s:Subdomain)
      -[:RESOLVES_TO]->(ip:IP)
      -[:HAS_PORT]->(port:Port)
OPTIONAL MATCH (port)-[:RUNS_SERVICE]->(svc:Service)
OPTIONAL MATCH (svc)-[:SERVES_URL]->(b:BaseURL)
RETURN s.name AS subdomain, ip.address AS ip,
       collect(DISTINCT {port: port.number, protocol: port.protocol,
                         service: svc.name, product: svc.product, version: svc.version}) AS services,
       collect(DISTINCT b.url) AS urls
""",
    },
    {
        "name": "chain_findings",
        "phase": "collecting_chain_findings",
        "description": "Attack chain findings from pentesting sessions",
        "query": """
MATCH (cf:ChainFinding {user_id: $userId, project_id: $projectId})
WHERE cf.finding_type IN ['exploit_success', 'credential_found', 'access_gained',
                          'privilege_escalation', 'vulnerability_confirmed']
OPTIONAL MATCH (cf)-[:FOUND_ON]->(target)
  WHERE target:IP OR target:Subdomain
OPTIONAL MATCH (cf)-[:FINDING_RELATES_CVE]->(cve:CVE)
OPTIONAL MATCH (cf)-[:CREDENTIAL_FOR]->(svc:Service)
OPTIONAL MATCH (step:ChainStep)-[:PRODUCED]->(cf)
OPTIONAL MATCH (ac:AttackChain)-[:HAS_STEP]->(step)
RETURN cf.finding_id AS finding_id, cf.finding_type AS finding_type,
       cf.severity AS severity, cf.title AS title,
       cf.description AS description, cf.evidence AS evidence,
       cf.confidence AS confidence, cf.phase AS phase,
       cf.target_ip AS target_ip, cf.target_port AS target_port,
       cf.cve_ids AS cve_ids, cf.attack_type AS attack_type,
       labels(target)[0] AS target_type,
       CASE WHEN target:IP THEN target.address ELSE target.name END AS target_value,
       collect(DISTINCT cve.id) AS related_cves,
       svc.name AS credential_service,
       ac.chain_id AS chain_id, ac.status AS chain_status,
       ac.attack_path_type AS attack_path_type
""",
    },
    {
        "name": "attack_chains",
        "phase": "collecting_attack_chains",
        "description": "Attack chain session summaries",
        "query": """
MATCH (ac:AttackChain {user_id: $userId, project_id: $projectId})
WHERE ac.status IN ['completed', 'active']
OPTIONAL MATCH (ac)-[:CHAIN_TARGETS]->(target)
OPTIONAL MATCH (ac)-[:HAS_STEP]->(step:ChainStep)-[:PRODUCED]->(cf:ChainFinding)
OPTIONAL MATCH (ac)-[:HAS_STEP]->(fstep:ChainStep)-[:FAILED_WITH]->(fail:ChainFailure)
RETURN ac.chain_id AS chain_id, ac.title AS title,
       ac.objective AS objective, ac.status AS status,
       ac.attack_path_type AS attack_path_type,
       ac.total_steps AS total_steps,
       ac.successful_steps AS successful_steps,
       ac.failed_steps AS failed_steps,
       ac.phases_reached AS phases_reached,
       ac.final_outcome AS final_outcome,
       collect(DISTINCT {type: labels(target)[0],
                         value: CASE WHEN target:IP THEN target.address
                                     WHEN target:Subdomain THEN target.name
                                     WHEN target:CVE THEN target.id
                                     ELSE coalesce(target.name, target.id, 'unknown') END}) AS targets,
       count(DISTINCT cf) AS findings_count,
       count(DISTINCT fail) AS failures_count
""",
    },
    {
        "name": "certificates",
        "phase": "collecting_certificates",
        "description": "TLS certificate findings",
        "query": """
MATCH (cert:Certificate {user_id: $userId, project_id: $projectId})
OPTIONAL MATCH (bu:BaseURL)-[:HAS_CERTIFICATE]->(cert)
OPTIONAL MATCH (ip:IP)-[:HAS_CERTIFICATE]->(cert)
RETURN cert.subject_cn AS subject_cn,
       cert.issuer AS issuer,
       cert.not_before AS valid_from,
       cert.not_after AS expires,
       cert.san AS san,
       cert.key_type AS key_type,
       cert.key_bits AS key_bits,
       cert.signature_algorithm AS signature_algorithm,
       cert.self_signed AS self_signed,
       cert.source AS source,
       collect(DISTINCT bu.url) AS baseurl_urls,
       collect(DISTINCT ip.address) AS ip_addresses,
       CASE WHEN cert.not_after < datetime() THEN 'expired'
            WHEN cert.not_after < datetime() + duration('P30D') THEN 'expiring_soon'
            ELSE 'valid' END AS cert_status
""",
    },
    {
        "name": "security_checks",
        "phase": "collecting_security_checks",
        "description": "Security check vulnerabilities (missing headers, misconfigs)",
        "query": """
MATCH (v:Vulnerability {user_id: $userId, project_id: $projectId, source: 'security_check'})
OPTIONAL MATCH (bu:BaseURL)-[:HAS_VULNERABILITY]->(v)
RETURN v.id AS vuln_id, v.name AS name, v.severity AS severity,
       v.description AS description, v.category AS category,
       bu.url AS affected_url
""",
    },
]
