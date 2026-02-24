import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { readFile } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'

// Path to recon output directory (mounted volume or local path)
const RECON_OUTPUT_PATH = process.env.RECON_OUTPUT_PATH || '/home/samuele/Progetti didattici/RedAmon/recon/output'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const url = new URL(request.url)
    const format = url.searchParams.get('format') || 'json'

    // Verify project exists
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true, name: true, targetDomain: true }
    })

    if (!project) {
      return NextResponse.json(
        { error: 'Project not found' },
        { status: 404 }
      )
    }

    // Construct the JSON file path using projectId
    const jsonFileName = `recon_${projectId}.json`
    const jsonFilePath = path.join(RECON_OUTPUT_PATH, jsonFileName)

    // Check if file exists
    if (!existsSync(jsonFilePath)) {
      return NextResponse.json(
        { error: 'Recon data not found. Run a reconnaissance first.' },
        { status: 404 }
      )
    }

    // Read the file
    const fileContent = await readFile(jsonFilePath, 'utf-8')

    if (format === 'html') {
      // Generate HTML report
      const reconData = JSON.parse(fileContent)
      const htmlContent = generateSimpleReport(project, reconData)
      const timestamp = new Date().toISOString().split('T')[0]
      const filename = `RedAmon_Report_${project.name.replace(/[^a-zA-Z0-9]/g, '_')}_${timestamp}.html`

      return new NextResponse(htmlContent, {
        status: 200,
        headers: {
          'Content-Type': 'text/html',
          'Content-Disposition': `attachment; filename="${filename}"`,
          'Cache-Control': 'no-cache',
        },
      })
    }

    // Return as downloadable JSON (default)
    return new NextResponse(fileContent, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="${jsonFileName}"`,
        'Cache-Control': 'no-cache',
      },
    })

  } catch (error) {
    console.error('Error downloading recon data:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}

// Also support HEAD request to check if data exists
export async function HEAD(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params

    // Verify project exists
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true }
    })

    if (!project) {
      return new NextResponse(null, { status: 404 })
    }

    const jsonFilePath = path.join(RECON_OUTPUT_PATH, `recon_${projectId}.json`)

    if (!existsSync(jsonFilePath)) {
      return new NextResponse(null, { status: 404 })
    }

    return new NextResponse(null, { status: 200 })

  } catch {
    return new NextResponse(null, { status: 500 })
  }
}

function generateSimpleReport(project: any, reconData: any): string {
  const metadata = reconData.metadata || {}
  const whois = reconData.whois || {}
  const subdomains = reconData.subdomains || []
  const dnsData = reconData.dns || {}
  const httpProbeData = reconData.http_probe || {}
  const portScanData = reconData.port_scan || {}
  const resourceEnumData = reconData.resource_enum || {}
  const vulnScanData = reconData.vuln_scan || {}

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RedAmon Security Report - ${project.name}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; color: #333; }
    .header { text-align: center; border-bottom: 3px solid #2563eb; padding-bottom: 20px; margin-bottom: 40px; }
    .header h1 { color: #1e40af; margin: 0; font-size: 32px; }
    .header p { color: #6b7280; margin: 10px 0 0 0; }
    .section { margin-bottom: 40px; page-break-inside: avoid; }
    .section h2 { color: #1e40af; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; margin-bottom: 20px; }
    .section h3 { color: #374151; margin: 20px 0 10px 0; }
    .info-grid { display: grid; grid-template-columns: 200px 1fr; gap: 12px; margin: 20px 0; background: #f8fafc; padding: 20px; border-radius: 8px; }
    .info-label { font-weight: bold; color: #374151; }
    .info-value { color: #6b7280; }
    table { width: 100%; border-collapse: collapse; margin: 15px 0; background: white; }
    th, td { border: 1px solid #e5e7eb; padding: 12px 8px; text-align: left; vertical-align: top; }
    th { background-color: #f8fafc; font-weight: bold; color: #374151; }
    tr:nth-child(even) { background-color: #f9fafb; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
    .stat-card { background: #f8fafc; border: 1px solid #e5e7eb; border-radius: 8px; padding: 15px; text-align: center; }
    .stat-number { font-size: 24px; font-weight: bold; color: #1e40af; display: block; }
    .stat-label { color: #6b7280; font-size: 14px; margin-top: 5px; }
    .code { background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 90%; }
    .vuln-high { color: #dc2626; font-weight: bold; }
    .vuln-medium { color: #f59e0b; font-weight: bold; }
    .vuln-low { color: #10b981; font-weight: bold; }
    .domain-item { margin: 5px 0; padding: 5px; background: #f9fafb; border-radius: 4px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>RedAmon Security Assessment Report</h1>
    <p>Comprehensive Reconnaissance Analysis</p>
    <p>Generated on ${new Date().toLocaleString()}</p>
  </div>

  <!-- Executive Summary -->
  <div class="section">
    <h2>Executive Summary</h2>
    <div class="stats-grid">
      <div class="stat-card">
        <span class="stat-number">${subdomains.length}</span>
        <div class="stat-label">Subdomains Found</div>
      </div>
      <div class="stat-card">
        <span class="stat-number">${dnsData.domain ? Object.keys(dnsData.subdomains || {}).length + 1 : 0}</span>
        <div class="stat-label">DNS Records</div>
      </div>
      <div class="stat-card">
        <span class="stat-number">${httpProbeData.by_url ? Object.keys(httpProbeData.by_url).length : 0}</span>
        <div class="stat-label">Web Services</div>
      </div>
      <div class="stat-card">
        <span class="stat-number">${resourceEnumData.by_url ? Object.keys(resourceEnumData.by_url || {}).length : 0}</span>
        <div class="stat-label">Endpoints</div>
      </div>
      <div class="stat-card">
        <span class="stat-number">${vulnScanData.by_ip ? Object.keys(vulnScanData.by_ip || {}).length : 0}</span>
        <div class="stat-label">Vulnerabilities</div>
      </div>
    </div>
  </div>

  <!-- Project Information -->
  <div class="section">
    <h2>Project Information</h2>
    <div class="info-grid">
      <div class="info-label">Project Name:</div>
      <div class="info-value">${project.name}</div>
      <div class="info-label">Target Domain:</div>
      <div class="info-value">${project.targetDomain || metadata.target || 'N/A'}</div>
      <div class="info-label">Scan Date:</div>
      <div class="info-value">${metadata.scan_timestamp ? new Date(metadata.scan_timestamp).toLocaleString() : 'N/A'}</div>
      <div class="info-label">Scan Type:</div>
      <div class="info-value">${metadata.scan_type || 'N/A'}</div>
      <div class="info-label">Modules Executed:</div>
      <div class="info-value">${metadata.modules_executed ? metadata.modules_executed.join(', ') : 'N/A'}</div>
    </div>
  </div>

  <!-- WHOIS Information -->
  ${whois.domain_name ? `
  <div class="section">
    <h2>WHOIS Information</h2>
    <div class="info-grid">
      <div class="info-label">Domain Name:</div>
      <div class="info-value">${whois.domain_name}</div>
      <div class="info-label">Registrar:</div>
      <div class="info-value">${whois.registrar || 'N/A'}</div>
      <div class="info-label">Created:</div>
      <div class="info-value">${whois.creation_date ? new Date(whois.creation_date[0]).toLocaleDateString() : 'N/A'}</div>
      <div class="info-label">Expires:</div>
      <div class="info-value">${whois.expiration_date ? new Date(whois.expiration_date[0]).toLocaleDateString() : 'N/A'}</div>
      <div class="info-label">Name Servers:</div>
      <div class="info-value">${whois.name_servers ? whois.name_servers.join(', ') : 'N/A'}</div>
    </div>
  </div>
  ` : ''}

  <!-- Subdomains -->
  ${subdomains.length > 0 ? `
  <div class="section">
    <h2>Subdomain Discovery</h2>
    <p>Found ${subdomains.length} subdomains:</p>
    <table>
      <thead>
        <tr>
          <th>Subdomain</th>
          <th>IP Address</th>
          <th>Source</th>
        </tr>
      </thead>
      <tbody>
        ${subdomains.slice(0, 50).map((sub: any) => `
          <tr>
            <td class="code">${typeof sub === 'string' ? sub : (sub.subdomain || sub.name || 'N/A')}</td>
            <td class="code">${dnsData.subdomains && dnsData.subdomains[sub] ? (dnsData.subdomains[sub].ips?.ipv4?.join(', ') || 'N/A') : 'N/A'}</td>
            <td>Discovery</td>
          </tr>
        `).join('')}
        ${subdomains.length > 50 ? `<tr><td colspan="3" style="text-align: center; font-style: italic;">... and ${subdomains.length - 50} more subdomains</td></tr>` : ''}
      </tbody>
    </table>
  </div>
  ` : ''}

  <!-- HTTP Probe Results -->
  ${httpProbeData.by_url && Object.keys(httpProbeData.by_url).length > 0 ? `
  <div class="section">
    <h2>Web Services Discovery</h2>
    <table>
      <thead>
        <tr>
          <th>URL</th>
          <th>Status</th>
          <th>Title</th>
          <th>Server</th>
          <th>Content Type</th>
        </tr>
      </thead>
      <tbody>
        ${Object.entries(httpProbeData.by_url).slice(0, 30).map(([url, http]: [string, any]) => `
          <tr>
            <td class="code">${url}</td>
            <td>${http.status_code || 'N/A'}</td>
            <td>${http.title ? (http.title.length > 40 ? http.title.substring(0, 40) + '...' : http.title) : 'N/A'}</td>
            <td>${http.server || 'N/A'}</td>
            <td>${http.content_type || 'N/A'}</td>
          </tr>
        `).join('')}
        ${Object.keys(httpProbeData.by_url).length > 30 ? `<tr><td colspan="5" style="text-align: center; font-style: italic;">... and ${Object.keys(httpProbeData.by_url).length - 30} more web services</td></tr>` : ''}
      </tbody>
    </table>
  </div>
  ` : ''}

  <!-- Resource Enumeration -->
  ${resourceEnumData.by_url && Object.keys(resourceEnumData.by_url).length > 0 ? `
  <div class="section">
    <h2>Resource Enumeration</h2>
    ${(() => {
      const allEndpoints = [];
      for (const [url, data] of Object.entries(resourceEnumData.by_url)) {
        if (data && typeof data === 'object' && 'endpoints' in data && data.endpoints) {
          for (const [path, endpoint] of Object.entries(data.endpoints as Record<string, any>)) {
            allEndpoints.push({url, path, endpoint});
          }
        }
      }
      return `
      <p>Found ${allEndpoints.length} endpoints and resources:</p>
      <table>
        <thead>
          <tr>
            <th>Base URL</th>
            <th>Path</th>
            <th>Methods</th>
            <th>Parameters</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
          ${allEndpoints.slice(0, 50).map(({url, path, endpoint}) => `
            <tr>
              <td class="code">${url}</td>
              <td class="code">${path}</td>
              <td>${endpoint.methods ? endpoint.methods.join(', ') : 'GET'}</td>
              <td>${endpoint.parameter_count ? endpoint.parameter_count.total : 0}</td>
              <td>${endpoint.sources ? endpoint.sources.join(', ') : 'N/A'}</td>
            </tr>
          `).join('')}
          ${allEndpoints.length > 50 ? `<tr><td colspan="5" style="text-align: center; font-style: italic;">... and ${allEndpoints.length - 50} more endpoints</td></tr>` : ''}
        </tbody>
      </table>`;
    })()}
  </div>
  ` : ''}

  <!-- Vulnerability Scan Results -->
  ${vulnScanData.by_category && Object.keys(vulnScanData.by_category).length > 0 ? `
  <div class="section">
    <h2>Vulnerability Assessment</h2>
    ${(() => {
      const allVulns = [];
      for (const [category, vulns] of Object.entries(vulnScanData.by_category)) {
        if (Array.isArray(vulns)) {
          allVulns.push(...vulns.map(v => ({ ...v, category })));
        }
      }
      const criticalCount = vulnScanData.vulnerabilities?.critical || 0;
      const highCount = vulnScanData.vulnerabilities?.high || 0;
      const mediumCount = vulnScanData.vulnerabilities?.medium || 0;
      const lowCount = vulnScanData.vulnerabilities?.low || 0;
      const totalVulns = criticalCount + highCount + mediumCount + lowCount;

      return `
      <div class="stats-grid" style="margin: 20px 0;">
        <div class="stat-card">
          <span class="stat-number vuln-high">${criticalCount}</span>
          <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card">
          <span class="stat-number vuln-high">${highCount}</span>
          <div class="stat-label">High</div>
        </div>
        <div class="stat-card">
          <span class="stat-number vuln-medium">${mediumCount}</span>
          <div class="stat-label">Medium</div>
        </div>
        <div class="stat-card">
          <span class="stat-number vuln-low">${lowCount}</span>
          <div class="stat-label">Low</div>
        </div>
      </div>
      <p>Found ${totalVulns} potential vulnerabilities:</p>
      <table>
        <thead>
          <tr>
            <th>Vulnerability</th>
            <th>Category</th>
            <th>Target</th>
            <th>Matched At</th>
          </tr>
        </thead>
        <tbody>
          ${allVulns.slice(0, 30).map((vuln) => `
            <tr>
              <td>${vuln.name || 'Unknown Vulnerability'}</td>
              <td class="vuln-high">${vuln.category?.toUpperCase() || 'Unknown'}</td>
              <td class="code">${vuln.target || 'N/A'}</td>
              <td class="code" style="font-size: 90%; word-break: break-all;">${vuln.matched_at ? (vuln.matched_at.length > 60 ? vuln.matched_at.substring(0, 60) + '...' : vuln.matched_at) : 'N/A'}</td>
            </tr>
          `).join('')}
          ${allVulns.length > 30 ? `<tr><td colspan="4" style="text-align: center; font-style: italic;">... and ${allVulns.length - 30} more vulnerabilities</td></tr>` : ''}
        </tbody>
      </table>`;
    })()}
  </div>
  ` : ''}

  <!-- DNS Records Summary -->
  ${dnsData.domain ? `
  <div class="section">
    <h2>DNS Records Summary</h2>
    <h3>Root Domain</h3>
    <div class="info-grid">
      <div class="info-label">A Records:</div>
      <div class="info-value">${dnsData.domain.records?.A ? dnsData.domain.records.A.join(', ') : 'None'}</div>
      <div class="info-label">MX Records:</div>
      <div class="info-value">${dnsData.domain.records?.MX ? dnsData.domain.records.MX.join(', ') : 'None'}</div>
      <div class="info-label">NS Records:</div>
      <div class="info-value">${dnsData.domain.records?.NS ? dnsData.domain.records.NS.join(', ') : 'None'}</div>
      <div class="info-label">TXT Records:</div>
      <div class="info-value">${dnsData.domain.records?.TXT ? dnsData.domain.records.TXT.join(', ') : 'None'}</div>
    </div>
  </div>
  ` : ''}

  <!-- Scan Statistics -->
  <div class="section">
    <h2>Scan Statistics</h2>
    ${metadata.graph_db_stats ? `
    <h3>Graph Database Statistics</h3>
    <div class="info-grid">
      <div class="info-label">Subdomains Created:</div>
      <div class="info-value">${metadata.graph_db_stats.subdomains_created || 0}</div>
      <div class="info-label">IPs Created:</div>
      <div class="info-value">${metadata.graph_db_stats.ips_created || 0}</div>
      <div class="info-label">DNS Records:</div>
      <div class="info-value">${metadata.graph_db_stats.dns_records_created || 0}</div>
      <div class="info-label">Relationships:</div>
      <div class="info-value">${metadata.graph_db_stats.relationships_created || 0}</div>
    </div>
    ` : ''}

    ${metadata.graph_db_vuln_scan_stats ? `
    <h3>Vulnerability Scan Statistics</h3>
    <div class="info-grid">
      <div class="info-label">Endpoints Scanned:</div>
      <div class="info-value">${metadata.graph_db_vuln_scan_stats.endpoints_created || 0}</div>
      <div class="info-label">Vulnerabilities Found:</div>
      <div class="info-value">${metadata.graph_db_vuln_scan_stats.vulnerabilities_created || 0}</div>
      <div class="info-label">Parameters Found:</div>
      <div class="info-value">${metadata.graph_db_vuln_scan_stats.parameters_created || 0}</div>
    </div>
    ` : ''}
  </div>

  <!-- Footer -->
  <div style="border-top: 2px solid #e5e7eb; padding-top: 20px; text-align: center; color: #6b7280; font-size: 14px; margin-top: 40px;">
    <p>Generated by RedAmon Security Assessment Platform</p>
    <p>Report contains reconnaissance data for ${project.name} (${project.targetDomain || reconData.domain})</p>
    <p>For detailed analysis and further investigation, use the RedAmon dashboard</p>
  </div>
</body>
</html>
  `
}
