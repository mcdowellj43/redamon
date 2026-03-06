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
      select: { id: true, name: true }
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
      // Parse JSON and generate HTML report
      const reconData = JSON.parse(fileContent)
      const htmlContent = generateSimpleReport(project, reconData)
      const filename = `recon_${project.name || projectId}_report.html`

      return new NextResponse(htmlContent, {
        status: 200,
        headers: {
          'Content-Type': 'text/html',
          'Content-Disposition': `attachment; filename="${filename}"`,
          'Cache-Control': 'no-cache',
        },
      })
    }

    // Return as downloadable JSON
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
  const projectName = project.name || 'Unknown Project'
  const generatedDate = new Date().toLocaleString()

  // Helper functions to safely extract data
  const getSubdomains = () => {
    const subdomains = reconData.subdomains || []
    return Array.isArray(subdomains) ? subdomains : []
  }

  const getHttpProbe = () => {
    const httpProbe = reconData.http_probe || {}
    return Array.isArray(httpProbe) ? httpProbe : []
  }

  const getVulnScan = () => {
    const vulnScan = reconData.vuln_scan || {}
    if (typeof vulnScan === 'object' && vulnScan.endpoints) {
      return vulnScan.endpoints || []
    }
    return []
  }

  const getPortScan = () => {
    const portScan = reconData.port_scan || {}
    return Array.isArray(portScan) ? portScan : []
  }

  const getWhoisInfo = () => {
    return reconData.whois || {}
  }

  // Count statistics
  const subdomainCount = getSubdomains().length
  const dnsCount = reconData.dns ? (Array.isArray(reconData.dns) ? reconData.dns.length : Object.keys(reconData.dns).length) : 0
  const webServiceCount = getHttpProbe().length
  const endpointCount = getVulnScan().length
  const vulnCount = getVulnScan().reduce((count: number, endpoint: any) => {
    return count + (endpoint.vulnerabilities ? endpoint.vulnerabilities.length : 0)
  }, 0)

  // Graph DB statistics
  const graphStats = reconData.graph_db_statistics || {}

  // Vulnerability scan statistics
  const vulnStats = reconData.vulnerability_scan_statistics || {}

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RedAmon Security Report - ${projectName}</title>
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
    <p>Generated on ${generatedDate}</p>
  </div>

  <!-- Executive Summary -->
  <div class="section">
    <h2>Executive Summary</h2>
    <div class="stats-grid">
      <div class="stat-card">
        <span class="stat-number">${subdomainCount}</span>
        <div class="stat-label">Subdomains Found</div>
      </div>
      <div class="stat-card">
        <span class="stat-number">${dnsCount}</span>
        <div class="stat-label">DNS Records</div>
      </div>
      <div class="stat-card">
        <span class="stat-number">${webServiceCount}</span>
        <div class="stat-label">Web Services</div>
      </div>
      <div class="stat-card">
        <span class="stat-number">${endpointCount}</span>
        <div class="stat-label">Endpoints</div>
      </div>
      <div class="stat-card">
        <span class="stat-number">${vulnCount}</span>
        <div class="stat-label">Vulnerabilities</div>
      </div>
    </div>
  </div>

  <!-- Project Information -->
  <div class="section">
    <h2>Project Information</h2>
    <div class="info-grid">
      <div class="info-label">Project Name:</div>
      <div class="info-value">${projectName}</div>
      <div class="info-label">Target Domain:</div>
      <div class="info-value">${reconData.metadata?.target_domain || 'N/A'}</div>
      <div class="info-label">Scan Date:</div>
      <div class="info-value">${reconData.metadata?.scan_date || 'N/A'}</div>
      <div class="info-label">Scan Type:</div>
      <div class="info-value">${reconData.metadata?.scan_type || 'N/A'}</div>
      <div class="info-label">Modules Executed:</div>
      <div class="info-value">${reconData.metadata?.modules_executed?.join(', ') || 'N/A'}</div>
    </div>
  </div>

  <!-- WHOIS Information -->
  ${Object.keys(getWhoisInfo()).length > 0 ? `
  <div class="section">
    <h2>WHOIS Information</h2>
    <div class="info-grid">
      <div class="info-label">Domain Name:</div>
      <div class="info-value">${getWhoisInfo().domain_name || 'N/A'}</div>
      <div class="info-label">Registrar:</div>
      <div class="info-value">${getWhoisInfo().registrar || 'N/A'}</div>
      <div class="info-label">Created:</div>
      <div class="info-value">${getWhoisInfo().creation_date || 'N/A'}</div>
      <div class="info-label">Expires:</div>
      <div class="info-value">${getWhoisInfo().expiration_date || 'N/A'}</div>
      <div class="info-label">Name Servers:</div>
      <div class="info-value">${getWhoisInfo().name_servers?.join(', ') || 'N/A'}</div>
    </div>
  </div>
  ` : ''}

  <!-- Subdomains -->
  ${subdomainCount > 0 ? `
  <div class="section">
    <h2>Subdomain Discovery</h2>
    <p>Found ${subdomainCount} subdomains:</p>
    <table>
      <thead>
        <tr>
          <th>Subdomain</th>
          <th>IP Address</th>
          <th>Source</th>
        </tr>
      </thead>
      <tbody>
        ${getSubdomains().map((subdomain: any) => `
          <tr>
            <td class="code">${subdomain.subdomain || 'N/A'}</td>
            <td class="code">${subdomain.ip || 'N/A'}</td>
            <td>${subdomain.source || 'N/A'}</td>
          </tr>
        `).join('')}

      </tbody>
    </table>
  </div>
  ` : ''}

  <!-- HTTP Probe Results -->
  ${webServiceCount > 0 ? `
  <div class="section">
    <h2>HTTP Probe Results</h2>
    <p>Found ${webServiceCount} web services:</p>
    <table>
      <thead>
        <tr>
          <th>URL</th>
          <th>Status</th>
          <th>Title</th>
          <th>Technology</th>
        </tr>
      </thead>
      <tbody>
        ${getHttpProbe().map((probe: any) => `
          <tr>
            <td class="code">${probe.url || 'N/A'}</td>
            <td>${probe.status_code || 'N/A'}</td>
            <td>${probe.title || 'N/A'}</td>
            <td>${probe.tech?.join(', ') || 'N/A'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>
  ` : ''}

  <!-- Resource Enumeration -->
  ${endpointCount > 0 ? `
  <div class="section">
    <h2>Resource Enumeration</h2>
    <p>Found ${endpointCount} endpoints:</p>
    <table>
      <thead>
        <tr>
          <th>Endpoint</th>
          <th>Status</th>
          <th>Length</th>
          <th>Vulnerabilities</th>
        </tr>
      </thead>
      <tbody>
        ${getVulnScan().map((endpoint: any) => `
          <tr>
            <td class="code">${endpoint.endpoint || 'N/A'}</td>
            <td>${endpoint.status || 'N/A'}</td>
            <td>${endpoint.length || 'N/A'}</td>
            <td>${endpoint.vulnerabilities?.length || 0} found</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>
  ` : ''}

  <!-- Vulnerability Scan Results -->
  ${vulnCount > 0 ? `
  <div class="section">
    <h2>Vulnerability Scan Results</h2>
    <p>Found ${vulnCount} vulnerabilities across ${endpointCount} endpoints:</p>
    ${getVulnScan().filter((endpoint: any) => endpoint.vulnerabilities?.length > 0).map((endpoint: any) => `
      <h3>${endpoint.endpoint}</h3>
      <table>
        <thead>
          <tr>
            <th>Template ID</th>
            <th>Severity</th>
            <th>Name</th>
            <th>Matched At</th>
          </tr>
        </thead>
        <tbody>
          ${endpoint.vulnerabilities.map((vuln: any) => `
            <tr>
              <td class="code">${vuln.template_id || 'N/A'}</td>
              <td><span class="vuln-${vuln.severity}">${vuln.severity || 'N/A'}</span></td>
              <td>${vuln.name || 'N/A'}</td>
              <td class="code">${vuln.matched_at || 'N/A'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `).join('')}
  </div>
  ` : ''}

  <!-- Port Scan Results -->
  ${getPortScan().length > 0 ? `
  <div class="section">
    <h2>Port Scan Results</h2>
    <table>
      <thead>
        <tr>
          <th>Host</th>
          <th>Port</th>
          <th>Service</th>
          <th>State</th>
        </tr>
      </thead>
      <tbody>
        ${getPortScan().map((port: any) => `
          <tr>
            <td class="code">${port.host || 'N/A'}</td>
            <td class="code">${port.port || 'N/A'}</td>
            <td>${port.service || 'N/A'}</td>
            <td>${port.state || 'N/A'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>
  ` : ''}

  <!-- Scan Statistics -->
  <div class="section">
    <h2>Scan Statistics</h2>

    <h3>Graph Database Statistics</h3>
    <div class="info-grid">
      <div class="info-label">Subdomains Created:</div>
      <div class="info-value">${graphStats.subdomains_created || 'N/A'}</div>
      <div class="info-label">IPs Created:</div>
      <div class="info-value">${graphStats.ips_created || 'N/A'}</div>
      <div class="info-label">DNS Records:</div>
      <div class="info-value">${graphStats.dns_records || 'N/A'}</div>
      <div class="info-label">Relationships:</div>
      <div class="info-value">${graphStats.relationships || 'N/A'}</div>
    </div>

    ${Object.keys(vulnStats).length > 0 ? `
    <h3>Vulnerability Scan Statistics</h3>
    <div class="info-grid">
      <div class="info-label">Endpoints Scanned:</div>
      <div class="info-value">${vulnStats.endpoints_scanned || 'N/A'}</div>
      <div class="info-label">Vulnerabilities Found:</div>
      <div class="info-value">${vulnStats.vulnerabilities_found || 'N/A'}</div>
      <div class="info-label">Parameters Found:</div>
      <div class="info-value">${vulnStats.parameters_found || 'N/A'}</div>
    </div>
    ` : ''}
  </div>

  <!-- Footer -->
  <div style="border-top: 2px solid #e5e7eb; padding-top: 20px; text-align: center; color: #6b7280; font-size: 14px; margin-top: 40px;">
    <p>Generated by RedAmon Security Assessment Platform</p>
    <p>Report contains reconnaissance data for ${projectName} (${reconData.metadata?.target_domain || 'N/A'})</p>
    <p>For detailed analysis and further investigation, use the RedAmon dashboard</p>
  </div>
</body>
</html>
  `

  return html
}
