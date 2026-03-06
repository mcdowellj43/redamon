'use client'

import { useState, useRef, useCallback, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { GraphToolbar } from './components/GraphToolbar'
import { GraphCanvas } from './components/GraphCanvas'
import { NodeDrawer } from './components/NodeDrawer'
import { AIAssistantDrawer } from './components/AIAssistantDrawer'
import { PageBottomBar } from './components/PageBottomBar'
import { ReconConfirmModal } from './components/ReconConfirmModal'
import { GvmConfirmModal } from './components/GvmConfirmModal'
import { ReconLogsDrawer } from './components/ReconLogsDrawer'
import { ViewTabs, type ViewMode, type TunnelStatus } from './components/ViewTabs'
import { DataTable } from './components/DataTable'
import { ActiveSessions } from './components/ActiveSessions'
import { useGraphData, useDimensions, useNodeSelection, useTableData } from './hooks'
import { exportToExcel } from './utils/exportExcel'
import { useTheme, useSession, useReconStatus, useReconSSE, useGvmStatus, useGvmSSE, useGithubHuntStatus, useGithubHuntSSE, useActiveSessions } from '@/hooks'
import { useProject } from '@/providers/ProjectProvider'
import { GVM_PHASES, GITHUB_HUNT_PHASES } from '@/lib/recon-types'
import styles from './page.module.css'

export default function GraphPage() {
  const router = useRouter()
  const { projectId, userId, currentProject, setCurrentProject, isLoading: projectLoading } = useProject()

  const [is3D, setIs3D] = useState(true)
  const [showLabels, setShowLabels] = useState(true)
  const [activeView, setActiveView] = useState<ViewMode>('graph')
  const [isAIOpen, setIsAIOpen] = useState(false)
  const [isReconModalOpen, setIsReconModalOpen] = useState(false)
  const [activeLogsDrawer, setActiveLogsDrawer] = useState<'recon' | 'gvm' | 'githubHunt' | null>(null)
  const [hasReconData, setHasReconData] = useState(false)
  const [hasGvmData, setHasGvmData] = useState(false)
  const [hasGithubHuntData, setHasGithubHuntData] = useState(false)
  const [hasPDFData, setHasPDFData] = useState(false)
  const [graphStats, setGraphStats] = useState<{ totalNodes: number; nodesByType: Record<string, number> } | null>(null)
  const [gvmStats, setGvmStats] = useState<{ totalGvmNodes: number; nodesByType: Record<string, number> } | null>(null)
  const [isGvmModalOpen, setIsGvmModalOpen] = useState(false)
  const contentRef = useRef<HTMLDivElement>(null)
  const bodyRef = useRef<HTMLDivElement>(null)

  const { selectedNode, drawerOpen, selectNode, clearSelection } = useNodeSelection()
  const dimensions = useDimensions(contentRef)

  // Track .body position for fixed-position log drawers
  useEffect(() => {
    const body = bodyRef.current
    if (!body) return
    const update = () => {
      const rect = body.getBoundingClientRect()
      document.documentElement.style.setProperty('--drawer-top', `${rect.top}px`)
      document.documentElement.style.setProperty('--drawer-bottom', `${window.innerHeight - rect.bottom}px`)
    }
    update()
    const ro = new ResizeObserver(update)
    ro.observe(body)
    window.addEventListener('resize', update)
    return () => { ro.disconnect(); window.removeEventListener('resize', update) }
  }, [])
  const { isDark } = useTheme()
  const { sessionId, resetSession } = useSession()

  // Tunnel status polling — check every 10s which tunnels are active
  const [tunnelStatus, setTunnelStatus] = useState<TunnelStatus>()

  useEffect(() => {
    const fetchTunnels = async () => {
      try {
        const res = await fetch('/api/agent/tunnel-status')
        if (res.ok) setTunnelStatus(await res.json())
      } catch { /* ignore */ }
    }
    fetchTunnels()
    const interval = setInterval(fetchTunnels, 10000)
    return () => clearInterval(interval)
  }, [])

  // Recon status hook - must be before useGraphData to provide isReconRunning
  const {
    state: reconState,
    isLoading: isReconLoading,
    startRecon,
    stopRecon,
    pauseRecon,
    resumeRecon,
  } = useReconStatus({
    projectId,
    enabled: !!projectId,
  })

  // Check if recon is running to enable auto-refresh of graph data
  const isReconRunning = reconState?.status === 'running' || reconState?.status === 'starting'

  // Graph data with auto-refresh every 5 seconds while recon is running
  const { data, isLoading, error, refetch: refetchGraph } = useGraphData(projectId, {
    isReconRunning,
  })

  // Recon logs SSE hook
  const {
    logs: reconLogs,
    currentPhase,
    currentPhaseNumber,
    clearLogs,
  } = useReconSSE({
    projectId,
    enabled: reconState?.status === 'running' || reconState?.status === 'starting' || reconState?.status === 'paused' || reconState?.status === 'stopping',
  })

  // GVM status hook
  const {
    state: gvmState,
    isLoading: isGvmLoading,
    error: gvmError,
    startGvm,
    stopGvm,
    pauseGvm,
    resumeGvm,
  } = useGvmStatus({
    projectId,
    enabled: !!projectId,
  })

  const isGvmRunning = gvmState?.status === 'running' || gvmState?.status === 'starting'

  // GVM logs SSE hook
  const {
    logs: gvmLogs,
    currentPhase: gvmCurrentPhase,
    currentPhaseNumber: gvmCurrentPhaseNumber,
    clearLogs: clearGvmLogs,
  } = useGvmSSE({
    projectId,
    enabled: gvmState?.status === 'running' || gvmState?.status === 'starting' || gvmState?.status === 'paused' || gvmState?.status === 'stopping',
  })

  // GitHub Hunt status hook
  const {
    state: githubHuntState,
    isLoading: isGithubHuntLoading,
    startGithubHunt,
    stopGithubHunt,
    pauseGithubHunt,
    resumeGithubHunt,
  } = useGithubHuntStatus({
    projectId,
    enabled: !!projectId,
  })

  const isGithubHuntRunning = githubHuntState?.status === 'running' || githubHuntState?.status === 'starting'

  // GitHub Hunt logs SSE hook
  const {
    logs: githubHuntLogs,
    currentPhase: githubHuntCurrentPhase,
    currentPhaseNumber: githubHuntCurrentPhaseNumber,
    clearLogs: clearGithubHuntLogs,
  } = useGithubHuntSSE({
    projectId,
    enabled: githubHuntState?.status === 'running' || githubHuntState?.status === 'starting' || githubHuntState?.status === 'paused' || githubHuntState?.status === 'stopping',
  })

  // Active sessions hook — polls kali-sandbox session list
  const activeSessions = useActiveSessions({
    enabled: true,
    fastPoll: activeView === 'sessions',
  })

  // Check if recon data exists
  const checkReconData = useCallback(async () => {
    if (!projectId) return
    try {
      const response = await fetch(`/api/recon/${projectId}/download`, { method: 'HEAD' })
      setHasReconData(response.ok)
    } catch {
      setHasReconData(false)
    }
  }, [projectId])

  // Calculate graph stats when data changes
  useEffect(() => {
    if (data?.nodes) {
      const nodesByType: Record<string, number> = {}
      data.nodes.forEach(node => {
        const type = node.type || 'Unknown'
        nodesByType[type] = (nodesByType[type] || 0) + 1
      })
      setGraphStats({
        totalNodes: data.nodes.length,
        nodesByType,
      })
    } else {
      setGraphStats(null)
    }
  }, [data])

  // Calculate GVM-specific stats from graph data
  useEffect(() => {
    if (data?.nodes) {
      const gvmTypes: Record<string, number> = {}
      let total = 0
      data.nodes.forEach(node => {
        const isGvmVuln = node.type === 'Vulnerability' && node.properties?.source === 'gvm'
        const isGvmTech = node.type === 'Technology' && (node.properties?.detected_by as string[] | undefined)?.includes('gvm')
        if (isGvmVuln || isGvmTech) {
          const type = node.type || 'Unknown'
          gvmTypes[type] = (gvmTypes[type] || 0) + 1
          total++
        }
      })
      setGvmStats(total > 0 ? { totalGvmNodes: total, nodesByType: gvmTypes } : null)
    } else {
      setGvmStats(null)
    }
  }, [data])

  // Check if GVM data exists
  const checkGvmData = useCallback(async () => {
    if (!projectId) return
    try {
      const response = await fetch(`/api/gvm/${projectId}/download`, { method: 'HEAD' })
      setHasGvmData(response.ok)
    } catch {
      setHasGvmData(false)
    }
  }, [projectId])

  // Check if GitHub Hunt data exists
  const checkGithubHuntData = useCallback(async () => {
    if (!projectId) return
    try {
      const response = await fetch(`/api/github-hunt/${projectId}/download`, { method: 'HEAD' })
      setHasGithubHuntData(response.ok)
    } catch {
      setHasGithubHuntData(false)
    }
  }, [projectId])

  // Check if PDF report data exists
  const checkPDFData = useCallback(async () => {
    if (!projectId) return
    try {
      const response = await fetch(`/api/reports/${projectId}/data`, { method: 'HEAD' })
      setHasPDFData(response.ok)
    } catch {
      setHasPDFData(false)
    }
  }, [projectId])

  // Check for recon/GVM/GitHub Hunt/PDF data on mount and when project changes
  useEffect(() => {
    checkReconData()
    checkGvmData()
    checkGithubHuntData()
    checkPDFData()
  }, [checkReconData, checkGvmData, checkGithubHuntData, checkPDFData])

  // Refresh graph data when recon completes
  useEffect(() => {
    if (reconState?.status === 'completed' || reconState?.status === 'error') {
      refetchGraph()
      checkReconData()
      checkPDFData()
    }
  }, [reconState?.status, refetchGraph, checkReconData, checkPDFData])

  // Refresh graph when GVM scan completes
  useEffect(() => {
    if (gvmState?.status === 'completed' || gvmState?.status === 'error') {
      refetchGraph()
      checkGvmData()
      checkPDFData()
    }
  }, [gvmState?.status, refetchGraph, checkGvmData, checkPDFData])

  // Refresh when GitHub Hunt completes
  useEffect(() => {
    if (githubHuntState?.status === 'completed' || githubHuntState?.status === 'error') {
      refetchGraph()
      checkGithubHuntData()
      checkPDFData()
    }
  }, [githubHuntState?.status, refetchGraph, checkGithubHuntData, checkPDFData])

  const handleToggleAI = useCallback(() => {
    setIsAIOpen((prev) => !prev)
  }, [])

  const handleCloseAI = useCallback(() => {
    setIsAIOpen(false)
  }, [])

  const handleToggleStealth = useCallback(async (newValue: boolean) => {
    if (!projectId) return
    try {
      const res = await fetch(`/api/projects/${projectId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ stealthMode: newValue }),
      })
      if (res.ok && currentProject) {
        setCurrentProject({ ...currentProject, stealthMode: newValue })
      }
    } catch (error) {
      console.error('Failed to toggle stealth mode:', error)
    }
  }, [projectId, currentProject, setCurrentProject])

  const handleStartRecon = useCallback(() => {
    setIsReconModalOpen(true)
  }, [])

  const handleConfirmRecon = useCallback(async () => {
    clearLogs()
    const result = await startRecon()
    if (result) {
      setIsReconModalOpen(false)
      setActiveLogsDrawer('recon')
    }
  }, [startRecon, clearLogs])

  const handleDownloadJSON = useCallback(async () => {
    if (!projectId) return
    window.open(`/api/recon/${projectId}/download`, '_blank')
  }, [projectId])

  const handleDeleteNode = useCallback(async (nodeId: string) => {
    if (!projectId) return
    const res = await fetch(`/api/graph?nodeId=${nodeId}&projectId=${projectId}`, {
      method: 'DELETE',
    })
    if (!res.ok) {
      const data = await res.json()
      alert(data.error || 'Failed to delete node')
      return
    }
    refetchGraph()
  }, [projectId, refetchGraph])

  const handleToggleLogs = useCallback(() => {
    setActiveLogsDrawer(prev => prev === 'recon' ? null : 'recon')
  }, [])

  const handleStartGvm = useCallback(() => {
    setIsGvmModalOpen(true)
  }, [])

  const handleConfirmGvm = useCallback(async () => {
    clearGvmLogs()
    const result = await startGvm()
    if (result) {
      setIsGvmModalOpen(false)
      setActiveLogsDrawer('gvm')
    }
  }, [startGvm, clearGvmLogs])

  const handleDownloadGvmJSON = useCallback(async () => {
    if (!projectId) return
    window.open(`/api/gvm/${projectId}/download`, '_blank')
  }, [projectId])

  const handleToggleGvmLogs = useCallback(() => {
    setActiveLogsDrawer(prev => prev === 'gvm' ? null : 'gvm')
  }, [])

  const handleStartGithubHunt = useCallback(async () => {
    clearGithubHuntLogs()
    const result = await startGithubHunt()
    if (result) {
      setActiveLogsDrawer('githubHunt')
    }
  }, [startGithubHunt, clearGithubHuntLogs])

  const handleDownloadGithubHuntJSON = useCallback(async () => {
    if (!projectId) return
    window.open(`/api/github-hunt/${projectId}/download`, '_blank')
  }, [projectId])

  const handleToggleGithubHuntLogs = useCallback(() => {
    setActiveLogsDrawer(prev => prev === 'githubHunt' ? null : 'githubHunt')
  }, [])

<<<<<<< Updated upstream
  // Pause/Resume/Stop handlers
  const handlePauseRecon = useCallback(async () => { await pauseRecon() }, [pauseRecon])
  const handleResumeRecon = useCallback(async () => { await resumeRecon() }, [resumeRecon])
  const handleStopRecon = useCallback(async () => { await stopRecon() }, [stopRecon])
  const handlePauseGvm = useCallback(async () => { await pauseGvm() }, [pauseGvm])
  const handleResumeGvm = useCallback(async () => { await resumeGvm() }, [resumeGvm])
  const handleStopGvm = useCallback(async () => { await stopGvm() }, [stopGvm])
  const handlePauseGithubHunt = useCallback(async () => { await pauseGithubHunt() }, [pauseGithubHunt])
  const handleResumeGithubHunt = useCallback(async () => { await resumeGithubHunt() }, [resumeGithubHunt])
  const handleStopGithubHunt = useCallback(async () => { await stopGithubHunt() }, [stopGithubHunt])
=======
  const handleDownloadPDFReport = useCallback(async () => {
    if (!projectId) return
    window.open(`/api/reports/${projectId}/pdf`, '_blank')
  }, [projectId])
>>>>>>> Stashed changes

  // Show message if no project is selected
  if (!projectLoading && !projectId) {
    return (
      <div className={styles.page}>
        <div className={styles.noProject}>
          <h2>No Project Selected</h2>
          <p>Select a project from the dropdown in the header or create a new one.</p>
          <button className="primaryButton" onClick={() => router.push('/projects')}>
            Go to Projects
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      <GraphToolbar
        projectId={projectId || ''}
        is3D={is3D}
        showLabels={showLabels}
        onToggle3D={setIs3D}
        onToggleLabels={setShowLabels}
        onToggleAI={handleToggleAI}
        isAIOpen={isAIOpen}
        // Target info
        targetDomain={currentProject?.targetDomain}
        subdomainList={currentProject?.subdomainList}
        // Recon props
        onStartRecon={handleStartRecon}
        onPauseRecon={handlePauseRecon}
        onResumeRecon={handleResumeRecon}
        onStopRecon={handleStopRecon}
        onDownloadJSON={handleDownloadJSON}
        onToggleLogs={handleToggleLogs}
        reconStatus={reconState?.status || 'idle'}
        hasReconData={hasReconData}
        isLogsOpen={activeLogsDrawer === 'recon'}
        // GVM props
        onStartGvm={handleStartGvm}
        onPauseGvm={handlePauseGvm}
        onResumeGvm={handleResumeGvm}
        onStopGvm={handleStopGvm}
        onDownloadGvmJSON={handleDownloadGvmJSON}
        onToggleGvmLogs={handleToggleGvmLogs}
        gvmStatus={gvmState?.status || 'idle'}
        hasGvmData={hasGvmData}
        isGvmLogsOpen={activeLogsDrawer === 'gvm'}
        // GitHub Hunt props
        onStartGithubHunt={handleStartGithubHunt}
        onPauseGithubHunt={handlePauseGithubHunt}
        onResumeGithubHunt={handleResumeGithubHunt}
        onStopGithubHunt={handleStopGithubHunt}
        onDownloadGithubHuntJSON={handleDownloadGithubHuntJSON}
        onToggleGithubHuntLogs={handleToggleGithubHuntLogs}
        githubHuntStatus={githubHuntState?.status || 'idle'}
        hasGithubHuntData={hasGithubHuntData}
        isGithubHuntLogsOpen={activeLogsDrawer === 'githubHunt'}
        // PDF Report
        onDownloadPDFReport={handleDownloadPDFReport}
        hasPDFData={hasPDFData}
        // Stealth mode
        stealthMode={currentProject?.stealthMode}
<<<<<<< Updated upstream
        // Agent status
        agentActiveCount={agentSummary.activeCount}
        agentConversations={agentSummary.conversations}
      />

      <ViewTabs
        activeView={activeView}
        onViewChange={setActiveView}
        globalFilter={globalFilter}
        onGlobalFilterChange={setGlobalFilter}
        onExport={handleExportExcel}
        totalRows={filteredByType.length}
        filteredRows={textFilteredCount}
        sessionCount={activeSessions.totalCount}
        tunnelStatus={tunnelStatus}
=======
>>>>>>> Stashed changes
      />

      <div ref={bodyRef} className={styles.body}>
        <NodeDrawer
          node={selectedNode}
          isOpen={drawerOpen}
          onClose={clearSelection}
          onDeleteNode={handleDeleteNode}
        />

        <div ref={contentRef} className={styles.content}>
<<<<<<< Updated upstream
          {activeView === 'graph' ? (
            <GraphCanvas
              data={filteredGraphData}
              isLoading={isLoading}
              error={error}
              projectId={projectId || ''}
              is3D={is3D}
              width={dimensions.width}
              height={dimensions.height}
              showLabels={showLabels}
              selectedNode={selectedNode}
              onNodeClick={selectNode}
              isDark={isDark}
              activeChainId={sessionId}
            />
          ) : activeView === 'table' ? (
            <DataTable
              data={data}
              isLoading={isLoading}
              error={error}
              rows={filteredByType}
              globalFilter={globalFilter}
              onGlobalFilterChange={setGlobalFilter}
            />
          ) : (
            <ActiveSessions
              sessions={activeSessions.sessions}
              jobs={activeSessions.jobs}
              nonMsfSessions={activeSessions.nonMsfSessions}
              agentBusy={activeSessions.agentBusy}
              isLoading={activeSessions.isLoading}
              projectId={projectId || ''}
              onInteract={activeSessions.interactWithSession}
              onKillSession={activeSessions.killSession}
              onKillJob={activeSessions.killJob}
            />
          )}
=======
          <GraphCanvas
            data={data}
            isLoading={isLoading}
            error={error}
            projectId={projectId || ''}
            is3D={is3D}
            width={dimensions.width}
            height={dimensions.height}
            showLabels={showLabels}
            selectedNode={selectedNode}
            onNodeClick={selectNode}
            isDark={isDark}
          />
>>>>>>> Stashed changes
        </div>

      </div>

      <ReconLogsDrawer
        isOpen={activeLogsDrawer === 'recon'}
        onClose={() => setActiveLogsDrawer(null)}
        logs={reconLogs}
        currentPhase={currentPhase}
        currentPhaseNumber={currentPhaseNumber}
        status={reconState?.status || 'idle'}
        onClearLogs={clearLogs}
        onPause={handlePauseRecon}
        onResume={handleResumeRecon}
        onStop={handleStopRecon}
      />

      <ReconLogsDrawer
        isOpen={activeLogsDrawer === 'gvm'}
        onClose={() => setActiveLogsDrawer(null)}
        logs={gvmLogs}
        currentPhase={gvmCurrentPhase}
        currentPhaseNumber={gvmCurrentPhaseNumber}
        status={gvmState?.status || 'idle'}
        onClearLogs={clearGvmLogs}
        onPause={handlePauseGvm}
        onResume={handleResumeGvm}
        onStop={handleStopGvm}
        title="GVM Vulnerability Scan Logs"
        phases={GVM_PHASES}
        totalPhases={4}
      />

      <ReconLogsDrawer
        isOpen={activeLogsDrawer === 'githubHunt'}
        onClose={() => setActiveLogsDrawer(null)}
        logs={githubHuntLogs}
        currentPhase={githubHuntCurrentPhase}
        currentPhaseNumber={githubHuntCurrentPhaseNumber}
        status={githubHuntState?.status || 'idle'}
        onClearLogs={clearGithubHuntLogs}
        onPause={handlePauseGithubHunt}
        onResume={handleResumeGithubHunt}
        onStop={handleStopGithubHunt}
        title="GitHub Secret Hunt Logs"
        phases={GITHUB_HUNT_PHASES}
        totalPhases={3}
      />

      <AIAssistantDrawer
        isOpen={isAIOpen}
        onClose={handleCloseAI}
        userId={userId || ''}
        projectId={projectId || ''}
        sessionId={sessionId || ''}
        onResetSession={resetSession}
        modelName={currentProject?.agentOpenaiModel}
        toolPhaseMap={currentProject?.agentToolPhaseMap}
        stealthMode={currentProject?.stealthMode}
        onToggleStealth={handleToggleStealth}
      />

      <ReconConfirmModal
        isOpen={isReconModalOpen}
        onClose={() => setIsReconModalOpen(false)}
        onConfirm={handleConfirmRecon}
        projectName={currentProject?.name || 'Unknown'}
        targetDomain={currentProject?.targetDomain || 'Unknown'}
        ipMode={currentProject?.ipMode}
        targetIps={currentProject?.targetIps}
        stats={graphStats}
        isLoading={isReconLoading}
      />

      <GvmConfirmModal
        isOpen={isGvmModalOpen}
        onClose={() => setIsGvmModalOpen(false)}
        onConfirm={handleConfirmGvm}
        projectName={currentProject?.name || 'Unknown'}
        targetDomain={currentProject?.targetDomain || currentProject?.targetIps?.join(', ') || 'Unknown'}
        stats={gvmStats}
        isLoading={isGvmLoading}
        error={gvmError}
      />

      <PageBottomBar data={data} is3D={is3D} showLabels={showLabels} activeView={activeView} />
    </div>
  )
}


