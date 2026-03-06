import { useQuery } from '@tanstack/react-query'
import { useMemo, useRef } from 'react'
import { GraphData } from '../types'

async function fetchGraphData(projectId: string): Promise<GraphData> {
  const response = await fetch(`/api/graph?projectId=${projectId}`)
  if (!response.ok) {
    throw new Error('Failed to fetch graph data')
  }
  return response.json()
}

/**
 * Generate a fingerprint of the graph data to detect actual changes.
 * Only considers structural changes (nodes/links added/removed), not position changes.
 */
function getGraphFingerprint(data: GraphData | undefined): string {
  if (!data) return ''

  // Sort IDs to ensure consistent fingerprint regardless of order
  const nodeIds = data.nodes.map(n => n.id).sort().join(',')
  const linkIds = data.links.map(l => `${l.source}-${l.target}`).sort().join(',')

  // Include counts and IDs for a comprehensive fingerprint
  return `${data.nodes.length}:${data.links.length}:${nodeIds}:${linkIds}`
}

interface UseGraphDataOptions {
  isReconRunning?: boolean
  isAgentRunning?: boolean
}

export function useGraphData(projectId: string | null, options?: UseGraphDataOptions) {
  const { isReconRunning = false, isAgentRunning = false } = options || {}

  // Keep track of the last stable data
  const stableDataRef = useRef<GraphData | undefined>(undefined)
  const lastFingerprintRef = useRef<string>('')

  const shouldPoll = isReconRunning || isAgentRunning

  const query = useQuery({
    queryKey: ['graph', projectId],
    queryFn: () => fetchGraphData(projectId!),
    enabled: !!projectId,
    // Poll every 5 seconds while recon or agent is running
    refetchInterval: shouldPoll ? 5000 : false,
    // Only re-render the component when data or error actually change
    // (not on isFetching / dataUpdatedAt / fetchStatus transitions)
    notifyOnChangeProps: ['data', 'error', 'isLoading'],
  })

  // Only update the stable data reference when the fingerprint changes
  const stableData = useMemo(() => {
    const newFingerprint = getGraphFingerprint(query.data)

    // If fingerprint changed, update the stable data
    if (newFingerprint !== lastFingerprintRef.current) {
      lastFingerprintRef.current = newFingerprint
      stableDataRef.current = query.data
    }

    return stableDataRef.current
  }, [query.data])

  return {
    ...query,
    data: stableData,
  }
}
