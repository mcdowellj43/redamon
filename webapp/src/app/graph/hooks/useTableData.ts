import { useMemo } from 'react'
import type { GraphData, GraphNode, GraphLink } from '../types'

export interface ConnectionInfo {
  nodeId: string
  nodeName: string
  nodeType: string
  relationType: string
}

export interface TableRow {
  node: GraphNode
  connectionsIn: ConnectionInfo[]
  connectionsOut: ConnectionInfo[]
  level2: ConnectionInfo[]
  level3: ConnectionInfo[]
}

function getNodeId(endpoint: string | GraphNode): string {
  return typeof endpoint === 'string' ? endpoint : endpoint.id
}

export function useTableData(data: GraphData | undefined): TableRow[] {
  return useMemo(() => {
    if (!data) return []

    const nodeMap = new Map<string, GraphNode>()
    data.nodes.forEach(n => nodeMap.set(n.id, n))

    // Build directed connection maps
    const connectionsIn = new Map<string, ConnectionInfo[]>()
    const connectionsOut = new Map<string, ConnectionInfo[]>()

    // Build undirected adjacency for BFS (set of neighbor IDs per node)
    const adjacency = new Map<string, Set<string>>()

    data.links.forEach((link: GraphLink) => {
      const sourceId = getNodeId(link.source)
      const targetId = getNodeId(link.target)
      const sourceNode = nodeMap.get(sourceId)
      const targetNode = nodeMap.get(targetId)

      if (!connectionsOut.has(sourceId)) connectionsOut.set(sourceId, [])
      connectionsOut.get(sourceId)!.push({
        nodeId: targetId,
        nodeName: targetNode?.name || targetId,
        nodeType: targetNode?.type || 'Unknown',
        relationType: link.type,
      })

      if (!connectionsIn.has(targetId)) connectionsIn.set(targetId, [])
      connectionsIn.get(targetId)!.push({
        nodeId: sourceId,
        nodeName: sourceNode?.name || sourceId,
        nodeType: sourceNode?.type || 'Unknown',
        relationType: link.type,
      })

      // Undirected adjacency
      if (!adjacency.has(sourceId)) adjacency.set(sourceId, new Set())
      if (!adjacency.has(targetId)) adjacency.set(targetId, new Set())
      adjacency.get(sourceId)!.add(targetId)
      adjacency.get(targetId)!.add(sourceId)
    })

    // BFS to get nodes at exactly depth 2 and 3
    function getNodesAtDepth(startId: string): { level2: string[]; level3: string[] } {
      const visited = new Set<string>([startId])
      let currentLevel = [startId]
      const levels: string[][] = []

      for (let depth = 0; depth < 3; depth++) {
        const nextLevel: string[] = []
        for (const nodeId of currentLevel) {
          const neighbors = adjacency.get(nodeId)
          if (!neighbors) continue
          for (const neighbor of neighbors) {
            if (!visited.has(neighbor)) {
              visited.add(neighbor)
              nextLevel.push(neighbor)
            }
          }
        }
        levels.push(nextLevel)
        currentLevel = nextLevel
      }

      return { level2: levels[1] || [], level3: levels[2] || [] }
    }

    return data.nodes.map(node => {
      const { level2, level3 } = getNodesAtDepth(node.id)

      return {
        node,
        connectionsIn: connectionsIn.get(node.id) || [],
        connectionsOut: connectionsOut.get(node.id) || [],
        level2: level2.map(id => {
          const n = nodeMap.get(id)
          return {
            nodeId: id,
            nodeName: n?.name || id,
            nodeType: n?.type || 'Unknown',
            relationType: '2 hops',
          }
        }),
        level3: level3.map(id => {
          const n = nodeMap.get(id)
          return {
            nodeId: id,
            nodeName: n?.name || id,
            nodeType: n?.type || 'Unknown',
            relationType: '3 hops',
          }
        }),
      }
    })
  }, [data])
}
