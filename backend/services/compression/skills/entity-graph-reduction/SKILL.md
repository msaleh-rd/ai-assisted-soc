---
name: entity-graph-reduction
phase: compression
description: Applies NetworkX topological graph algorithms (PageRank, betweenness centrality, community detection) to reduce peripheral nodes and isolate the core incident blast radius.
collects:
  - blast_radius_subgraph
  - core_entities
  - peripheral_nodes_pruned
  - graph_centrality
actions:
  - isolate_blast_radius
  - prune_peripheral_nodes
method: statistical
parameters:
  max_hop_distance:
    type: integer
    default: 2
    description: Maximum distance from primary compromised nodes
---

# Entity Graph Reduction Skill

## Purpose
Prunes thousands of irrelevant system entities (e.g. normal background service accounts, internal DNS servers) from the graph, isolating only the entities that sit on direct attack paths between the threat actor and the target assets.

## Outputs
- Pruned attack interaction subgraph
- Key pivot nodes and high-centrality bridge entities
- Quantified blast radius count
