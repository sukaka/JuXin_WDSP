package apidataflow

import (
	"context"
	"fmt"
)

type serviceNodeMetadata struct {
	environment string
	namespace   string
	cluster     string
	addresses   []string
}

func (s *CHReader) addNodeMetadata(ctx context.Context, filter GraphFilter, graph *Graph) error {
	querier, err := s.querier(ctx)
	if err != nil {
		return err
	}
	where, args := graphWhere(filter, true)
	rows, err := querier.Query(ctx, `
SELECT service_name,
 argMax(environment,received_at),
 argMax(namespace,received_at),
 argMax(cluster,received_at),
 groupUniqArrayIf(10)(host,host != '')
FROM wdsp.api_observations
WHERE `+where+` AND direction = 'SERVER'
GROUP BY service_name`, args...)
	if err != nil {
		return fmt.Errorf("query dataflow node metadata: %w", err)
	}
	defer rows.Close()
	metadata := map[string]serviceNodeMetadata{}
	for rows.Next() {
		var name string
		var item serviceNodeMetadata
		if err := rows.Scan(&name, &item.environment, &item.namespace, &item.cluster, &item.addresses); err != nil {
			return err
		}
		metadata[name] = item
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range graph.Nodes {
		node := &graph.Nodes[i]
		node.GroupName = groupNameForNode(node.Type)
		if node.Type != "SERVICE" {
			if node.Addresses == nil {
				node.Addresses = []string{}
			}
			if node.Type == "CLIENT" {
				node.Addresses = []string{node.Name}
			}
			continue
		}
		node.ServiceName = node.Name
		node.Addresses = []string{}
		item := metadata[node.Name]
		node.Environment = item.environment
		node.Namespace = item.namespace
		node.Cluster = item.cluster
		node.Addresses = append(node.Addresses, item.addresses...)
		if item.environment != "" {
			node.GroupName = item.environment
			if item.namespace != "" {
				node.GroupName += " / " + item.namespace
			}
		}
	}
	return nil
}

func groupNameForNode(nodeType string) string {
	switch nodeType {
	case "KAFKA":
		return "消息与基础设施"
	case "EXTERNAL", "CLIENT":
		return "来源与外部"
	default:
		return "未分区"
	}
}

func applyNetworkView(graph *Graph) {
	ids := map[string]string{}
	names := map[string]string{}
	usedNames := map[string]bool{}
	for i := range graph.Nodes {
		node := &graph.Nodes[i]
		oldID := node.ID
		name := node.Name
		if node.Type == "SERVICE" && len(node.Addresses) > 0 {
			name = node.Addresses[0]
			if len(node.Addresses) > 1 {
				name = fmt.Sprintf("%s 等%d个地址", name, len(node.Addresses))
			}
			if usedNames[name] {
				name += " / " + node.ServiceName
			}
			node.Type = "ENDPOINT"
		} else if node.Type == "CLIENT" {
			node.Type = "ENDPOINT"
		}
		usedNames[name] = true
		node.Name = name
		node.ID = nodeID(node.Type, name)
		ids[oldID] = node.ID
		names[oldID] = name
	}
	for i := range graph.Edges {
		edge := &graph.Edges[i]
		if name := names[edge.SourceID]; name != "" {
			edge.SourceID = ids[edge.SourceID]
			edge.SourceName = name
		}
		if name := names[edge.TargetID]; name != "" {
			edge.TargetID = ids[edge.TargetID]
			edge.TargetName = name
		}
	}
	graph.View = "network"
}
