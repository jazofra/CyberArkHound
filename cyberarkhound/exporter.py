import json
from typing import Any, Dict, List
from .utils import sanitize_properties_for_bloodhound, get_logger


def export_opengraph_to_bloodhound_json(og: Any, external_edges: List[Dict[str, Any]], output_file: str, *, debug: bool = False, verbose: bool = True, log_level: str = "INFO") -> Dict[str, Any]:
    logger = get_logger(verbose)
    logger.info("Starting export to BloodHound JSON format")

    # Adjust progress logging frequency based on log level
    if log_level == "WARNING" or log_level == "ERROR":
        node_interval = 10000
        edge_interval = 50000
    elif log_level == "DEBUG":
        node_interval = 25
        edge_interval = 100
    else:  # INFO (default)
        node_interval = 100
        edge_interval = 500

    # Extract nodes
    nodes_array: List[Dict[str, Any]] = []
    if hasattr(og, 'nodes'):
        if isinstance(og.nodes, dict):
            nodes_to_process = list(og.nodes.values())
        else:
            nodes_to_process = list(og.nodes)
    else:
        nodes_to_process = []

    total_nodes = len(nodes_to_process)
    logger.info("Processing %d nodes...", total_nodes)
    
    for idx, node in enumerate(nodes_to_process, 1):
        if isinstance(node, str):
            continue
        
        # Progress logging based on log level
        if idx % node_interval == 0 or idx == total_nodes:
            logger.info("  Processed %d/%d nodes (%.1f%%)", idx, total_nodes, (idx/total_nodes)*100)
        
        node_dict = {
            "id": getattr(node, 'id', str(node)),
            "kinds": [],
            "properties": {}
        }
        kinds = getattr(node, 'kinds', [])
        if isinstance(kinds, str):
            node_dict["kinds"] = [kinds]
        else:
            node_dict["kinds"] = list(kinds)
        
        # Extract properties efficiently
        props_extracted = {}
        props = getattr(node, 'properties', None)
        if isinstance(props, dict):
            props_extracted = props
        elif hasattr(props, 'to_dict'):
            try:
                props_extracted = props.to_dict()
            except Exception:
                pass
        elif hasattr(props, '__dict__'):
            props_extracted = {k: v for k, v in vars(props).items() if not k.startswith('_')}
        
        node_dict["properties"] = sanitize_properties_for_bloodhound(props_extracted)
        nodes_array.append(node_dict)

    # Extract edges
    edges_array: List[Dict[str, Any]] = []
    if hasattr(og, 'edges'):
        if isinstance(og.edges, dict):
            edges_to_process = list(og.edges.values())
        else:
            edges_to_process = list(og.edges)
    else:
        edges_to_process = []

    total_internal_edges = len(edges_to_process)
    logger.info("Processing %d internal edges...", total_internal_edges)

    for idx, edge in enumerate(edges_to_process, 1):
        if isinstance(edge, str):
            continue
        
        # Progress logging based on log level
        if idx % edge_interval == 0 or idx == total_internal_edges:
            logger.info("  Processed %d/%d edges (%.1f%%)", idx, total_internal_edges, (idx/total_internal_edges)*100)
        
        start_node_value = getattr(edge, 'start_node', None)
        end_node_value = getattr(edge, 'end_node', None)
        if not start_node_value or not end_node_value:
            continue
        start_match_by = getattr(edge, 'start_match_by', 'id') or 'id'
        end_match_by = getattr(edge, 'end_match_by', 'id') or 'id'
        edge_dict = {
            "kind": getattr(edge, 'kind', 'Unknown'),
            "start": {"value": start_node_value, "match_by": start_match_by},
            "end": {"value": end_node_value, "match_by": end_match_by},
        }
        
        # Extract properties efficiently
        props_extracted = {}
        props = getattr(edge, 'properties', None)
        if isinstance(props, dict):
            props_extracted = props
        elif hasattr(props, 'to_dict'):
            try:
                props_extracted = props.to_dict()
            except Exception:
                pass
        elif hasattr(props, '__dict__'):
            props_extracted = {k: v for k, v in vars(props).items() if not k.startswith('_')}
        
        if props_extracted:
            edge_dict["properties"] = sanitize_properties_for_bloodhound(props_extracted)
        edges_array.append(edge_dict)

    # Add external edges
    logger.info("Processing %d external edges...", len(external_edges))
    for ext_edge in external_edges:
        edge_dict = {
            "kind": ext_edge["kind"],
            "start": ext_edge["start"],
            "end": ext_edge["end"],
        }
        if ext_edge.get("properties"):
            edge_dict["properties"] = sanitize_properties_for_bloodhound(ext_edge["properties"])
        edges_array.append(edge_dict)

    # Build final structure
    output_json = {"graph": {"nodes": nodes_array, "edges": edges_array}}
    
    # Write to file with progress indicator
    logger.info("Writing JSON to file: %s", output_file)
    logger.info("  Total nodes: %d, Total edges: %d", len(nodes_array), len(edges_array))
    
    with open(output_file, 'w', encoding='utf-8', buffering=1048576) as f:
        # Always use compact encoding for BloodHound (doesn't need pretty JSON)
        logger.info("  Writing compact JSON format...")
        json.dump(output_json, f, ensure_ascii=False, separators=(',', ':'))
    
    logger.info("Export complete! File written successfully.")
    return output_json
