import json
from typing import Any, Dict, List
from .utils import sanitize_properties_for_bloodhound, get_logger


def export_opengraph_to_bloodhound_json(og: Any, external_edges: List[Dict[str, Any]], output_file: str, *, debug: bool = False, verbose: bool = True) -> Dict[str, Any]:
    logger = get_logger(verbose)
    if debug:
        logger.debug("Starting export to BloodHound JSON format")

    nodes_array: List[Dict[str, Any]] = []
    if hasattr(og, 'nodes'):
        if isinstance(og.nodes, dict):
            nodes_to_process = list(og.nodes.values())
        else:
            nodes_to_process = list(og.nodes)
    else:
        nodes_to_process = []

    for node in nodes_to_process:
        if isinstance(node, str):
            continue
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

    edges_array: List[Dict[str, Any]] = []
    if hasattr(og, 'edges'):
        if isinstance(og.edges, dict):
            edges_to_process = list(og.edges.values())
        else:
            edges_to_process = list(og.edges)
    else:
        edges_to_process = []

    for edge in edges_to_process:
        if isinstance(edge, str):
            continue
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

    for ext_edge in external_edges:
        edge_dict = {
            "kind": ext_edge["kind"],
            "start": ext_edge["start"],
            "end": ext_edge["end"],
        }
        if ext_edge.get("properties"):
            edge_dict["properties"] = sanitize_properties_for_bloodhound(ext_edge["properties"])
        edges_array.append(edge_dict)

    output_json = {"graph": {"nodes": nodes_array, "edges": edges_array}}
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_json, f, indent=2, ensure_ascii=False)

    if debug:
        logger.debug("Exported %d nodes and %d edges", len(nodes_array), len(edges_array))
    return output_json
