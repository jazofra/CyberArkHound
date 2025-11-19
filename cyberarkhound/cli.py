"""Command-line interface for CyberArkHound export tool."""
from __future__ import annotations
import argparse
import concurrent.futures
import sys
from typing import List

from .client import CyberArkClient
from .graph import build_opengraph
from .exporter import export_opengraph_to_bloodhound_json
from .utils import get_logger


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CyberArk to BloodHound OpenGraph exporter")
    p.add_argument("--pvwa", required=True, help="PVWA base URL")
    p.add_argument("--username", required=True, help="API username")
    p.add_argument("--password", required=True, help="API password (consider using env var CYBERARK_PASSWORD)")
    p.add_argument("--output", required=True, help="Output JSON file")
    p.add_argument("--target-domains", nargs='+', required=True, help="Target AD domain(s) for SyncsToADUser edges")
    p.add_argument("--workers", type=int, default=50, help="Concurrent workers for account detail retrieval")
    p.add_argument("--auth-timeout", type=int, default=360, help="Auth timeout seconds")
    p.add_argument("--req-timeout", type=int, default=360, help="Request timeout seconds")
    p.add_argument("--quiet", action="store_true", help="Suppress verbose logs")
    p.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    p.add_argument("--ca-bundle", help="Path to CA bundle file")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    # Testing / limiting
    t = p.add_argument_group("testing limits")
    t.add_argument("--limit-users", type=int, help="Limit number of users")
    t.add_argument("--limit-groups", type=int, help="Limit number of groups")
    t.add_argument("--limit-safes", type=int, help="Limit number of safes")
    t.add_argument("--test-safe", help="Fetch single safe by search term")
    return p


def run(args: argparse.Namespace) -> int:
    logger = get_logger(not args.quiet)
    verify_value = False if args.insecure else (args.ca_bundle if args.ca_bundle else None)

    client = CyberArkClient(
        pvwa_url=args.pvwa,
        username=args.username,
        password=args.password,
        auth_timeout=args.auth_timeout,
        req_timeout=args.req_timeout,
        verbose=not args.quiet,
        verify=verify_value,
    )

    client.authenticate()

    logger.info("Target domains: %s", ", ".join(args.target_domains))

    users = client.list_users(limit_count=args.limit_users)
    groups = client.list_groups(limit_count=args.limit_groups)

    if args.test_safe:
        safes = client.list_safes(search=args.test_safe)
        if not safes:
            logger.error("No safes found matching '%s'", args.test_safe)
            return 1
        logger.info("Found %d safes matching '%s'", len(safes), args.test_safe)
    else:
        safes = client.list_safes(limit_count=args.limit_safes)

    safe_members: List[dict] = []
    accounts: List[dict] = []

    for safe_idx, safe in enumerate(safes, start=1):
        sname = safe.get("safeName")
        safe_url_id = safe.get("safeUrlId")
        logger.info("Processing safe %d/%d: '%s'", safe_idx, len(safes), sname)
        try:
            members = client.list_safe_members(sname, safe_url_id)
            safe_members.extend(members)
        except Exception as e:  # pragma: no cover network
            logger.warning("Failed members for safe '%s': %s", sname, e)
            continue
        try:
            safe_accounts = client.list_accounts(sname, safe_url_id)
        except Exception as e:  # pragma: no cover network
            logger.warning("Failed accounts for safe '%s': %s", sname, e)
            continue
        if not safe_accounts:
            logger.info("No accounts in safe '%s'", sname)
            continue
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(client.get_account_details, a["id"]): a for a in safe_accounts if a.get("id")}
            for future in concurrent.futures.as_completed(futures):
                acc = futures[future]
                try:
                    details = future.result()
                    if details and not details.get("disabled") and details.get("status") != "Archived":
                        accounts.append(details)
                except Exception as e:  # pragma: no cover network
                    logger.warning("Account detail error %s: %s", acc.get("id"), e)

    try:
        graph, external_edges = build_opengraph(
            users, groups, safes, safe_members, accounts, args.target_domains,
            debug=args.debug, verbose=not args.quiet
        )
        export_opengraph_to_bloodhound_json(
            graph, external_edges, args.output, debug=args.debug, verbose=not args.quiet
        )
        node_count = len(graph.nodes) if hasattr(graph, 'nodes') else 0
        edge_count = len(graph.edges) if hasattr(graph, 'edges') else 0
        total_edges = edge_count + len(external_edges)
        logger.info("Export complete: nodes=%d internal_edges=%d external_edges=%d total=%d", node_count, edge_count, len(external_edges), total_edges)
        return 0
    finally:
        client.logoff()


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
