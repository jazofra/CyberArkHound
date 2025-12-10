"""Command-line interface for CyberArkHound export tool."""
from __future__ import annotations
import argparse
import concurrent.futures
import sys
import time
from typing import List, Dict, Any

from .client import CyberArkClient
from .graph import build_opengraph
from .exporter import export_opengraph_to_bloodhound_json
from .utils import get_logger


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CyberArk to BloodHound OpenGraph exporter")
    p.add_argument("--pvwa", required=False, help="PVWA base URL (required for on-premise, ignored for ISPSS)")
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
    p.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO", help="Set logging level (default: INFO)")
    # Activity tracking
    a = p.add_argument_group("activity tracking")
    a.add_argument("--include-activity", action="store_true", help="Include account activity data (creates CyberArkUsedAccount edges)")
    a.add_argument("--activity-days", type=int, default=3, help="Number of days to look back for activity (default: 3)")
    a.add_argument("--activity-limit", type=int, default=100, help="Max activities per account (default: 100)")
    # Testing / limiting
    t = p.add_argument_group("testing limits")
    t.add_argument("--limit-users", type=int, help="Limit number of users")
    t.add_argument("--limit-groups", type=int, help="Limit number of groups")
    t.add_argument("--limit-safes", type=int, help="Limit number of safes")
    t.add_argument("--test-safe", help="Fetch single safe by search term")
    # ISPSS (Privilege Cloud) authentication
    i = p.add_argument_group("ISPSS authentication (Privilege Cloud)")
    i.add_argument("--auth-mode", choices=["cyberark", "ispss"], default="cyberark",
                   help="Authentication mode: 'cyberark' (on-premise) or 'ispss' (Privilege Cloud)")
    i.add_argument("--identity-url", default=None,
                   help="Identity URL override (GovCloud/custom deployments only)")
    return p


def run(args: argparse.Namespace) -> int:
    logger = get_logger(not args.quiet)
    verify_value = False if args.insecure else (args.ca_bundle if args.ca_bundle else None)

    # Validate args based on auth mode
    if args.auth_mode == "ispss":
        if args.pvwa:
            logger.warning("--pvwa is ignored when using --auth-mode ispss (auto-discovered)")
        if not args.username or not args.password:
            logger.error("--username and --password are required for ISPSS authentication")
            return 1
    else:
        if not args.pvwa:
            logger.error("--pvwa is required for on-premise (cyberark) authentication")
            return 1

    # Create client based on auth mode
    if args.auth_mode == "ispss":
        from .auth import ISPSSAuthenticator
        logger.info("Authenticating to CyberArk ISPSS (Privilege Cloud)...")
        authenticator = ISPSSAuthenticator(
            username=args.username,
            password=args.password,
            identity_url=args.identity_url,
        )
        authenticator.authenticate()
        client = CyberArkClient(
            authenticator=authenticator,
            auth_timeout=args.auth_timeout,
            req_timeout=args.req_timeout,
            verbose=not args.quiet,
            verify=verify_value,
        )
        client.authenticate()  # Just applies the token to session
    else:
        logger.info("Authenticating to CyberArk PVWA (on-premise)...")
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

    # Fetch account activities if requested
    account_activities: Dict[str, List[Dict[str, Any]]] = {}
    if args.include_activity and accounts:
        logger.info("Fetching account activities (last %d days)...", args.activity_days)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(client.get_account_activities, a.get("id"), 
                                      limit=args.activity_limit, days_back=args.activity_days): a 
                      for a in accounts if a.get("id")}
            for idx, future in enumerate(concurrent.futures.as_completed(futures), 1):
                acc = futures[future]
                acc_id = acc.get("id")
                try:
                    activities = future.result()
                    if activities:
                        account_activities[acc_id] = activities
                    if idx % 100 == 0:
                        logger.info("  Fetched activities for %d/%d accounts", idx, len(accounts))
                except Exception as e:  # pragma: no cover network
                    logger.warning("Activity fetch error for %s: %s", acc_id, e)
        logger.info("Collected activities for %d accounts", len(account_activities))

    try:
        graph, external_edges = build_opengraph(
            users, groups, safes, safe_members, accounts, args.target_domains,
            debug=args.debug, verbose=not args.quiet, log_level=args.log_level,
            account_activities=account_activities if args.include_activity else None
        )
        export_opengraph_to_bloodhound_json(
            graph, external_edges, args.output, debug=args.debug, verbose=not args.quiet, log_level=args.log_level
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
