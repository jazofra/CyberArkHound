"""Graph building logic converting CyberArk collections into an OpenGraph.

Returns an (OpenGraph, external_edges) tuple. External edges reference non-CyberArk
entities (e.g., AD users/groups) and are serialized at export time.
"""
from __future__ import annotations
import json
import re
from typing import Any, Dict, List, Tuple
from bhopengraph.OpenGraph import OpenGraph
from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties

from .utils import parse_domain_from_dn, get_logger

_USER_FIELDS = {
    "id": ["id"],
    "username": ["username"],
    "userDN": ["userDN"],
    "userType": ["userType"],
    "componentUser": ["componentUser"],
    "enabled": ["enabled"],
    "suspended": ["suspended"],
    "location": ["location"],
    "source": ["source"],
    "authorizedInterfaces": ["authorizedInterfaces"],
    "vaultAuthorization": ["vaultAuthorization"],
    "allowedAuthenticationMethods": ["allowedAuthenticationMethods"],
    "personalDetails": ["personalDetails"],
    "groupsMembership": ["groupsMembership"],
}

_GROUP_FIELDS = {
    "id": ["id"],
    "groupName": ["groupName"],
    "groupType": ["groupType"],
    "location": ["location"],
    "description": ["description"],
    "directory": ["directory"],
    "dn": ["dn"],
    "members": ["members"],
}

_SAFE_FIELDS = {
    "safeName": ["safeName"],
    "safeUrlId": ["safeUrlId"],
    "description": ["description"],
    "location": ["location"],
    "olacEnabled": ["olacEnabled"],
    "managingCPM": ["managingCPM"],
}

_ACCOUNT_FIELDS = {
    "id": ["id"],
    "userName": ["userName"],
    "address": ["address"],
    "platformId": ["platformId"],
    "safeName": ["safeName"],
    "safeUrlId": ["safeUrlId"],
    "safeId": ["safeId"],
    "secretType": ["secretType"],
    "status": ["status"],
    "disabled": ["disabled"],
}

_SAFE_MEMBER_FIELDS = {
    "MemberName": ["MemberName"],
    "MemberType": ["MemberType"],
    "SafeName": ["SafeName"],
    "SafeUrlId": ["SafeUrlId"],
    "Permissions": ["Permissions"],
    "permissionParameters": ["permissionParameters"],
}

def _get(obj: Dict[str, Any], field_map: Dict[str, List[str]], logical: str) -> Any:
    """Get field value from object using field mapping.
    
    Returns the first matching field value from the field_map, or None if not found.
    """
    for physical in field_map.get(logical, []):
        if physical in obj:
            val = obj.get(physical)
            if val is not None:  # Skip None values, try next field
                return val
    return None


def _get_str(obj: Dict[str, Any], field_map: Dict[str, List[str]], logical: str, default: str = "") -> str:
    """Get field value as string, returning default if None/missing."""
    val = _get(obj, field_map, logical)
    return default if val is None else str(val)

# Permissions that allow actual account access per CyberArk API documentation
# https://docs.cyberark.com/pam-self-hosted/latest/en/content/webservices/add%20safe%20member.htm
_ACCOUNT_ACCESS_PERMISSIONS = {
    "useaccounts",        # Use accounts (PSM connections) but cannot view passwords
    "retrieveaccounts",   # Retrieve and view accounts (includes viewing passwords)
    # Note: listAccounts alone does NOT allow password retrieval - only viewing account list
}

# Permissions that allow privilege escalation to grant account access
# Users with these permissions can modify safe membership or grant themselves account access
_PRIVILEGE_ESCALATION_PERMISSIONS = {
    "managesafe",         # Update safe properties, recover safe, delete safe
    "managesafemembers",  # Add/remove safe members and update their permissions
}


def build_opengraph(
    users: List[Dict[str, Any]],
    groups: List[Dict[str, Any]],
    safes: List[Dict[str, Any]],
    safe_members: List[Dict[str, Any]],
    accounts: List[Dict[str, Any]],
    target_domains: List[str],
    *,
    debug: bool = False,
    verbose: bool = True,
) -> Tuple[OpenGraph, List[Dict[str, Any]]]:
    logger = get_logger(verbose)
    if debug:
        logger.debug("Building OpenGraph (users=%d groups=%d safes=%d accounts=%d)",
                     len(users), len(groups), len(safes), len(accounts))

    def norm(s: Any) -> str:
        return "" if s is None else str(s).strip()

    def norm_perm_name(p: Any) -> str:
        if not p:
            return ""
        return "".join(ch for ch in str(p).lower() if ch.isalnum())

    node_index: Dict[str, Dict[str, Any]] = {}
    edge_set = set()
    internal_edges: List[Dict[str, Any]] = []
    external_edges: List[Dict[str, Any]] = []

    def merge_node(node: Dict[str, Any]) -> Dict[str, Any]:
        nid = node["id"]
        existing = node_index.get(nid)
        if not existing:
            node_index[nid] = {"kinds": list(node.get("kinds", [])), "properties": dict(node.get("properties", {}))}
            return node_index[nid]
        for k in node.get("kinds", []):
            if k not in existing["kinds"]:
                existing["kinds"].append(k)
        for pk, pv in node.get("properties", {}).items():
            if pk not in existing["properties"]:
                existing["properties"][pk] = pv
        return existing

    def add_edge(kind: str, start: str, end: str, *, properties: Dict[str, Any] | None = None,
                 start_match_by: str = "id", end_match_by: str = "id", external: bool = False) -> None:
        try:
            key = (kind, start, end, start_match_by, end_match_by, json.dumps(properties, sort_keys=True) if properties else "")
        except Exception:
            return
        if key in edge_set:
            return
        edge_set.add(key)
        edge_dict = {
            "kind": kind,
            "start": {"value": start, "match_by": start_match_by},
            "end": {"value": end, "match_by": end_match_by},
            "properties": properties or {}
        }
        (external_edges if external else internal_edges).append(edge_dict)

    users_by_id: Dict[str, str] = {}
    users_by_username: Dict[str, str] = {}

    for u in users:
        username = _get(u, _USER_FIELDS, "username")
        user_dn = _get(u, _USER_FIELDS, "userDN")
        source = norm(_get(u, _USER_FIELDS, "source"))
        is_ldap = "ldap" in source.lower()
        ca_node_id = f"causer-{username}" if username else None
        if not ca_node_id:
            continue
        
        # Extract personal details
        personal_details = _get(u, _USER_FIELDS, "personalDetails") or {}
        
        # Determine if user is LDAP/Directory synced
        is_ldap_synced = is_ldap or (user_dn and len(user_dn) > 0)
        
        # Extract and serialize vault authorizations (might be complex objects)
        vault_auth = _get(u, _USER_FIELDS, "vaultAuthorization") or []
        if isinstance(vault_auth, list) and vault_auth and isinstance(vault_auth[0], dict):
            # Complex structure, serialize it
            from .utils import sanitize_properties_for_bloodhound
            vault_auth_serialized = sanitize_properties_for_bloodhound({"auth": vault_auth}).get("auth")
        else:
            # Simple list of strings
            vault_auth_serialized = vault_auth
        
        merge_node({
            "id": ca_node_id,
            "kinds": ["CyberArkUser", "CyberArkBase"],
            "properties": {
                "id": ca_node_id,
                "name": username,
                "userId": _get(u, _USER_FIELDS, "id"),
                "isLDAPSynced": is_ldap_synced,
                "enabled": bool(_get(u, _USER_FIELDS, "enabled")) if _get(u, _USER_FIELDS, "enabled") is not None else True,
                "suspended": bool(_get(u, _USER_FIELDS, "suspended")) if _get(u, _USER_FIELDS, "suspended") is not None else False,
                "distinguishedName": user_dn or "",
                "authorizedInterfaces": _get(u, _USER_FIELDS, "authorizedInterfaces") or [],
                "componentUser": _get(u, _USER_FIELDS, "componentUser"),
                "source": source,
                "userType": _get(u, _USER_FIELDS, "userType") or "",
                "location": _get(u, _USER_FIELDS, "location") or "",
                "vaultAuthorization": vault_auth_serialized,
                "allowedAuthenticationMethods": _get(u, _USER_FIELDS, "allowedAuthenticationMethods") or [],
                "firstName": personal_details.get("firstName", ""),
                "middleName": personal_details.get("middleName", ""),
                "lastName": personal_details.get("lastName", ""),
                "email": personal_details.get("email", ""),
                "businessEmail": personal_details.get("businessEmail", ""),
                "homeEmail": personal_details.get("homeEmail", ""),
                "businessPhone": personal_details.get("businessPhone", ""),
                "homePhone": personal_details.get("homePhone", ""),
                "mobilePhone": personal_details.get("mobilePhone", ""),
                "faxNumber": personal_details.get("faxNumber", ""),
                "street": personal_details.get("street", ""),
                "city": personal_details.get("city", ""),
                "state": personal_details.get("state", ""),
                "zip": personal_details.get("zip", ""),
                "country": personal_details.get("country", ""),
                "title": personal_details.get("title", ""),
                "organization": personal_details.get("organization", ""),
                "department": personal_details.get("department", ""),
                "profession": personal_details.get("profession", ""),
                "groupsMembership": [gm.get("groupName") or gm.get("name") for gm in (_get(u, _USER_FIELDS, "groupsMembership") or [])],
                "safePermissions": [],  # Will be populated from safe member data
            }
        })
        if _get(u, _USER_FIELDS, "id"):
            users_by_id[str(_get(u, _USER_FIELDS, "id"))] = ca_node_id
        if username:
            users_by_username[username] = ca_node_id
        groups_membership = _get(u, _USER_FIELDS, "groupsMembership") or []
        for gm in groups_membership:
            gname = gm.get("groupName") or gm.get("name")
            if gname:
                add_edge("CyberArkMemberOf", ca_node_id, f"cagroup-{gname}", properties={"source": "userDetails"})
        if is_ldap and user_dn and username:
            domain = parse_domain_from_dn(user_dn)
            if domain:
                ad_user_name = f"{username.upper()}@{domain.upper()}"
                add_edge("SyncsToCyberArkUser", ad_user_name, ca_node_id, properties={
                    "inferred": True,
                    "source": "LDAP",
                    "domain": domain,
                    "userDN": user_dn
                }, start_match_by="name", end_match_by="id", external=True)

    groups_by_id: Dict[str, str] = {}
    groups_by_name: Dict[str, str] = {}

    for g in groups:
        gid_raw = _get(g, _GROUP_FIELDS, "id") or _get(g, _GROUP_FIELDS, "groupName")
        groupname = _get(g, _GROUP_FIELDS, "groupName") or gid_raw
        gid = f"cagroup-{gid_raw or groupname}"
        
        # Extract members list
        members = _get(g, _GROUP_FIELDS, "members") or []
        member_names = [m.get("username") or m.get("memberName") for m in members if isinstance(m, dict)]
        
        # Determine if group is directory synced
        group_type_val = _get(g, _GROUP_FIELDS, "groupType") or ""
        is_directory_synced = group_type_val.lower() == "directory"
        group_dn = _get(g, _GROUP_FIELDS, "dn")
        
        merge_node({
            "id": gid,
            "kinds": ["CyberArkGroup", "CyberArkBase"],
            "properties": {
                "id": gid,
                "name": groupname,
                "groupId": gid_raw,
                "isDirectorySynced": is_directory_synced,
                "description": _get(g, _GROUP_FIELDS, "description") or "",
                "groupType": _get(g, _GROUP_FIELDS, "groupType") or "",
                "location": _get(g, _GROUP_FIELDS, "location") or "",
                "directory": _get(g, _GROUP_FIELDS, "directory") or "",
                "distinguishedName": _get(g, _GROUP_FIELDS, "dn") or "",
                "memberCount": len(members),
                "members": member_names,
                "safePermissions": [],  # Will be populated from safe member data
            }
        })
        if gid_raw:
            groups_by_id[str(gid_raw)] = gid
        if groupname:
            groups_by_name[str(groupname)] = gid
        
        # Create external edge for directory-synced groups
        if is_directory_synced and group_dn and groupname:
            domain = parse_domain_from_dn(group_dn)
            if domain:
                cn_match = re.search(r'CN=([^,]+)', group_dn, re.IGNORECASE)
                cn_name = cn_match.group(1) if cn_match else groupname
                ad_group_name = f"{cn_name.upper()}@{domain.upper()}"
                add_edge("SyncsToCyberArkGroup", ad_group_name, gid, properties={
                    "inferred": True,
                    "source": "LDAP",
                    "domain": domain,
                    "groupDN": group_dn,
                    "directory": g.get("directory", "")
                }, start_match_by="name", end_match_by="id", external=True)

    safes_by_name: Dict[str, str] = {}
    safes_by_urlid: Dict[str, str] = {}
    # Track which accounts belong to which safe for permission-based edge creation
    safe_accounts: Dict[str, List[str]] = {}  # safe_id -> [account_ids]
    for s in safes:
        safe_name = _get(s, _SAFE_FIELDS, "safeName")
        safe_url_id = _get(s, _SAFE_FIELDS, "safeUrlId")
        sid = f"casafe-{safe_url_id or safe_name}"
        merge_node({
            "id": sid,
            "kinds": ["CyberArkSafe", "CyberArkBase"],
            "properties": {
                "id": sid,
                "name": safe_name,
                "safeName": safe_name,
                "description": _get(s, _SAFE_FIELDS, "description") or "",
                "safeUrlId": safe_url_id or "",
                "safeNumber": s.get("safeNumber"),
                "location": _get(s, _SAFE_FIELDS, "location") or "",
                "creator": s.get("creator") or "",
                "olacEnabled": bool(_get(s, _SAFE_FIELDS, "olacEnabled")) if _get(s, _SAFE_FIELDS, "olacEnabled") is not None else False,
                "managingCPM": _get(s, _SAFE_FIELDS, "managingCPM") or "",
                "numberOfVersionsRetention": s.get("numberOfVersionsRetention"),
                "numberOfDaysRetention": s.get("numberOfDaysRetention"),
                "autoPurgeEnabled": s.get("autoPurgeEnabled"),
                "creationTime": s.get("creationTime"),
                "lastModificationTime": s.get("lastModificationTime"),
                "isExpiredMembershipEnable": s.get("isExpiredMembershipEnable"),
            }
        })
        if safe_name:
            safes_by_name[str(safe_name)] = sid
        if safe_url_id:
            safes_by_urlid[str(safe_url_id)] = sid

    accounts_by_id: Dict[str, bool] = {}
    td_lower = {d.lower() for d in target_domains}
    for a in accounts:
        if _get(a, _ACCOUNT_FIELDS, "disabled") or _get(a, _ACCOUNT_FIELDS, "status") == "Archived":
            continue
        aid = f"caaccount-{_get(a, _ACCOUNT_FIELDS, 'id')}"
        acct_name = _get(a, _ACCOUNT_FIELDS, "userName")
        safe_for_account = _get(a, _ACCOUNT_FIELDS, "safeName")
        safe_url = _get(a, _ACCOUNT_FIELDS, "safeUrlId") or _get(a, _ACCOUNT_FIELDS, "safeId")
        
        # Extract platform account properties if present
        platform_props = a.get("platformAccountProperties") or {}
        secret_mgmt = a.get("secretManagement") or {}
        
        # Serialize complex objects for BloodHound compatibility
        from .utils import sanitize_properties_for_bloodhound
        platform_props_serialized = sanitize_properties_for_bloodhound({"data": platform_props}).get("data") if platform_props else None
        secret_mgmt_serialized = sanitize_properties_for_bloodhound({"data": secret_mgmt}).get("data") if secret_mgmt else None
        
        merge_node({
            "id": aid,
            "kinds": ["CyberArkAccount", "CyberArkBase"],
            "properties": {
                "id": aid,
                "name": acct_name,
                "accountId": _get(a, _ACCOUNT_FIELDS, "id"),
                "userName": acct_name,
                "platformId": _get(a, _ACCOUNT_FIELDS, "platformId") or "",
                "address": _get(a, _ACCOUNT_FIELDS, "address") or "",
                "safeName": safe_for_account or "",
                "safeUrlId": safe_url or "",
                "secretType": _get(a, _ACCOUNT_FIELDS, "secretType") or "",
                "status": _get(a, _ACCOUNT_FIELDS, "status"),
                "disabled": _get(a, _ACCOUNT_FIELDS, "disabled"),
                "categoryModificationTime": a.get("categoryModificationTime"),
                "createdTime": a.get("createdTime"),
                "lastModifiedTime": a.get("lastModifiedTime"),
                "lastVerifiedTime": secret_mgmt.get("lastVerifiedTime"),
                "lastReconciledTime": secret_mgmt.get("lastReconciledTime"),
                "lastModifiedBy": secret_mgmt.get("modifiedBy"),
                "automaticManagementEnabled": secret_mgmt.get("automaticManagementEnabled"),
                "manualManagementReason": secret_mgmt.get("manualManagementReason"),
                "platformAccountProperties": platform_props_serialized,
                "secretManagement": secret_mgmt_serialized,
            }
        })
        accounts_by_id[aid] = True
        safe_node_id = None
        if safe_url and str(safe_url) in safes_by_urlid:
            safe_node_id = safes_by_urlid[str(safe_url)]
        elif safe_for_account and str(safe_for_account) in safes_by_name:
            safe_node_id = safes_by_name[str(safe_for_account)]
        else:
            safe_node_id = f"casafe-{safe_for_account or safe_url}"
            merge_node({"id": safe_node_id, "kinds": ["CyberArkSafe"], "properties": {"id": safe_node_id, "name": safe_for_account or safe_url}})
        add_edge("CyberArkContains", safe_node_id, aid, properties={"accountName": acct_name})
        
        # Track accounts by safe for later permission-based edge creation
        if safe_node_id not in safe_accounts:
            safe_accounts[safe_node_id] = []
        safe_accounts[safe_node_id].append(aid)
        
        address_val = (a.get("address", "") or "").strip().lower()
        sam_account = (acct_name or "").strip()
        if address_val and sam_account and address_val in td_lower:
            ad_user_name = f"{sam_account.upper()}@{address_val.upper()}"
            add_edge("SyncsToADUser", aid, ad_user_name, properties={
                "domain": address_val,
                "samAccountName": sam_account,
                "accountName": acct_name
            }, start_match_by="id", end_match_by="name", external=True)

    # Track safe permissions per user/group for later node property updates
    user_safe_permissions: Dict[str, List[Dict[str, Any]]] = {}  # user_node_id -> [{safeName, permissions}]
    group_safe_permissions: Dict[str, List[Dict[str, Any]]] = {}  # group_node_id -> [{safeName, permissions}]

    for sm in safe_members:
        member_name = sm.get("MemberName") or sm.get("memberName")
        member_type = sm.get("MemberType") or sm.get("memberType") or ""
        safe_name = sm.get("SafeName") or sm.get("safeName")
        safe_url_id = sm.get("SafeUrlId") or sm.get("safeUrlId")
        
        if debug:
            logger.debug("Processing safe member: %s (type: %s) for safe: %s", member_name, member_type, safe_name)
        
        if safe_url_id and str(safe_url_id) in safes_by_urlid:
            end_value = safes_by_urlid[str(safe_url_id)]
        elif safe_name and str(safe_name) in safes_by_name:
            end_value = safes_by_name[str(safe_name)]
        else:
            end_value = f"casafe-{safe_name or safe_url_id}"
            merge_node({"id": end_value, "kinds": ["CyberArkSafe"], "properties": {"id": end_value, "name": safe_name or safe_url_id}})
        if not member_name or not end_value:
            continue
        mtype_lower = member_type.lower() if isinstance(member_type, str) else ""
        if "user" in mtype_lower:
            start_value = users_by_id.get(str(member_name)) or users_by_username.get(str(member_name)) or f"causer-{member_name}"
        else:
            start_value = groups_by_id.get(str(member_name)) or groups_by_name.get(str(member_name)) or f"cagroup-{member_name}"
        
        raw_perms = sm.get("Permissions") or sm.get("permissions")
        
        if debug:
            logger.debug("Safe member %s -> Safe %s: raw_perms type=%s", member_name, safe_name, type(raw_perms).__name__)
        
        perm_entries: List[Dict[str, Any]] = []
        if isinstance(raw_perms, dict):
            for perm_key, perm_val in raw_perms.items():
                if isinstance(perm_val, bool) and perm_val:
                    perm_entries.append({"permission": perm_key, "permissionParameters": None})
        elif isinstance(raw_perms, list):
            for item in raw_perms:
                if isinstance(item, dict):
                    pname = item.get("permission") or item.get("Permission") or item.get("permissionName") or item.get("name")
                    pparams = item.get("permissionParameters") or item.get("PermissionParameters") or item.get("parameters")
                    perm_entries.append({"permission": norm(pname), "permissionParameters": pparams})
                else:
                    perm_entries.append({"permission": norm(item), "permissionParameters": None})
        elif isinstance(raw_perms, str):
            for p in [p.strip() for p in raw_perms.split(",") if p.strip()]:
                perm_entries.append({"permission": norm(p), "permissionParameters": None})
        else:
            for key in ("CanRetrieve", "HasAccess", "canRetrieve", "hasAccess", "useAccounts", "retrieveAccounts", "listAccounts", "addAccounts",
                        "updateAccountContent", "updateAccountProperties", "manageSafe", "manageSafeMembers", "viewAuditLog", "viewSafeMembers"):
                if sm.get(key):
                    perm_entries.append({"permission": key, "permissionParameters": None})
        top_level_pp = sm.get("permissionParameters")
        if top_level_pp and perm_entries and perm_entries[0].get("permissionParameters") is None:
            perm_entries[0]["permissionParameters"] = top_level_pp
        
        # Check if user/group has actual account access permissions
        # Per CyberArk API docs, only useAccounts and retrieveAccounts allow direct account access
        has_direct_access = False
        direct_access_perms: List[str] = []
        direct_access_params: List[Any] = []
        
        # Check if user/group can escalate privileges to grant themselves access
        has_privilege_escalation = False
        escalation_perms: List[str] = []
        escalation_params: List[Any] = []
        
        for pe in perm_entries:
            pname = norm_perm_name(pe.get("permission"))
            
            # Check for direct account access
            if pname in _ACCOUNT_ACCESS_PERMISSIONS:
                has_direct_access = True
                direct_access_perms.append(pe.get("permission"))
                if pe.get("permissionParameters") is not None:
                    direct_access_params.append(pe.get("permissionParameters"))
            
            # Check for privilege escalation permissions
            if pname in _PRIVILEGE_ESCALATION_PERMISSIONS:
                has_privilege_escalation = True
                escalation_perms.append(pe.get("permission"))
                if pe.get("permissionParameters") is not None:
                    escalation_params.append(pe.get("permissionParameters"))
        
        # Legacy support: check for boolean flags in safe member response
        if not has_direct_access:
            if sm.get("useAccounts") or sm.get("UseAccounts"):
                has_direct_access = True
                direct_access_perms.append("UseAccounts")
            if sm.get("retrieveAccounts") or sm.get("RetrieveAccounts"):
                has_direct_access = True
                direct_access_perms.append("RetrieveAccounts")
        
        if not has_privilege_escalation:
            if sm.get("manageSafe") or sm.get("ManageSafe"):
                has_privilege_escalation = True
                escalation_perms.append("ManageSafe")
            if sm.get("manageSafeMembers") or sm.get("ManageSafeMembers"):
                has_privilege_escalation = True
                escalation_perms.append("ManageSafeMembers")
        
        # Track safe permissions for user/group node properties
        safe_perm_entry = {
            "safeName": safe_name or safe_url_id,
            "safeId": end_value,
            "permissions": [p.get("permission") for p in perm_entries],
            "hasDirectAccess": has_direct_access,
            "canGrantAccess": has_privilege_escalation
        }
        
        if "user" in mtype_lower:
            if start_value not in user_safe_permissions:
                user_safe_permissions[start_value] = []
            user_safe_permissions[start_value].append(safe_perm_entry)
        else:
            if start_value not in group_safe_permissions:
                group_safe_permissions[start_value] = []
            group_safe_permissions[start_value].append(safe_perm_entry)
        
        # Create direct access edges: User/Group -> Account
        if has_direct_access:
            # CyberArkHasAccessTo: user/group can directly use/retrieve accounts in this safe
            # useAccounts allows PSM connections, retrieveAccounts allows password viewing
            # Create an edge to EACH account in the safe
            safe_id = end_value
            accounts_in_safe = safe_accounts.get(safe_id, [])
            
            if debug:
                logger.debug("Creating %d CyberArkHasAccessTo edges: %s -> accounts in %s (perms: %s)", 
                           len(accounts_in_safe), member_name, safe_name, direct_access_perms)
            
            for account_id in accounts_in_safe:
                add_edge("CyberArkHasAccessTo", start_value, account_id, properties={
                    "permissions": perm_entries,
                    "matchedPermissionNames": direct_access_perms,
                    "matchedPermissionParameters": direct_access_params,
                    "accessType": "direct",
                    "via": safe_id,
                    "viaSafeName": safe_name or safe_url_id
                })
        
        # Create privilege escalation edge: User/Group -> Safe
        if has_privilege_escalation:
            # CyberArkCanGrantAccessTo: user/group can modify safe/members to grant themselves access
            # manageSafe allows safe property changes, manageSafeMembers allows adding/modifying permissions
            
            if debug:
                logger.debug("Creating CyberArkCanGrantAccessTo edge: %s -> %s (perms: %s)", 
                           member_name, safe_name, escalation_perms)
            
            add_edge("CyberArkCanGrantAccessTo", start_value, end_value, properties={
                "permissions": perm_entries,
                "matchedPermissionNames": escalation_perms,
                "matchedPermissionParameters": escalation_params,
                "accessType": "privilege_escalation",
                "attackPath": "Can grant self or others account access permissions"
            })

    for g in groups:
        gid_raw = _get(g, _GROUP_FIELDS, "id") or _get(g, _GROUP_FIELDS, "groupName")
        groupname = _get(g, _GROUP_FIELDS, "groupName") or gid_raw
        group_node_id = groups_by_id.get(str(gid_raw)) or groups_by_name.get(str(groupname)) or f"cagroup-{gid_raw or groupname}"
        for m in (_get(g, _GROUP_FIELDS, "members") or []):
            member_username = m.get("username")
            member_id = m.get("id")
            if not member_username:
                continue
            member_node_id = users_by_id.get(str(member_id)) or users_by_username.get(str(member_username)) or f"causer-{member_username}"
            add_edge("CyberArkMemberOf", member_node_id, group_node_id, properties={"source": "groupMembership"})

    # Update user and group nodes with safe permissions collected during safe member processing
    from .utils import sanitize_properties_for_bloodhound
    
    for user_node_id, safe_perms in user_safe_permissions.items():
        if user_node_id in node_index:
            # Serialize the safe permissions list (contains dicts)
            serialized_perms = sanitize_properties_for_bloodhound({"perms": safe_perms}).get("perms")
            node_index[user_node_id]["properties"]["safePermissions"] = serialized_perms
    
    for group_node_id, safe_perms in group_safe_permissions.items():
        if group_node_id in node_index:
            # Serialize the safe permissions list (contains dicts)
            serialized_perms = sanitize_properties_for_bloodhound({"perms": safe_perms}).get("perms")
            node_index[group_node_id]["properties"]["safePermissions"] = serialized_perms

    og = OpenGraph(source_kind="CyberArkBase")
    for nid, nd in node_index.items():
        kinds = nd.get("kinds", [])[:3]
        props = nd.get("properties", {})
        
        # Sanitize all properties to ensure no dicts are passed to bhopengraph
        sanitized_props = {}
        for key, value in props.items():
            if value is None:
                sanitized_props[key] = value
            elif isinstance(value, (str, int, float, bool)):
                sanitized_props[key] = value
            elif isinstance(value, list):
                # Check if list contains dicts
                if value and isinstance(value[0], dict):
                    # Serialize complex list
                    sanitized_props[key] = sanitize_properties_for_bloodhound({key: value}).get(key)
                else:
                    sanitized_props[key] = value
            elif isinstance(value, dict):
                # Serialize dict to JSON string
                sanitized_props[key] = sanitize_properties_for_bloodhound({key: value}).get(key)
            else:
                # Unknown type, try to serialize
                sanitized_props[key] = sanitize_properties_for_bloodhound({key: value}).get(key)
        
        try:
            node_obj = Node(id=nid, kinds=kinds, properties=Properties(**sanitized_props))
        except TypeError:
            clean_props = {str(k): v for k, v in sanitized_props.items()}
            node_obj = Node(id=nid, kinds=kinds, properties=Properties(**clean_props))
        og.add_node(node_obj)
    for e in internal_edges:
        kind = e.get("kind")
        start_val = e.get("start", {}).get("value")
        end_val = e.get("end", {}).get("value")
        start_match = e.get("start", {}).get("match_by", "id")
        end_match = e.get("end", {}).get("match_by", "id")
        properties = e.get("properties") or {}
        prop_obj = None
        if properties:
            try:
                prop_obj = Properties(**properties)
            except TypeError:
                clean_props = {str(k): v for k, v in properties.items()}
                prop_obj = Properties(**clean_props)
        edge_obj = Edge(start_node=start_val, end_node=end_val, kind=kind,
                        properties=prop_obj, start_match_by=start_match, end_match_by=end_match)
        og.add_edge(edge_obj)
    if debug:
        logger.debug("Graph build complete: nodes=%d internal_edges=%d external_edges=%d", len(og.nodes), len(internal_edges), len(external_edges))
    return og, external_edges
