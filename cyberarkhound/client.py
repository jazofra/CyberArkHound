"""CyberArk PVWA API client.

Encapsulates API interactions, retry logic, and authentication.
"""
from __future__ import annotations
import json
import random
import time
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote
import requests

try:
    import certifi  # type: ignore
except Exception:  # pragma: no cover
    certifi = None  # type: ignore

from .utils import get_logger

SAFE_PAGE_LIMIT = 1000


class CyberArkClient:
    """Client for interacting with CyberArk PVWA REST API.

    Parameters
    ----------
    pvwa_url: str
        Base URL for PVWA (e.g. https://pvwa.example.com)
    username: str
        API user name
    password: str
        API user password
    auth_timeout: int
        Timeout (seconds) for authentication requests
    req_timeout: int
        Timeout (seconds) for general requests
    verbose: bool
        Enable verbose logging
    verify: bool | str | None
        SSL verification control. Use False to disable (insecure). Provide a CA bundle path or None for default behavior.
    retry_initial_backoff: float
        Initial backoff time for retryable errors
    retry_max_backoff: float
        Maximum backoff time
    retry_multiplier: float
        Factor to multiply backoff after each retry
    retry_jitter: float
        Jitter percentage applied to backoff (0.2 -> ±20%)
    """

    def __init__(
        self,
        pvwa_url: str,
        username: str,
        password: str,
        auth_timeout: int = 360,
        req_timeout: int = 360,
        verbose: bool = True,
        verify: Optional[Union[bool, str]] = None,
        retry_initial_backoff: float = 1.0,
        retry_max_backoff: float = 60.0,
        retry_multiplier: float = 2.0,
        retry_jitter: float = 0.2,
    ) -> None:
        if not pvwa_url or not pvwa_url.startswith(("http://", "https://")):
            raise ValueError("pvwa_url must start with http:// or https://")
        if not username or not password:
            raise ValueError("username and password are required")
        
        self.base = pvwa_url.rstrip("/")
        self.session = requests.Session()
        self.username = username
        self.password = password
        self.auth_timeout = auth_timeout
        self.req_timeout = req_timeout
        self.verbose = verbose
        self.token: Optional[str] = None
        self.logger = get_logger(verbose)

        if verify is None:
            if certifi:
                self.session.verify = certifi.where()
                self.logger.debug("Using certifi CA bundle: %s", self.session.verify)
            else:
                self.session.verify = True
                self.logger.debug("certifi not available; using system CA store")
        else:
            self.session.verify = verify
            if verify is False:
                self.logger.warning(
                    "SSL verification DISABLED (insecure). Use only if you understand the risk."
                )
            else:
                self.logger.debug("Using provided CA bundle for verification: %s", verify)

        self.retry_initial_backoff = retry_initial_backoff
        self.retry_max_backoff = retry_max_backoff
        self.retry_multiplier = retry_multiplier
        self.retry_jitter = retry_jitter

    # ------------------------------------------------------------------
    # Low-level request handling
    # ------------------------------------------------------------------
    def _request_with_retries(
        self,
        method: str,
        url: str,
        *,
        max_retries: Optional[int] = None,
        timeout: Optional[float] = None,
        raise_for_status: bool = True,
        **kwargs: Any,
    ) -> requests.Response:
        attempt = 0
        backoff = self.retry_initial_backoff
        timeout_val = timeout or self.req_timeout

        while True:
            attempt += 1
            try:
                self.logger.debug("Request attempt %d: %s %s", attempt, method, url)
                resp = self.session.request(method, url, timeout=timeout_val, **kwargs)
                if raise_for_status:
                    resp.raise_for_status()
                if attempt > 1:
                    self.logger.info("Request succeeded on attempt %d: %s", attempt, url)
                return resp
            except requests.exceptions.SSLError as e:
                self.logger.error("SSL error on attempt %d for %s: %s", attempt, url, e)
                if self.session.verify is False:
                    raise
                self.logger.error(
                    "CERTIFICATE VERIFY FAILED. Remedies: install CA bundle, install certifi, or use --insecure for testing."
                )
                raise
            except requests.exceptions.ConnectionError as e:
                self.logger.warning("ConnectionError attempt %d for %s: %s", attempt, url, e)
                if max_retries is not None and attempt >= max_retries:
                    self.logger.error("Reached max_retries=%s for %s", max_retries, url)
                    raise
                jitter = 1.0 + random.uniform(-self.retry_jitter, self.retry_jitter)
                sleep_time = max(
                    0.0, min(self.retry_max_backoff, backoff * jitter)
                )
                self.logger.debug("Sleeping %.2fs before retry", sleep_time)
                time.sleep(sleep_time)
                backoff = min(self.retry_max_backoff, backoff * self.retry_multiplier)
                continue
            except requests.exceptions.HTTPError as e:
                resp = getattr(e, "response", None)
                status = resp.status_code if resp is not None else None
                if status == 401:
                    allowed_retries = max_retries if max_retries is not None else 3
                    if attempt >= allowed_retries:
                        self.logger.error(
                            "Authentication retries exhausted for %s", url
                        )
                        raise
                    self.logger.info(
                        "HTTP 401 received. Attempting re-authentication (attempt %d)",
                        attempt,
                    )
                    self.authenticate()
                    jitter = 1.0 + random.uniform(-self.retry_jitter, self.retry_jitter)
                    sleep_time = max(
                        0.0, min(self.retry_max_backoff, backoff * jitter)
                    )
                    time.sleep(sleep_time)
                    backoff = min(
                        self.retry_max_backoff, backoff * self.retry_multiplier
                    )
                    continue
                raise
            except Exception:
                self.logger.exception("Unexpected exception during request to %s", url)
                raise

    # ------------------------------------------------------------------
    # API endpoints
    # ------------------------------------------------------------------
    def authenticate(self) -> None:
        url = f"{self.base}/PasswordVault/API/Auth/CyberArk/Logon"
        resp = self._request_with_retries(
            "POST",
            url,
            json={"username": self.username, "password": self.password},
            timeout=self.auth_timeout,
        )
        token_value: Any
        try:
            token_value = resp.json()
        except ValueError:
            token_value = resp.text
        if isinstance(token_value, dict):
            token_value = (
                token_value.get("CyberArkLogonResult")
                or token_value.get("token")
                or json.dumps(token_value)
            )
        self.token = str(token_value)
        self.session.headers.update({"Authorization": self.token})
        self.logger.info("Authenticated successfully")

    def list_safes(
        self, *, limit_count: Optional[int] = None, search: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        safes: List[Dict[str, Any]] = []
        limit = SAFE_PAGE_LIMIT
        offset = 0
        while True:
            url = f"{self.base}/PasswordVault/API/safes?limit={limit}&offset={offset}"
            if search:
                url += f"&search={requests.utils.quote(search)}"
            resp = self._request_with_retries("GET", url)
            data = resp.json()
            page = data.get("value", [])
            safes.extend(page)
            if limit_count is not None and len(safes) >= limit_count:
                safes = safes[:limit_count]
                break
            if len(page) < limit:
                break
            offset += limit
        self.logger.info("Collected %d safes", len(safes))
        return safes

    def list_safe_members(self, safe_name: str, safe_url_id: str) -> List[Dict[str, Any]]:
        members: List[Dict[str, Any]] = []
        limit = 1000
        offset = 0
        safe_name_encoded = quote(safe_name, safe='')
        while True:
            url = f"{self.base}/PasswordVault/API/Safes/{safe_name_encoded}/Members?limit={limit}&offset={offset}"
            resp = self._request_with_retries("GET", url)
            data = resp.json()
            page = data.get("value", [])
            members.extend(page)
            if len(page) < limit:
                break
            offset += limit
        return members

    def get_group_details(self, group_id: str) -> Optional[Dict[str, Any]]:
        if not group_id:
            return None
        url = f"{self.base}/PasswordVault/API/UserGroups/{group_id}?includeMembers=true"
        try:
            resp = self._request_with_retries("GET", url)
            return resp.json()
        except Exception as e:  # pragma: no cover network
            self.logger.warning("Failed to get details for group %s: %s", group_id, e)
            return None

    def list_accounts(
        self, safe_name: str, safe_url_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        accounts: List[Dict[str, Any]] = []
        limit = 1000
        offset = 0
        # URL-encode the filter parameter (no quotes needed in the filter value)
        filter_value = f"safeName eq {safe_name}"
        while True:
            url = f"{self.base}/PasswordVault/API/Accounts?limit={limit}&offset={offset}&filter={requests.utils.quote(filter_value)}"
            resp = self._request_with_retries("GET", url)
            data = resp.json()
            page = data.get("value", [])
            accounts.extend(page)
            if len(page) < limit:
                break
            offset += limit
        return accounts

    def get_account_details(self, account_id: str) -> Optional[Dict[str, Any]]:
        url = f"{self.base}/PasswordVault/API/Accounts/{account_id}"
        try:
            resp = self._request_with_retries("GET", url, raise_for_status=True)
        except requests.exceptions.HTTPError as e:  # pragma: no cover network
            if (
                hasattr(e, "response")
                and e.response is not None
                and e.response.status_code == 404
            ):
                return None
            raise
        if resp.status_code == 404:
            return None
        return resp.json()

    def get_account_activities(self, account_id: str, *, limit: int = 100, days_back: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get recent activities for an account.
        
        Parameters
        ----------
        account_id: str
            The account ID to query
        limit: int
            Maximum number of activities to return (default: 100)
        days_back: Optional[int]
            Number of days to look back (default: None for all activities)
            Activities are filtered client-side based on the Date field (Unix timestamp)
            
        Returns
        -------
        List[Dict[str, Any]]
            List of activity records with fields: User, Action, Date (Unix timestamp), 
            ActionID, ClientID, Reason, MoreInfo, Alert
        """
        url = f"{self.base}/PasswordVault/API/Accounts/{account_id}/Activities"
        
        try:
            resp = self._request_with_retries("GET", url, raise_for_status=True)
            raw_response = resp.json()
            activities = raw_response.get("Activities", [])
            
            # Debug: Log the raw response structure
            self.logger.debug("=== Account Activities API Response Debug ===")
            self.logger.debug("Account ID: %s", account_id)
            self.logger.debug("Response keys: %s", list(raw_response.keys()))
            self.logger.debug("Total activities returned: %d", len(activities))
            if activities:
                self.logger.debug("First activity sample: %s", json.dumps(activities[0], indent=2, default=str))
                self.logger.debug("First activity keys: %s", list(activities[0].keys()))
            self.logger.debug("===========================================")
            
            # Filter by time if days_back specified
            # API returns "Date" as Unix timestamp (epoch seconds)
            if days_back is not None and activities:
                from datetime import datetime, timezone, timedelta
                import time as time_module
                cutoff_timestamp = time_module.time() - (days_back * 86400)
                
                filtered = []
                for act in activities:
                    activity_date = act.get("Date")  # Unix timestamp
                    if activity_date:
                        try:
                            # Compare Unix timestamps directly
                            if activity_date >= cutoff_timestamp:
                                filtered.append(act)
                        except Exception:
                            # If comparison fails, include the activity
                            filtered.append(act)
                    else:
                        # No date, include it
                        filtered.append(act)
                
                activities = filtered
                self.logger.debug("Filtered to %d activities within last %d days", len(activities), days_back)
            
            # Apply limit
            if limit and len(activities) > limit:
                activities = activities[:limit]
            
            return activities
        except requests.exceptions.HTTPError as e:  # pragma: no cover network
            if (
                hasattr(e, "response")
                and e.response is not None
                and e.response.status_code in (404, 403)
            ):
                # Account doesn't exist or no permission to view activities
                self.logger.debug("No activities available for account %s: %s", account_id, e)
                return []
            raise
        except Exception as e:  # pragma: no cover
            self.logger.warning("Failed to get activities for account %s: %s", account_id, e)
            return []

    def get_linked_accounts(self, account_id: str) -> List[Dict[str, Any]]:
        """Get linked accounts for an account (logon, reconcile, enable).

        Parameters
        ----------
        account_id: str
            The account ID to query

        Returns
        -------
        List[Dict[str, Any]]
            List of linked account records with fields: Name, FolderPath,
            SafeName, AccountID, ExtraPassID (1=Logon, 2=Enable, 3=Reconcile)
        """
        url = f"{self.base}/PasswordVault/API/Accounts/{account_id}/LinkedAccounts"
        try:
            resp = self._request_with_retries("GET", url, raise_for_status=True)
            linked = resp.json()
            if isinstance(linked, dict):
                linked = linked.get("value", [])
            self.logger.debug("Account %s: fetched %d linked accounts", account_id, len(linked))
            return linked
        except requests.exceptions.HTTPError as e:
            resp_obj = getattr(e, "response", None)
            if resp_obj is not None and resp_obj.status_code in (404, 403):
                self.logger.debug("No linked accounts available for account %s", account_id)
                return []
            self.logger.debug("Failed to get linked accounts for account %s: %s", account_id, e)
            return []
        except Exception as e:
            self.logger.warning("Failed to get linked accounts for account %s: %s", account_id, e)
            return []

    def list_platforms(self) -> List[Dict[str, Any]]:
        """Retrieve all target platforms.

        Returns
        -------
        List[Dict[str, Any]]
            List of platform records with nested 'general' containing
            id, name, systemType, active, description.
        """
        platforms: List[Dict[str, Any]] = []
        limit = 500
        offset = 0
        while True:
            url = f"{self.base}/PasswordVault/API/Platforms/Targets?limit={limit}&offset={offset}"
            resp = self._request_with_retries("GET", url)
            data = resp.json()
            page = data.get("Platforms", []) or data.get("value", [])
            platforms.extend(page)
            if len(page) < limit:
                break
            offset += len(page)
        self.logger.info("Collected %d platforms", len(platforms))
        return platforms

    def list_users(self, *, limit_count: Optional[int] = None) -> List[Dict[str, Any]]:
        users: List[Dict[str, Any]] = []
        url = f"{self.base}/PasswordVault/API/Users?ExtendedDetails=true"
        try:
            resp = self._request_with_retries("GET", url)
            j = resp.json()
            users = j.get("Users", []) or j.get("value", [])
        except Exception:
            self.logger.warning("ExtendedDetails failed; falling back to basic list")
            url_basic = f"{self.base}/PasswordVault/API/Users"
            resp = self._request_with_retries("GET", url_basic)
            j = resp.json()
            users = j.get("Users", []) or j.get("value", [])
        if limit_count is not None and len(users) > limit_count:
            users = users[:limit_count]
        self.logger.info("Collected %d users", len(users))
        return users

    def list_groups(self, *, limit_count: Optional[int] = None) -> List[Dict[str, Any]]:
        url = f"{self.base}/PasswordVault/API/UserGroups"
        resp = self._request_with_retries("GET", url)
        groups = resp.json().get("value", [])
        if limit_count is not None and len(groups) > limit_count:
            groups = groups[:limit_count]
        enriched: List[Dict[str, Any]] = []
        for g in groups:
            # Use only documented API fields: id and groupName
            group_id = g.get("id") or g.get("groupName")
            details = self.get_group_details(str(group_id)) if group_id else None
            if details:
                merged = {**g, **details}
                enriched.append(merged)
            else:
                enriched.append(g)
        self.logger.info("Collected %d groups (enriched)", len(enriched))
        return enriched

    def logoff(self) -> None:
        """Terminate the session with PVWA."""
        if not self.token:
            return
        url = f"{self.base}/PasswordVault/API/Auth/Logoff"
        try:
            self._request_with_retries("POST", url, timeout=30)
            self.logger.info("Logged off successfully")
        except Exception as e:
            self.logger.warning("Logoff failed: %s", e)
        finally:
            self.token = None
            if "Authorization" in self.session.headers:
                del self.session.headers["Authorization"]
