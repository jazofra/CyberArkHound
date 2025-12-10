"""Authentication strategies for CyberArkHound.

This module provides an abstraction layer for different CyberArk authentication methods:
- CyberArkAuthenticator: On-premise PAM authentication
- ISPSSAuthenticator: Identity Security Platform Shared Services (Privilege Cloud)
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class Authenticator(ABC):
    """Abstract base class for authentication strategies."""

    @abstractmethod
    def authenticate(self) -> None:
        """Perform authentication. Raises exception on failure."""
        pass

    @abstractmethod
    def get_token(self) -> str:
        """Return the current authentication token."""
        pass

    @abstractmethod
    def get_base_url(self) -> str:
        """Return the PVWA base URL for API calls."""
        pass

    @abstractmethod
    def is_ispss(self) -> bool:
        """Return True if this is an ISPSS authenticator (affects header format)."""
        pass

    @abstractmethod
    def logoff(self) -> None:
        """Terminate the session."""
        pass


class CyberArkAuthenticator(Authenticator):
    """On-premise CyberArk PAM authentication.

    This authenticator is a thin wrapper that stores configuration.
    Actual authentication is delegated to CyberArkClient for backward compatibility.
    """

    def __init__(self, base_url: str, username: str, password: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.token: Optional[str] = None

    def authenticate(self) -> None:
        """No-op: Authentication is handled by CyberArkClient for on-premise."""
        # Token is set by CyberArkClient after successful auth
        pass

    def get_token(self) -> str:
        return self.token or ""

    def get_base_url(self) -> str:
        return self.base_url

    def is_ispss(self) -> bool:
        return False

    def logoff(self) -> None:
        self.token = None


class ISPSSAuthenticator(Authenticator):
    """ISPSS (Privilege Cloud) authentication via ARK SDK.

    Uses CyberArk's ark-sdk-python for Identity Service User authentication.
    Automatically discovers PVWA URL from tenant subdomain.

    Parameters
    ----------
    username : str
        Identity Service User username (e.g., service-user@cyberark.cloud.12345)
    password : str
        Service user password
    identity_url : str, optional
        Override Identity URL for GovCloud/custom deployments
    """

    def __init__(
        self,
        username: str,
        password: str,
        identity_url: Optional[str] = None,
    ) -> None:
        self.username = username
        self.password = password
        self.identity_url = identity_url
        self.token: Optional[str] = None
        self.pvwa_url: Optional[str] = None
        self._isp_auth = None

    def authenticate(self) -> None:
        """Authenticate using ARK SDK Identity Service User method."""
        # Import here to avoid dependency issues if ark-sdk-python not installed
        try:
            from ark_sdk_python.auth import ArkISPAuth
            from ark_sdk_python.models.auth import (
                ArkAuthMethod,
                ArkAuthProfile,
                ArkSecret,
                IdentityServiceUserArkAuthMethodSettings,
            )
        except ImportError as e:
            raise ImportError(
                "ark-sdk-python is required for ISPSS authentication. "
                "Install with: pip install ark-sdk-python"
            ) from e

        logger.debug("Authenticating to ISPSS as user %s", self.username)

        self._isp_auth = ArkISPAuth(cache_authentication=False)

        # Build auth method settings
        settings = IdentityServiceUserArkAuthMethodSettings()
        if self.identity_url:
            settings.identity_url = self.identity_url

        # Authenticate using Identity Service User method
        try:
            token_result = self._isp_auth.authenticate(
                auth_profile=ArkAuthProfile(
                    username=self.username,
                    auth_method=ArkAuthMethod.IdentityServiceUser,
                    auth_method_settings=settings,
                ),
                secret=ArkSecret(secret=self.password),
            )
        except Exception as e:
            raise RuntimeError(f"ISPSS authentication failed: {e}") from e

        # Store JWT token
        self.token = token_result.token

        # Extract tenant subdomain from Identity endpoint
        tenant_subdomain = self._extract_tenant_subdomain(token_result.endpoint)

        # Construct PVWA URL
        self.pvwa_url = f"https://{tenant_subdomain}.privilegecloud.cyberark.cloud"

        logger.info("ISPSS authentication successful")
        logger.info("Identity endpoint: %s", token_result.endpoint)
        logger.info("PVWA URL (auto-discovered): %s", self.pvwa_url)

    def get_token(self) -> str:
        return self.token or ""

    def get_base_url(self) -> str:
        return self.pvwa_url or ""

    def is_ispss(self) -> bool:
        return True

    def logoff(self) -> None:
        """Clear token (ISPSS doesn't require explicit logoff)."""
        self.token = None
        logger.info("ISPSS session cleared")

    @staticmethod
    def _extract_tenant_subdomain(identity_url: str) -> str:
        """Extract tenant subdomain from Identity URL.

        "https://abc123.id.cyberark.cloud" -> "abc123"

        Raises
        ------
        ValueError
            If subdomain cannot be extracted
        """
        if not identity_url:
            raise ValueError("Identity URL is empty")

        parsed = urlparse(identity_url)
        host = parsed.hostname or ""

        if not host:
            raise ValueError(f"No hostname in identity URL: {identity_url}")

        parts = host.split(".")
        if not parts or not parts[0]:
            raise ValueError(f"Cannot extract subdomain from hostname: {host}")

        return parts[0]
