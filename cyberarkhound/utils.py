import json
import logging
import os
import re
from typing import Any, Dict

_COMPLEX_PROPERTIES = {
    'safePermissions',
    'authorizedInterfaces',
    'vaultAuthorization',
    'permissions',
    'matchedPermissionNames',
    'matchedPermissionParameters'
}

_LOGGER_NAME = "cyberarkhound"


def get_logger(verbose: bool = True) -> logging.Logger:
    """Return a configured logger instance.

    Logging level can be overridden by environment CYBERARKHOUND_LOG_LEVEL.
    """
    logger = logging.getLogger(_LOGGER_NAME)
    if not logger.handlers:
        handler = logging.StreamHandler()
        fmt = logging.Formatter('[%(asctime)s] %(levelname)s %(name)s: %(message)s')
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    env_level = os.getenv('CYBERARKHOUND_LOG_LEVEL')
    if env_level:
        level = getattr(logging, env_level.upper(), logging.DEBUG)
    else:
        level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    return logger


def parse_domain_from_dn(dn: str) -> str:
    if not dn:
        return ""
    dc_parts = re.findall(r'DC=([^,]+)', dn, re.IGNORECASE)
    return ".".join(dc_parts).lower() if dc_parts else ""


def sanitize_properties_for_bloodhound(props: Dict[str, Any]) -> Dict[str, Any]:
    sanitized: Dict[str, Any] = {}
    for key, value in props.items():
        if value is None:
            continue
        if key in _COMPLEX_PROPERTIES:
            # Use separators for compact JSON
            sanitized[key] = json.dumps(value, separators=(',', ':'))
            continue
        value_type = type(value)
        if value_type in (str, int, float, bool):
            sanitized[key] = value
        elif value_type is list:
            if not value:
                continue
            # Quick primitive check without all()
            first = value[0]
            first_type = type(first)
            if first_type in (str, int, float, bool):
                # Assume homogeneous for performance
                sanitized[key] = value
            else:
                sanitized[key] = json.dumps(value, separators=(',', ':'))
        else:
            sanitized[key] = json.dumps(value, separators=(',', ':'))
    return sanitized
