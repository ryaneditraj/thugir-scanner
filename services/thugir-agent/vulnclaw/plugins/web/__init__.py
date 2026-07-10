from __future__ import annotations

from vulnclaw.plugins.web.headers import SecurityHeadersPlugin
from vulnclaw.plugins.web.js_endpoints import JavaScriptEndpointsPlugin
from vulnclaw.plugins.web.jwt import JWTClaimsPlugin

BUILTIN_WEB_PLUGINS = (
    SecurityHeadersPlugin,
    JWTClaimsPlugin,
    JavaScriptEndpointsPlugin,
)


__all__ = [
    "BUILTIN_WEB_PLUGINS",
    "JWTClaimsPlugin",
    "JavaScriptEndpointsPlugin",
    "SecurityHeadersPlugin",
]
