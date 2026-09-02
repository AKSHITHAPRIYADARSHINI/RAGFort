"""Phase 4 identity and authorization contracts.

Concrete OIDC/JWKS and database adapters are deliberately kept behind these
interfaces so neither routes nor RAG services trust browser supplied scope.
"""

from backend.app.auth.models import Principal, RequestContext
from backend.app.auth.policy import AuthorizationService, PolicyDecision

__all__ = ["AuthorizationService", "PolicyDecision", "Principal", "RequestContext"]
