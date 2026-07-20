"""Public contracts shared by built-in and third-party providers."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, Optional


class ErrorKind(str, Enum):
    CONFIGURATION = "configuration"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    RATE_LIMIT = "rate_limit"
    VALIDATION = "validation"
    TIMEOUT = "timeout"
    DEPENDENCY = "dependency"
    REMOTE_SERVICE = "remote_service"


class ProviderError(Exception):
    """A normalized provider failure safe to return through the API."""

    def __init__(
        self,
        kind: ErrorKind,
        message: str,
        *,
        retryable: bool = False,
        provider: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.kind = ErrorKind(kind)
        self.message = message
        self.retryable = retryable
        self.provider = provider
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": False,
            "error": self.message,
            "error_kind": self.kind.value,
            "retryable": self.retryable,
            "provider": self.provider,
            "metadata": self.metadata,
        }


class CertificateAuthorityProvider(ABC):
    """Stable extension contract for certificate authority providers."""

    name: str

    @abstractmethod
    def issue(self, request: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def renew(self, request: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def revoke(self, request: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def health(self) -> Dict[str, Any]:
        raise NotImplementedError


class DNSChallengeProvider(ABC):
    """Stable extension contract for ACME DNS-01 record lifecycle."""

    name: str

    @abstractmethod
    def present(self, domain: str, validation: str) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def cleanup(self, domain: str, record_id: str) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def health(self) -> Dict[str, Any]:
        raise NotImplementedError
