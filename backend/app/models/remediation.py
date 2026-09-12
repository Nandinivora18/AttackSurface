"""
Remediation Enums (preserved for migration history compatibility).
The active remediation engine and models have been removed.
"""
import enum


class ConnectionType(str, enum.Enum):
    git_repo = "git_repo"
    local_project = "local_project"
    generic = "generic"


class RemediationStatus(str, enum.Enum):
    NOT_AVAILABLE = "NOT_AVAILABLE"
    MANUAL_FIX_REQUIRED = "MANUAL_FIX_REQUIRED"
    AVAILABLE = "AVAILABLE"
    PREVIEWING = "PREVIEWING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    BACKUP_CREATED = "BACKUP_CREATED"
    APPLYING = "APPLYING"
    VALIDATING = "VALIDATING"
    VERIFYING = "VERIFYING"
    FIXED = "FIXED"
    PARTIALLY_FIXED = "PARTIALLY_FIXED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
