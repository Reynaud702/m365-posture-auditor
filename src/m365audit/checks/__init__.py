"""Security checks. Importing each module registers its checks."""

from .base import all_checks, register, Check  # noqa: F401
from . import identity, email, sharepoint, oauth, conditional_access  # noqa: F401
