from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class Resource:
    resource_id: str
    resource_type: str
    sensitivity: int
    owner: str
    network_zone: str
    required_role: str
    required_credential: str
    discoverable: bool


def build_resources() -> Dict[str, Resource]:
    resources = [
        Resource("public_docs", "public", 1, "communications", "public", "employee", "employee_basic", True),
        Resource("hr_portal", "application", 2, "hr", "application", "employee", "employee_basic", True),
        Resource("app_service", "application", 2, "engineering", "application", "service", "svc_app", True),
        Resource("internal_api", "internal", 3, "platform", "internal", "service", "svc_app", False),
        Resource("ops_runbooks", "internal", 3, "operations", "internal", "admin", "admin_ops", False),
        Resource("employee_records", "database", 4, "hr", "database", "employee", "hr_read", False),
        Resource("orders_db", "database", 4, "commerce", "database", "service", "svc_db", False),
        Resource("finance_db", "database", 5, "finance", "database", "finance", "finance_read", False),
        Resource("credential_vault", "credential_store", 5, "security", "admin", "admin", "vault_admin", False),
        Resource("admin_console", "admin_service", 5, "operations", "admin", "admin", "admin_ops", False),
        Resource("source_repo", "sensitive", 4, "engineering", "internal", "developer", "repo_read", False),
        Resource("customer_pii", "sensitive", 5, "security", "sensitive", "security", "pii_access", False),
    ]
    return {resource.resource_id: resource for resource in resources}


def is_sensitive(resource: Resource) -> bool:
    return resource.sensitivity >= 5 or resource.resource_type == "sensitive"

