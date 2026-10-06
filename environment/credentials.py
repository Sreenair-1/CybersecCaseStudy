from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class Credential:
    credential_id: str
    owner: str
    role: str
    scope: str
    resource_access: List[str]
    isolated: bool


def build_credentials(environment: str) -> Dict[str, Credential]:
    baseline = environment == "baseline"
    credentials = [
        Credential("employee_basic", "employee", "employee", "broad" if baseline else "user", ["public_docs", "hr_portal", "employee_records"] if baseline else ["public_docs", "hr_portal"], not baseline),
        Credential("hr_read", "hr", "employee", "department", ["employee_records", "hr_portal"], not baseline),
        Credential("svc_app", "service_bot", "service", "service" if not baseline else "broad", ["app_service", "internal_api", "orders_db"] if not baseline else ["app_service", "internal_api", "orders_db", "finance_db"], not baseline),
        Credential("svc_db", "service_bot", "service", "database", ["orders_db"], not baseline),
        Credential("admin_ops", "admin", "admin", "admin", ["admin_console", "ops_runbooks", "app_service"] if not baseline else ["admin_console", "ops_runbooks", "app_service", "credential_vault", "finance_db"], not baseline),
        Credential("vault_admin", "security", "admin", "vault", ["credential_vault"], not baseline),
        Credential("finance_read", "finance", "finance", "database", ["finance_db"], not baseline),
        Credential("repo_read", "developer", "developer", "source", ["source_repo"], not baseline),
        Credential("pii_access", "security", "security", "sensitive", ["customer_pii"], not baseline),
    ]
    return {credential.credential_id: credential for credential in credentials}

