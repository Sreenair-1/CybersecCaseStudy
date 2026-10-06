from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class Service:
    service_id: str
    zone: str
    backs_resource: str
    criticality: int


def build_services() -> Dict[str, Service]:
    services = [
        Service("web_frontend", "public", "public_docs", 1),
        Service("hr_app", "application", "hr_portal", 2),
        Service("commerce_worker", "application", "app_service", 3),
        Service("internal_api_service", "internal", "internal_api", 3),
        Service("db_listener", "database", "orders_db", 4),
        Service("admin_plane", "admin", "admin_console", 5),
    ]
    return {service.service_id: service for service in services}

