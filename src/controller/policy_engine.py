"""
Policy Engine: decides whether a given user may access a given resource,
implementing the SDP "need-to-know" least-privilege principle.
"""
from typing import Dict, Any, Optional
import yaml
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "config.yaml")


class PolicyEngine:
    def __init__(self, config_path: str = CONFIG_PATH):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        self.users = self.config.get("users", {})
        self.resources = self.config.get("resources", {})
        self.gateways = self.config.get("gateways", {})

    def is_authorized(self, client_id: str, resource: str) -> bool:
        """Least-privilege check: is `resource` in this user's allow-list?"""
        user = self.users.get(client_id)
        if not user:
            return False
        return resource in user.get("allowed_resources", [])

    def resolve_gateway(self, resource: str) -> Optional[Dict[str, Any]]:
        """Map a resource to the cloud gateway that fronts it."""
        res_info = self.resources.get(resource)
        if not res_info:
            return None
        cloud = res_info["cloud"]
        gw = self.gateways.get(cloud)
        if not gw:
            return None
        return {"cloud": cloud, **gw}

    def resource_sensitivity(self, resource: str) -> Optional[str]:
        res_info = self.resources.get(resource)
        return res_info["sensitivity"] if res_info else None
