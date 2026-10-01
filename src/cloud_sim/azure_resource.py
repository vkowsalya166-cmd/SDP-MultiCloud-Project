"""Simulated Azure backend resource (e.g., an App Service admin API)."""
from src.cloud_sim.base_resource import CloudResource


class AzureResource(CloudResource):
    def __init__(self, name: str = "azure-app-01", sensitivity: str = "medium"):
        super().__init__(name=name, cloud="azure", sensitivity=sensitivity)

    def handle_request(self, client_id: str) -> dict:
        result = super().handle_request(client_id)
        result["simulated_data"] = {"deployment_slots": ["staging", "production"], "status": "running"}
        return result
