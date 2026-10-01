"""Simulated GCP backend resource (e.g., a Cloud Storage admin endpoint)."""
from src.cloud_sim.base_resource import CloudResource


class GCPResource(CloudResource):
    def __init__(self, name: str = "gcp-storage-01", sensitivity: str = "medium"):
        super().__init__(name=name, cloud="gcp", sensitivity=sensitivity)

    def handle_request(self, client_id: str) -> dict:
        result = super().handle_request(client_id)
        result["simulated_data"] = {"bucket": "analytics-exports", "object_count": 842}
        return result
