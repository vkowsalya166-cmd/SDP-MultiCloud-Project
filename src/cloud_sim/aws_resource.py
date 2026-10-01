"""Simulated AWS backend resource (e.g., an RDS database)."""
from src.cloud_sim.base_resource import CloudResource


class AWSResource(CloudResource):
    def __init__(self, name: str = "aws-db-01", sensitivity: str = "high"):
        super().__init__(name=name, cloud="aws", sensitivity=sensitivity)

    def handle_request(self, client_id: str) -> dict:
        result = super().handle_request(client_id)
        result["simulated_data"] = {"table": "customers", "row_count": 15230}
        return result
