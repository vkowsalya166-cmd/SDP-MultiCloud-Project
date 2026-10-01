"""Base class for simulated cloud backend resources."""


class CloudResource:
    def __init__(self, name: str, cloud: str, sensitivity: str):
        self.name = name
        self.cloud = cloud
        self.sensitivity = sensitivity

    def describe(self) -> str:
        return f"{self.name} ({self.cloud}, sensitivity={self.sensitivity})"

    def handle_request(self, client_id: str) -> dict:
        """Simulate serving a request once SDP access has been granted."""
        return {
            "resource": self.name,
            "cloud": self.cloud,
            "served_to": client_id,
            "message": f"Simulated response from {self.name}",
        }
