__version__ = "0.1.0"
from .scanner import scan_text, scan_file, SecretFinding
__all__ = ["scan_text", "scan_file", "SecretFinding"]
