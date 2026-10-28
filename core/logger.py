import os
import json
import threading
from datetime import datetime, timezone

class HoneypotLogger:
    """Thread-safe structured JSON logger for honeypot events."""
    
    _lock = threading.Lock()

    def __init__(self, log_dir="logs", log_file="honeypot_events.json"):
        self.log_dir = log_dir
        self.log_path = os.path.join(log_dir, log_file)
        os.makedirs(self.log_dir, exist_ok=True)

    def log_event(self, protocol: str, event_type: str, src_ip: str, src_port: int, details: dict):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": protocol.upper(),
            "event_type": event_type,
            "src_ip": src_ip,
            "src_port": src_port,
            "details": details
        }
        
        # Format terminal message
        tag = f"[{event['timestamp'][:19]} UTC] [{protocol.upper():4}] [{event_type}]"
        info = " | ".join(f"{k}={v}" for k, v in details.items() if v)
        print(f"\033[93m{tag}\033[0m \033[96m{src_ip}:{src_port}\033[0m -> {info}")

        # Write to JSONL
        with self._lock:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
