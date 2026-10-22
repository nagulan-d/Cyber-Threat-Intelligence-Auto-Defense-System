"""
Centralized IP Blocking Synchronization Manager
Coordinates blocking operations across Windows host and Linux VM(s)
Ensures consistency, handles rollbacks, and maintains audit logs
"""

import json
import logging
import os
import threading
from datetime import datetime, timedelta
from importlib.util import find_spec
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import jwt
import requests
import websockets

# Detect optional WebSocket support without importing an unused module.
WS_AVAILABLE = find_spec("websocket_server") is not None

# Import IP blocker
from ip_blocker import ip_blocker  # noqa: E402

logger = logging.getLogger(__name__)


class BlockingSyncManager:
    """
    Centralized manager for IP blocking synchronization
    Ensures all blocking operations are atomic and synchronized
    """

    def __init__(self, db_session=None):
        self.db = db_session
        self.blocking_lock = threading.Lock()
        self.pending_blocks: Dict[str, Dict[str, Any]] = {}
        self.failed_blocks: Dict[str, List[Dict[str, Any]]] = {}
        self.sync_log_file = Path(__file__).parent / "logs" / "blocking_sync.log"
        self.sync_log_file.parent.mkdir(exist_ok=True)

        # Create dedicated logger for sync operations
        self.sync_logger = logging.getLogger("sync_manager")
        handler = logging.FileHandler(self.sync_log_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s - [SYNC] %(levelname)s - %(message)s"))
        self.sync_logger.handlers.clear()
        self.sync_logger.addHandler(handler)
        self.sync_logger.setLevel(logging.INFO)
        # Prevent double logging through root handlers with non-UTF-8 streams on Windows.
        self.sync_logger.propagate = False

        logger.info("BlockingSyncManager initialized")

    def set_db_session(self, db_session):
        """Set database session (called from Flask app context)"""
        self.db = db_session

    def _build_ws_url(self) -> str:
        ws_url = os.getenv("WS_SERVER_URL")
        if ws_url:
            return ws_url
        host = os.getenv("WS_HOST", "127.0.0.1")
        if host == "0.0.0.0":
            host = "127.0.0.1"
        port = os.getenv("WS_PORT", "8765")
        return f"ws://{host}:{port}"

    def _build_vm_api_config(self) -> Dict[str, Any]:
        """Build Kali enhanced-agent API configuration."""
        vm_host = os.getenv("LINUX_VM_API_HOST") or os.getenv("LINUX_VM_HOST") or "192.168.56.50"
        vm_port = int(os.getenv("LINUX_VM_API_PORT") or os.getenv("LINUX_VM_PORT", "5001"))
        vm_token = os.getenv("LINUX_VM_API_TOKEN") or os.getenv("BLOCKING_API_TOKEN") or ""
        timeout = int(os.getenv("LINUX_VM_API_TIMEOUT", "8"))
        return {
            "host": vm_host,
            "port": vm_port,
            "token": vm_token,
            "timeout": timeout,
        }

    def _notify_vm_api_block(
        self, ip_address: str, threat_data: Dict[str, Any], reason: str
    ) -> bool:
        """Fallback sync to Kali enhanced agent via REST API."""
        cfg = self._build_vm_api_config()
        if not cfg["host"]:
            self.sync_logger.warning(
                "VM API sync skipped: LINUX_VM_API_HOST/LINUX_VM_HOST not configured"
            )
            return False

        url = f"http://{cfg['host']}:{cfg['port']}/api/blocking/block"
        headers = {"Content-Type": "application/json"}
        if cfg["token"]:
            headers["Authorization"] = f"Bearer {cfg['token']}"

        payload = {
            "ip_address": ip_address,
            "reason": reason or threat_data.get("summary", "Security threat"),
            "threat_type": threat_data.get("threat_type", "Unknown"),
            "risk_score": threat_data.get("risk_score", 0),
            "rule_type": "THREATGUARD",
            "timestamp": datetime.utcnow().isoformat(),
        }

        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=cfg["timeout"])
            if resp.status_code in (200, 201):
                self.sync_logger.info(f"VM API block synced for {ip_address}")
                return True

            self.sync_logger.warning(
                f"VM API block failed for {ip_address}: HTTP {resp.status_code} {resp.text[:200]}"
            )
            return False
        except Exception as e:
            self.sync_logger.warning(f"VM API block exception for {ip_address}: {e}")
            return False

    def _notify_vm_api_unblock(self, ip_address: str, user_id: int) -> bool:
        """Fallback unsync to Kali enhanced agent via REST API."""
        cfg = self._build_vm_api_config()
        if not cfg["host"]:
            self.sync_logger.warning(
                "VM API unblock skipped: LINUX_VM_API_HOST/LINUX_VM_HOST not configured"
            )
            return False

        url = f"http://{cfg['host']}:{cfg['port']}/api/blocking/unblock"
        headers = {"Content-Type": "application/json"}
        if cfg["token"]:
            headers["Authorization"] = f"Bearer {cfg['token']}"

        payload = {
            "ip_address": ip_address,
            "unblocked_by": user_id,
            "timestamp": datetime.utcnow().isoformat(),
        }

        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=cfg["timeout"])
            if resp.status_code in (200, 201):
                self.sync_logger.info(f"VM API unblock synced for {ip_address}")
                return True

            self.sync_logger.warning(
                f"VM API unblock failed for {ip_address}: HTTP {resp.status_code} {resp.text[:200]}"
            )
            return False
        except Exception as e:
            self.sync_logger.warning(f"VM API unblock exception for {ip_address}: {e}")
            return False

    def _get_ws_token(self) -> str:
        token = os.getenv("WS_SERVER_TOKEN")
        if token:
            return token
        secret = os.getenv("SECRET_KEY", "default_secret")
        payload = {"user_id": 0, "role": "admin", "exp": datetime.utcnow() + timedelta(minutes=5)}
        return jwt.encode(payload, secret, algorithm="HS256")

    async def _notify_ws_server(self, message: Dict[str, Any]) -> bool:
        ws_url = self._build_ws_url()
        token = self._get_ws_token()
        auth = {"token": token, "client_type": "admin", "agent_id": "backend-service"}
        try:
            async with websockets.connect(ws_url, open_timeout=5) as ws:
                await ws.send(json.dumps(auth))
                await ws.send(json.dumps(message))
            return True
        except Exception as e:
            self.sync_logger.error(f"WebSocket server notify failed: {e}")
            return False

    async def block_ip_synchronized(
        self,
        ip_address: str,
        threat_data: Dict[str, Any],
        user_id: int,
        blocked_by: str = "admin",
        reason: str = "",
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Perform synchronized IP blocking across host and VM(s)
        Returns: (success, message, threat_record)
        """
        with self.blocking_lock:
            self.sync_logger.info(f"Starting synchronized block for {ip_address}")

            # Step 1: Validate IP
            if not self._validate_ip(ip_address):
                return False, f"Invalid IP address: {ip_address}", None

            # Step 2: Check for duplicates in database
            if self.db:
                from app import BlockedThreat

                existing = (
                    self.db.query(BlockedThreat)
                    .filter_by(ip_address=ip_address, is_active=True)
                    .first()
                )

                if existing:
                    self.sync_logger.warning(f"IP {ip_address} already blocked")
                    return False, f"IP {ip_address} already blocked", None

            # Track this operation
            operation_id = f"block_{ip_address}_{datetime.utcnow().timestamp()}"
            self.pending_blocks[ip_address] = {
                "operation_id": operation_id,
                "start_time": datetime.utcnow(),
                "ip_address": ip_address,
                "user_id": user_id,
                "threat_data": threat_data,
            }

            windows_blocked = False
            vm_blocked = False
            db_record = None

            try:
                # Step 3: Block on Windows host
                self.sync_logger.info(f"[{operation_id}] Blocking on Windows host...")
                windows_success, windows_msg = ip_blocker.block_ip(
                    ip_address, reason or threat_data.get("summary", "Security threat")
                )

                if not windows_success:
                    self.sync_logger.error(f"[{operation_id}] Windows block failed: {windows_msg}")
                    return False, f"Windows firewall error: {windows_msg}", None

                windows_blocked = True
                self.sync_logger.info(f"[{operation_id}] [OK] Windows host blocked")

                # Step 4: Create database record
                if self.db:
                    self.sync_logger.info(f"[{operation_id}] Creating database record...")

                    from app import BlockedThreat

                    db_record = BlockedThreat(
                        user_id=user_id,
                        ip_address=ip_address,
                        threat_type=threat_data.get("threat_type", "Unknown"),
                        risk_category=threat_data.get("risk_category", "High"),
                        risk_score=threat_data.get("risk_score", 0),
                        summary=threat_data.get("summary", ""),
                        blocked_by=blocked_by,
                        blocked_by_user_id=threat_data.get("blocked_by_user_id"),
                        reason=reason,
                        is_active=True,
                    )

                    self.db.add(db_record)
                    self.db.flush()  # Get the ID without committing

                    self.sync_logger.info(
                        f"[{operation_id}] [OK] Database record created (ID: {db_record.id})"
                    )

                # Step 5: Notify VM agents via WebSocket server
                self.sync_logger.info(f"[{operation_id}] Notifying VM agents via WebSocket...")
                vm_blocked = await self._notify_ws_server(
                    {
                        "type": "broadcast_block",
                        "ip_address": ip_address,
                        "details": {
                            "threat_type": threat_data.get("threat_type", "Unknown"),
                            "risk_score": threat_data.get("risk_score", 0),
                            "reason": reason,
                            "summary": threat_data.get("summary", ""),
                            "blocked_by": blocked_by,
                            "operation_id": operation_id,
                        },
                    }
                )
                if vm_blocked:
                    self.sync_logger.info(f"[{operation_id}] [OK] VM agents notified via WebSocket")
                else:
                    self.sync_logger.warning(
                        f"[{operation_id}] VM agents not notified via WebSocket; trying VM API fallback"
                    )
                    vm_blocked = self._notify_vm_api_block(ip_address, threat_data, reason)
                    if vm_blocked:
                        self.sync_logger.info(
                            f"[{operation_id}] [OK] VM synced via REST API fallback"
                        )
                    else:
                        self.sync_logger.warning(
                            f"[{operation_id}] VM sync failed via both WebSocket and REST API"
                        )

                # Step 6: Commit database transaction
                if self.db:
                    self.db.commit()
                    self.sync_logger.info(f"[{operation_id}] [OK] Database transaction committed")

                # Step 7: Log the action
                if self.db and db_record:
                    from app import ThreatActionLog

                    action_log = ThreatActionLog(
                        user_id=user_id,
                        action="block",
                        ip_address=ip_address,
                        threat_id=db_record.id,
                        performed_by_user_id=threat_data.get("blocked_by_user_id"),
                        details=json.dumps(
                            {
                                "operation_id": operation_id,
                                "windows_blocked": windows_blocked,
                                "vm_notified": vm_blocked,
                                "threat_type": threat_data.get("threat_type"),
                                "risk_score": threat_data.get("risk_score"),
                                "auto_block": threat_data.get("auto_block", False),
                            }
                        ),
                    )
                    self.db.add(action_log)
                    self.db.commit()

                # Success!
                del self.pending_blocks[ip_address]

                success_msg = f"IP {ip_address} blocked successfully on "
                if windows_blocked and vm_blocked:
                    success_msg += "Windows and VM"
                elif windows_blocked:
                    success_msg += "Windows (VM sync pending)"

                self.sync_logger.info(f"[{operation_id}] [COMPLETE] {success_msg}")

                return True, success_msg, db_record

            except Exception as e:
                self.sync_logger.error(f"[{operation_id}] [ERROR] Exception during block: {e}")

                # Rollback database
                if self.db:
                    self.db.rollback()
                    self.sync_logger.info(f"[{operation_id}] Database rolled back")

                # Rollback Windows firewall if it was blocked
                if windows_blocked:
                    self.sync_logger.info(f"[{operation_id}] Rolling back Windows firewall...")
                    try:
                        ip_blocker.unblock_ip(ip_address)
                        self.sync_logger.info(f"[{operation_id}] Windows rollback complete")
                    except Exception as rb_error:
                        self.sync_logger.error(
                            f"[{operation_id}] Windows rollback failed: {rb_error}"
                        )

                # Track failed operation
                if ip_address not in self.failed_blocks:
                    self.failed_blocks[ip_address] = []

                self.failed_blocks[ip_address].append(
                    {
                        "operation_id": operation_id,
                        "timestamp": datetime.utcnow().isoformat(),
                        "error": str(e),
                        "windows_blocked": windows_blocked,
                        "vm_blocked": vm_blocked,
                    }
                )

                # Clean up pending
                if ip_address in self.pending_blocks:
                    del self.pending_blocks[ip_address]

                return False, f"Blocking failed: {str(e)}", None

    async def unblock_ip_synchronized(
        self, ip_address: str, user_id: int, threat_id: Optional[int] = None
    ) -> Tuple[bool, str]:
        """
        Perform synchronized IP unblocking across host and VM(s)
        Returns: (success, message)
        """
        with self.blocking_lock:
            self.sync_logger.info(f"Starting synchronized unblock for {ip_address}")

            operation_id = f"unblock_{ip_address}_{datetime.utcnow().timestamp()}"

            windows_unblocked = False
            vm_notified = False

            try:
                # Step 1: Unblock on Windows host
                self.sync_logger.info(f"[{operation_id}] Unblocking on Windows host...")
                windows_success, windows_msg = ip_blocker.unblock_ip(ip_address)

                if windows_success:
                    windows_unblocked = True
                    self.sync_logger.info(f"[{operation_id}] [OK] Windows host unblocked")
                else:
                    self.sync_logger.warning(
                        f"[{operation_id}] Windows unblock warning: {windows_msg}"
                    )

                # Step 2: Update database record
                if self.db and threat_id:
                    from app import BlockedThreat

                    threat_record = (
                        self.db.query(BlockedThreat)
                        .filter_by(id=threat_id, ip_address=ip_address)
                        .first()
                    )

                    if threat_record:
                        threat_record.is_active = False
                        threat_record.unblocked_at = datetime.utcnow()
                        threat_record.unblocked_by_user_id = user_id
                        self.db.commit()
                        self.sync_logger.info(f"[{operation_id}] [OK] Database record updated")

                # Step 3: Notify VM agents
                self.sync_logger.info(f"[{operation_id}] Notifying VM agents...")
                vm_notified = await self._notify_ws_server(
                    {
                        "type": "broadcast_unblock",
                        "ip_address": ip_address,
                        "details": {"unblocked_by": user_id, "operation_id": operation_id},
                    }
                )
                if vm_notified:
                    self.sync_logger.info(f"[{operation_id}] [OK] VM agents notified via WebSocket")
                else:
                    self.sync_logger.warning(
                        f"[{operation_id}] VM agents not notified via WebSocket; trying VM API fallback"
                    )
                    vm_notified = self._notify_vm_api_unblock(ip_address, user_id)
                    if vm_notified:
                        self.sync_logger.info(
                            f"[{operation_id}] [OK] VM unsynced via REST API fallback"
                        )
                    else:
                        self.sync_logger.warning(
                            f"[{operation_id}] VM unsync failed via both WebSocket and REST API"
                        )

                # Step 4: Log the action
                if self.db:
                    from app import ThreatActionLog

                    action_log = ThreatActionLog(
                        user_id=user_id,
                        action="unblock",
                        ip_address=ip_address,
                        threat_id=threat_id,
                        performed_by_user_id=user_id,
                        details=json.dumps(
                            {
                                "operation_id": operation_id,
                                "windows_unblocked": windows_unblocked,
                                "vm_notified": vm_notified,
                            }
                        ),
                    )
                    self.db.add(action_log)
                    self.db.commit()

                self.sync_logger.info(f"[{operation_id}] [COMPLETE] Unblock successful")

                return True, f"IP {ip_address} unblocked successfully"

            except Exception as e:
                self.sync_logger.error(f"[{operation_id}] [ERROR] Exception during unblock: {e}")

                if self.db:
                    self.db.rollback()

                return False, f"Unblock failed: {str(e)}"

    def get_sync_status(self) -> Dict[str, Any]:
        """Get current synchronization status"""
        return {
            "pending_operations": len(self.pending_blocks),
            "failed_operations": sum(len(v) for v in self.failed_blocks.values()),
            "pending_ips": list(self.pending_blocks.keys()),
            "failed_ips": list(self.failed_blocks.keys()),
        }

    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        import re

        ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"

        if re.match(ipv4_pattern, ip):
            parts = ip.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                # Exclude critical IPs
                if ip not in ["0.0.0.0", "127.0.0.1", "255.255.255.255"]:
                    return True
        return False


# Global sync manager instance
sync_manager = BlockingSyncManager()
