import React, { useState } from "react";
import { API_URL } from "../config";

function ThreatCard({ threat = {}, users = [], token }) {
  // attempt to extract an IP address (IPv4 or IPv6) from indicator or summary
  const extractIP = (text) => {
    if (!text) return null;
    try {
      const s = text.toString();
      // IPv4 regex
      const ipv4 = s.match(/(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}/);
      if (ipv4) return ipv4[0];
      // simple IPv6 (may be compressed) - find groups of hex and colons
      const ipv6 = s.match(/([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}/);
      if (ipv6) return ipv6[0];
    } catch (e) {
      // ignore
    }
    return null;
  };

  const ipAddress = extractIP(threat.indicator) || extractIP(threat.summary) || extractIP(threat.type) || null;

  // if not found, try searching the raw OTX object more comprehensively
  const flattenForSearch = (val, depth = 0, maxDepth = 4, out = []) => {
    if (val == null || depth > maxDepth) return out;
    if (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean') {
      out.push(String(val));
      return out;
    }
    if (Array.isArray(val)) {
      for (const v of val) flattenForSearch(v, depth + 1, maxDepth, out);
      return out;
    }
    if (typeof val === 'object') {
      for (const k of Object.keys(val)) {
        try { flattenForSearch(val[k], depth + 1, maxDepth, out); } catch (e) { /* ignore */ }
      }
      return out;
    }
    return out;
  };

  let ipFromOtx = null;
  if (!ipAddress && threat.otx) {
    try {
      const pieces = flattenForSearch(threat.otx);
      const joined = pieces.join(' ');
      ipFromOtx = extractIP(joined);
    } catch (e) {
      ipFromOtx = null;
    }
  }

  const finalIP = ipAddress || ipFromOtx || null;
  // Prefer backend-provided ip_addresses when available
  const ipList = Array.isArray(threat.ip_addresses) && threat.ip_addresses.length > 0
    ? threat.ip_addresses
    : (finalIP ? [finalIP] : []);
  // Determine risk class - ALWAYS use threat.score as the source of truth
  const severity = (threat.severity || "").toLowerCase();
  const displayScore = threat.score ?? 0;  // Use score as the authoritative value
  let riskClass = "low";
  if (severity === "high" || displayScore >= 75) riskClass = "high";
  else if (severity === "medium" || (displayScore >= 50 && displayScore < 75)) riskClass = "medium";

  const [selectedUser, setSelectedUser] = useState(""); // For notification dropdown
  const [sending, setSending] = useState(false); // Disable button while sending
  const [blocking, setBlocking] = useState(false); // For block action
  const [showBlockModal, setShowBlockModal] = useState(false); // Show block confirmation

  const handleSendNotification = async () => {
    if (!selectedUser) {
      alert("Please select a user to notify.");
      return;
    }

    setSending(true);
    try {
      const res = await fetch(`${API_URL}/send-notification`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ threat, user_email: selectedUser }),
      });

      const data = await res.json().catch(() => ({}));
      if (res.ok && data.email_sent) {
        alert("Notification sent successfully!");
        setSelectedUser("");
      } else {
        const serverMsg = data.error || data.message || "Failed to send notification";
        alert(`Error sending notification: ${serverMsg}`);
      }
    } catch (err) {
      alert("Network error. Check console for details.");
      console.error("Send notification error:", err);
    } finally {
      setSending(false);
    }
  };

  const handleBlockThreat = async () => {
    if (!ipList || ipList.length === 0) {
      alert("No IP address found for this threat. Cannot block.");
      return;
    }

    const ipToBlock = ipList[0]; // Block the first IP
    setBlocking(true);

    try {
      const res = await fetch(`${API_URL}/block-threat`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          ip_address: ipToBlock,
          threat_type: threat.type || threat.category || "Unknown",
          risk_category: threat.severity || (displayScore >= 75 ? "High" : displayScore >= 50 ? "Medium" : "Low"),
          risk_score: displayScore || 0,
          summary: threat.summary || threat.title || "",
          reason: "Blocked from ThreatGuard Dashboard",
        }),
      });

      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        alert(`✓ IP ${ipToBlock} blocked successfully!\nFirewall rules created.`);
        setShowBlockModal(false);
      } else {
        const serverMsg = data.error || data.message || "Failed to block IP";
        alert(`Error: ${serverMsg}`);
      }
    } catch (err) {
      alert("Network error. Check console for details.");
      console.error("Block threat error:", err);
    } finally {
      setBlocking(false);
    }
  };

  const riskColors = {
    high: "#dc3545",
    medium: "#f0ad4e",
    low: "#28a745",
  };

  return (
    <div className={`threat-card ${riskClass}`} style={{ position: "relative" }}>
      <span
        style={{
          position: "absolute",
          top: 12,
          right: 12,
          background: riskColors[riskClass] || "#6c757d",
          color: riskClass === "medium" ? "#000" : "#fff",
          padding: "4px 10px",
          borderRadius: 999,
          fontWeight: 700,
          fontSize: "0.85rem",
          textTransform: "uppercase",
          boxShadow: "0 1px 3px rgba(0,0,0,0.15)",
        }}
      >
        {threat.severity || riskClass}
      </span>

      <h3>{threat.title || threat.indicator}</h3>
      <p><b>Threat ID:</b> <span className="threat-value">{threat.id || 'N/A'}</span></p>
      <p><b>IP Address:</b> <span className="threat-value">{ipList.length ? ipList.join(', ') : (threat.ip || 'N/A')}</span></p>
      <p><b>Category:</b> <span className="threat-value">{threat.category || "Other"}</span></p>
      <p><b>Threat Score:</b> <span className="threat-value">{displayScore}/100</span></p>
      <p><b>Threat Level:</b> <span className="threat-value">{(threat.severity || (riskClass.charAt(0).toUpperCase() + riskClass.slice(1)))}</span></p>
      <p><b>Type:</b> <span className="threat-value">{threat.type || 'N/A'}</span></p>
      <p><b>Status:</b> <span style={{ 
        color: threat.status === 'Active' ? '#dc3545' : threat.status === 'Monitoring' ? '#f0ad4e' : '#28a745',
        fontWeight: 600
      }}>{threat.status || 'Unknown'}</span></p>
      <p><b>Detection Time:</b> <span className="threat-value">{threat.detection_time ? new Date(threat.detection_time).toLocaleString() : (threat.timestamp || 'N/A')}</span></p>
      <p><b>Summary:</b> <span className="threat-value">{threat.summary || 'No summary available'}</span></p>

      {users.length > 0 && (
        <div style={{ marginTop: "1rem" }}>
          <label htmlFor={`user-select-${threat.indicator}`} style={{ display: "block", marginBottom: "0.5rem" }}>
            Notify User:
          </label>
          <select
            id={`user-select-${threat.indicator}`}
            value={selectedUser}
            onChange={(e) => setSelectedUser(e.target.value)}
            style={{
              padding: "0.5rem",
              width: "100%",
              border: "1px solid #ccc",
              borderRadius: "4px",
              marginBottom: "0.5rem",
            }}
          >
            <option value="">Select a user...</option>
            {users.map((user) => (
              <option key={user.id} value={user.email}>
                {user.username} ({user.email})
              </option>
            ))}
          </select>

          <button
            onClick={handleSendNotification}
            disabled={sending || !selectedUser}
            style={{
              padding: "0.5rem 1rem",
              backgroundColor: sending ? "#ccc" : "#007bff",
              color: "white",
              border: "none",
              borderRadius: "4px",
              cursor: sending || !selectedUser ? "not-allowed" : "pointer",
              width: "100%",
            }}
          >
            {sending ? "Sending..." : "Send Notification"}
          </button>
        </div>
      )}

      {/* Block Button */}
      <button
        onClick={() => setShowBlockModal(true)}
        disabled={!ipList || ipList.length === 0 || blocking}
        style={{
          marginTop: "1rem",
          padding: "0.5rem 1rem",
          backgroundColor: !ipList || ipList.length === 0 ? "#ccc" : "#dc3545",
          color: "white",
          border: "none",
          borderRadius: "4px",
          cursor: !ipList || ipList.length === 0 || blocking ? "not-allowed" : "pointer",
          width: "100%",
          fontWeight: "bold",
        }}
      >
        {blocking ? "Blocking..." : "🛡️ Block IP"}
      </button>

      {/* Block Confirmation Modal */}
      {showBlockModal && (
        <div className="ip-block-modal-overlay">
          <div className="ip-block-modal-card">
            <h3 className="ip-block-modal-title">Confirm IP Block</h3>

            <div className="ip-block-modal-details">
              <p><span className="ip-block-modal-label">IP Address:</span> <span className="ip-block-modal-value ip">{ipList[0]}</span></p>
              <p><span className="ip-block-modal-label">Threat Type:</span> <span className="ip-block-modal-value">{threat.type || threat.category || "Unknown"}</span></p>
              <p><span className="ip-block-modal-label">Risk Level:</span> <span className="ip-block-modal-value">{threat.severity || (displayScore >= 75 ? "High" : displayScore >= 50 ? "Medium" : "Low")}</span></p>
              <p><span className="ip-block-modal-label">Score:</span> <span className="ip-block-modal-value score">{Number(displayScore || 0).toFixed(2)}/100</span></p>
              <div className="ip-block-modal-summary-row">
                <span className="ip-block-modal-label">Summary:</span>
                <div className="ip-block-modal-value summary">{threat.summary || "N/A"}</div>
              </div>
            </div>

            <p className="ip-block-modal-note">
              This will create firewall rules to block all incoming and outgoing traffic to/from this IP on both Windows and Linux systems.
            </p>

            <div className="ip-block-modal-actions">
              <button
                onClick={() => setShowBlockModal(false)}
                className="ip-block-btn-cancel"
              >
                Cancel
              </button>
              <button
                onClick={handleBlockThreat}
                disabled={blocking}
                className="ip-block-btn-confirm"
              >
                {blocking ? "Blocking..." : "✓ Confirm Block"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default ThreatCard;
