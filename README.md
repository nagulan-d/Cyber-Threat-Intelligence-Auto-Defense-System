
cd backend
python -m venv .venv
.\.venv-1\Scripts\Activate.ps1
.\start_all_services.ps1
//deactivate

python app.py
python websocket_server.py
python auto_block_monitor.py

pip install -r requirements.txt
flask db upgrade

# ⚠️ IMPORTANT: Run as Administrator for IP Blocking!
# The backend needs admin privileges to create Windows Firewall rules
# Right-click PowerShell -> "Run as Administrator", then run:
python app.py


# Or use the admin startup script:
# .\START_BACKEND_ADMIN.ps1
```

Kali VM (enhanced agent) checks:
live block in vm : sudo journalctl -u threatguard-agent -f
agent log file : tail -f /opt/threatguard/logs/blocking_agent.log
blocked chain in vm : sudo iptables -S THREATGUARD
blocked rules in vm : sudo iptables -L THREATGUARD -n -v --line-numbers
rule for one ip : sudo iptables -L THREATGUARD -n -v | grep <ip address>
vm api health : curl -s -H "Authorization: Bearer $env:BLOCKING_API_TOKEN" http://127.0.0.1:5001/api/health
vm blocked list : curl -s -H "Authorization: Bearer $env:BLOCKING_API_TOKEN" http://127.0.0.1:5001/api/blocking/list

Windows host (PowerShell) WebSocket checks:
Get-NetTCPConnection -LocalPort 8765 -State Listen
Get-NetTCPConnection -LocalPort 8765 -State Established | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State
netstat -ano | findstr :8765

From Kali to test host WebSocket reachability:
nc -vz 192.168.56.1 8765

Backend runs on: `http://127.0.0.1:5000`

Deployment guide: readme/DEPLOYMENT_GUIDE.md

### 2. Frontend Setup (New Terminal)

```powershell
cd frontend
npm install
npm start
```

Frontend runs on: `http://localhost:3000`

### 3. Login

Visit `http://localhost:3000` and login with:
- **Username**: `admin`
- **Password**: Set `DEFAULT_ADMIN_PASSWORD` in your local environment.

//inbound & outbound

tracert <>
ping <IP_ADDRESS>
Test-NetConnection <IP_ADDRESS> -Port 443
