---

## 🛡️ Detection Scenario: Brute Force Login Attempt

### 📄 Scenario Description

This scenario detects brute-force login attempts against a Windows machine. A brute-force attack is characterized by multiple failed login attempts, often followed by a successful login if credentials are guessed correctly.

---

### 🎯 Objective

* Detect 5 or more failed login attempts (Event ID 4625) within a 10-minute window from the same IP address.
* Alert when a successful login (Event ID 4624) follows the failed attempts from the same source.

---

### 🛠️ Tools Used

| Tool/Platform | Purpose                    |
| ------------- | -------------------------- |
| Windows 10 VM | Log source                 |
| Sysmon        | Process and log monitoring |
| Wazuh SIEM    | Detection and alerting     |
| Ubuntu        | Wazuh server host          |
| Hydra / RDP   | Brute-force simulation     |

---

### 🔍 Event ID Mapping

| Source       | Event ID | Description                 |
| ------------ | -------- | --------------------------- |
| Windows Logs | 4625     | Failed login attempt        |
| Windows Logs | 4624     | Successful login            |
| Sysmon       | 1        | Process creation (optional) |

---

### 🧠 Detection Logic

#### Wazuh Rule (example snippet):

```xml
<group name="windows,authentication_failed,">
  <rule id="100001" level="10">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">4625</field>
    <frequency>5</frequency>
    <timeframe>600</timeframe>
    <description>Multiple failed login attempts</description>
  </rule>
</group>
```

---

### 🖼️ Screenshot

> ![Wazuh Alert Screenshot](../screenshots/brute-force-alert.png)

---

### 📁 Sample Logs

```json
{
  "event_id": 4625,
  "source_ip": "192.168.1.5",
  "username": "admin",
  "failure_reason": "Unknown username or bad password"
}
```

---

### 🧑‍💻 Simulation Steps

1. Use `Hydra` or simulate login via RDP with wrong credentials:

   ```bash
   hydra -l admin -P rockyou.txt rdp://192.168.1.5
   ```
2. Observe Event ID 4625 in Wazuh dashboard
3. Login successfully to trigger Event ID 4624

---

### ✅ Detection Outcome

* Alert triggered: ✅
* Detection timestamp: `YYYY-MM-DD HH:MM`
* Status: **Working**

---

### 🔎 Analyst Recommendations

* Investigate the source IP for malicious activity.
* Check for lateral movement after successful login.
* Lock account or trigger MFA for suspicious login attempts.

--
