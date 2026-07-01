import sqlite3, json
from datetime import datetime

conn = sqlite3.connect('owleye.db')
raw = json.dumps({
    'event_id': 4688,
    'source_ip': '10.0.0.45',
    'target_user': 'SYSTEM',
    'process_name': 'cred_tool.exe',
    'process_id': 4729,
    'parent_process': 'cmd.exe',
    'command_line': 'cred_tool.exe privilege::debug sekurlsa::logonpasswords',
    'time': datetime.utcnow().isoformat(),
    'message': 'Credential dumping tool detected running under SYSTEM context'
})
conn.execute(
    'INSERT INTO alerts (timestamp, source, event_type, severity, raw_data, status) VALUES (?,?,?,?,?,?)',
    (datetime.utcnow().isoformat(), 'Process Monitor', 'Suspicious Process Detected', 'critical', raw, 'new')
)
conn.commit()
conn.close()
print('Critical alert injected!')