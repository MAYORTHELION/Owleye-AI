import sqlite3
conn = sqlite3.connect('owleye.db')
conn.execute("UPDATE incidents SET status='approved' WHERE id=1")
conn.commit()
conn.close()
print('Incident 1 approved')
