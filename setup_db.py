import sqlite3

def init_db():
    conn = sqlite3.connect('ids_logs.db')
    c = conn.cursor()
    
    # Create table for Alerts
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            attack_type TEXT,
            confidence REAL
        )
    ''')
    
    # Create table for Live Stats (optional, to show traffic volume)
    c.execute('''
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            packet_count INTEGER
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database 'ids_logs.db' initialized successfully!")

if __name__ == "__main__":
    init_db()