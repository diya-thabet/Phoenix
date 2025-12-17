import sqlite3
import time
import random

# Connect to the SAME database your app uses
conn = sqlite3.connect('ids_logs.db')
c = conn.cursor()

print("🔫 Firing simulated attacks into the database...")

attack_types = ["DDoS", "PortScan", "Botnet", "Brute Force"]
ips = ["192.168.1.50", "10.0.0.99", "172.16.0.4", "45.33.22.11"]

try:
    # Inject 5 fake attacks
    for i in range(5):
        attack = random.choice(attack_types)
        ip = random.choice(ips)
        conf = random.randint(85, 99)
        
        c.execute('''
            INSERT INTO alerts (src_ip, dst_ip, src_port, dst_port, attack_type, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (ip, "192.168.1.100", 4444, 80, attack, conf))
        
        conn.commit()
        print(f"   🔥 INJECTED: {attack} from {ip}")
        time.sleep(1) # Wait 1 second between attacks

    print("\n✅ Simulation Complete. Check your Web Dashboard now!")

except Exception as e:
    print(f"❌ Error: {e}")
finally:
    conn.close()