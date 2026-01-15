from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import sqlite3
import uvicorn
import os

app = FastAPI()

# HTML Template (Embed code directly for simplicity)

templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})




@app.get("/api/data")
def get_data():
    conn = sqlite3.connect('ids_logs.db')
    c = conn.cursor()
    
    # 1. Recent Alerts
    c.execute("SELECT timestamp, attack_type, src_ip, dst_ip, dst_port, confidence FROM alerts ORDER BY id DESC LIMIT 10")
    rows = c.fetchall()
    alerts = [{
        "time": r[0].split()[1], # Just take the time part
        "type": r[1],
        "src": r[2],
        "dst": r[3],
        "dport": r[4],
        "conf": int(r[5])
    } for r in rows]
    
    # 2. Stats
    c.execute("SELECT COUNT(*), AVG(confidence) FROM alerts")
    stats = c.fetchone()
    total_count = stats[0]
    avg_conf = round(stats[1], 1) if stats[1] else 0
    
    # 3. Distribution (for Chart)
    c.execute("SELECT attack_type, COUNT(*) FROM alerts GROUP BY attack_type")
    dist_rows = c.fetchall()
    distribution = {r[0]: r[1] for r in dist_rows}
    
    # 4. Top Attack
    top_attack = max(distribution, key=distribution.get) if distribution else "None"
    
    conn.close()
    
    return {
        "recent_alerts": alerts,
        "total_count": total_count,
        "avg_confidence": avg_conf,
        "distribution": distribution,
        "top_attack": top_attack
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)