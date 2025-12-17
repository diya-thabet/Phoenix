from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import sqlite3
import uvicorn
import os

app = FastAPI()

# HTML Template (Embed code directly for simplicity)
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial_scale=1.0">
    <title>CyberGuard SOC Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { background-color: #0f172a; color: #e2e8f0; }
        .glass { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid #334155; }
    </style>
</head>
<body class="p-6">
    <div class="max-w-7xl mx-auto">
        <header class="flex justify-between items-center mb-8">
            <div>
                <h1 class="text-3xl font-bold text-emerald-400">🛡️ CyberGuard AI</h1>
                <p class="text-slate-400">Real-time Intelligent Intrusion Detection System</p>
            </div>
            <div class="flex gap-4">
                <div class="glass p-3 rounded-lg text-center min-w-[120px]">
                    <p class="text-xs text-slate-400">STATUS</p>
                    <p class="text-emerald-400 font-bold animate-pulse">● LIVE</p>
                </div>
            </div>
        </header>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="glass p-6 rounded-xl border-l-4 border-red-500">
                <h3 class="text-slate-400 text-sm">TOTAL THREATS DETECTED</h3>
                <p class="text-4xl font-bold mt-2" id="total-alerts">0</p>
            </div>
            <div class="glass p-6 rounded-xl border-l-4 border-blue-500">
                <h3 class="text-slate-400 text-sm">MOST COMMON ATTACK</h3>
                <p class="text-xl font-bold mt-2" id="top-attack">None</p>
            </div>
            <div class="glass p-6 rounded-xl border-l-4 border-emerald-500">
                <h3 class="text-slate-400 text-sm">AI CONFIDENCE (AVG)</h3>
                <p class="text-4xl font-bold mt-2" id="avg-conf">0%</p>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div class="lg:col-span-2 glass rounded-xl p-6">
                <h2 class="text-xl font-bold mb-4 flex items-center gap-2">
                    <span class="w-2 h-2 bg-red-500 rounded-full"></span> Live Alert Feed
                </h2>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-sm">
                        <thead class="text-slate-400 border-b border-slate-700">
                            <tr>
                                <th class="pb-3">Time</th>
                                <th class="pb-3">Attack Type</th>
                                <th class="pb-3">Source IP</th>
                                <th class="pb-3">Target</th>
                                <th class="pb-3">Confidence</th>
                            </tr>
                        </thead>
                        <tbody id="alert-table-body" class="text-slate-300">
                            </tbody>
                    </table>
                </div>
            </div>

            <div class="glass rounded-xl p-6">
                <h2 class="text-xl font-bold mb-4">Threat Distribution</h2>
                <canvas id="attackChart"></canvas>
            </div>
        </div>
    </div>

    <script>
        let chartInstance = null;

        async function fetchData() {
            try {
                const response = await fetch('/api/data');
                const data = await response.json();
                
                // Update Stats
                document.getElementById('total-alerts').innerText = data.total_count;
                document.getElementById('top-attack').innerText = data.top_attack || "None";
                document.getElementById('avg-conf').innerText = data.avg_confidence + "%";

                // Update Table
                const tbody = document.getElementById('alert-table-body');
                tbody.innerHTML = "";
                data.recent_alerts.forEach(alert => {
                    const row = `
                        <tr class="border-b border-slate-700/50 hover:bg-slate-800/50 transition">
                            <td class="py-3 text-slate-400">${alert.time}</td>
                            <td class="py-3 font-bold text-red-400">${alert.type}</td>
                            <td class="py-3 text-mono">${alert.src}</td>
                            <td class="py-3 text-mono">${alert.dst}:${alert.dport}</td>
                            <td class="py-3">
                                <span class="px-2 py-1 rounded text-xs bg-slate-700 border border-slate-600">
                                    ${alert.conf}%
                                </span>
                            </td>
                        </tr>
                    `;
                    tbody.innerHTML += row;
                });

                // Update Chart
                updateChart(data.distribution);

            } catch (error) {
                console.error("Error fetching data:", error);
            }
        }

        function updateChart(dist) {
            const ctx = document.getElementById('attackChart').getContext('2d');
            const labels = Object.keys(dist);
            const values = Object.values(dist);

            if (chartInstance) {
                chartInstance.data.labels = labels;
                chartInstance.data.datasets[0].data = values;
                chartInstance.update();
            } else {
                chartInstance = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: values,
                            backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6'],
                            borderWidth: 0
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { position: 'bottom', labels: { color: '#94a3b8' } }
                        }
                    }
                });
            }
        }

        // Refresh every 2 seconds
        setInterval(fetchData, 2000);
        fetchData();
    </script>
</body>
</html>
"""

@app.get("/")
def dashboard():
    return HTMLResponse(content=html_content)

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