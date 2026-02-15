"""
Flask dashboard — displays LKSM events at http://host:port.
"""

import json
import threading
from collections import deque
from datetime import datetime
from typing import List

from flask import Flask, jsonify, Response

from python_tools.core.module_base import LKSMEvent

_events: deque = deque(maxlen=500)
_lock = threading.Lock()

_HTML = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>LKSM Dashboard</title>
<style>
  body { background:#1a1a2e; color:#e0e0e0; font-family:monospace; margin:2em; }
  h1 { color:#00d4ff; }
  table { border-collapse:collapse; width:100%; }
  th,td { border:1px solid #333; padding:6px 10px; text-align:left; }
  th { background:#16213e; color:#00d4ff; }
  tr:nth-child(even) { background:#0f3460; }
  .high { color:#ff4444; font-weight:bold; }
  .critical { color:#ff0000; font-weight:bold; }
  .medium { color:#ffaa00; }
  .info { color:#88cc88; }
  #status { color:#888; font-size:0.9em; margin-bottom:1em; }
</style>
</head>
<body>
<h1>LKSM Monitoring Dashboard</h1>
<div id="status">Waiting for events...</div>
<table>
  <thead><tr><th>Seq</th><th>Time</th><th>Type</th><th>Details</th><th>Severity</th></tr></thead>
  <tbody id="evbody"></tbody>
</table>
<script>
function fmt(ts){ return ts > 1e9 ? new Date(ts*1000).toLocaleString() : ts.toFixed(6)+"s"; }
function esc(s){ var d=document.createElement('div'); d.textContent=s; return d.innerHTML; }
function poll(){
  fetch("/api/events").then(r=>r.json()).then(data=>{
    var tb=document.getElementById("evbody");
    tb.innerHTML="";
    data.slice().reverse().forEach(function(ev){
      var tr=document.createElement("tr");
      tr.innerHTML="<td>"+ev.seq+"</td><td>"+esc(fmt(ev.ts))+"</td>"
        +"<td>"+esc(ev.type)+"</td>"
        +"<td>"+esc(JSON.stringify(ev.data))+"</td>"
        +"<td class='"+ev.severity+"'>"+esc(ev.severity)+"</td>";
      tb.appendChild(tr);
    });
    document.getElementById("status").textContent="Last refresh: "+new Date().toLocaleTimeString()+" | Events: "+data.length;
  }).catch(function(){});
}
setInterval(poll, 2000);
poll();
</script>
</body>
</html>
"""


def push_events(events: List[LKSMEvent]) -> None:
    """Called by the daemon loop to feed new events into the dashboard."""
    with _lock:
        for ev in events:
            _events.append(ev.to_dict())


def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response(_HTML, content_type="text/html")

    @app.route("/api/events")
    def api_events():
        with _lock:
            return jsonify(list(_events))

    return app
