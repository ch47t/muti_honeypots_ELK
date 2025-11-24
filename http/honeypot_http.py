#!/usr/bin/env python3
import subprocess
import json
import time
import logging
import os
from flask import Flask, request, render_template


LOG_DIR = os.path.join(os.path.dirname(__file__), '..', 'logs')
if not os.path.exists(LOG_DIR):
    try:
        os.makedirs(LOG_DIR)
    except OSError:
        pass # Ignore si erreur de permission

LOGFILE = os.path.join(LOG_DIR, 'http.json')
logging.basicConfig(filename=LOGFILE, level=logging.INFO, format='%(message)s')

app = Flask(__name__)

def log(ev):
    ev.update({
        "honeypot": "http",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "src_ip": request.remote_addr 
    })
    logging.info(json.dumps(ev))

@app.route('/', methods=['GET', 'POST'])
def index():
    
    log({
        "action": "visit_home",
        "method": request.method,
        "form_data": request.form.to_dict(),
        "headers": dict(request.headers)
    })

    result = None
    command = None

    if request.method == 'POST':
        site = request.form.get('site', '')
        command = f'curl -I -s -L {site} | grep "HTTP"'
        
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            result = e.output
        except Exception as e:
            result = str(e)

    return render_template('index.html', result=result, command=command)

@app.route("/<path:p>", methods=["GET","POST"])
def anypath(p):
    # Logue tout le reste (scanners, bots)
    log({
        "action": "catch_all",
        "method": request.method,
        "path": "/" + p,
        "args": request.args.to_dict(),
        "data": request.get_data(as_text=True),
        "headers": dict(request.headers)
    })
    return "Not found", 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
