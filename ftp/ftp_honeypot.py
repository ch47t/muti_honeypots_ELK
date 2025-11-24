#!/usr/bin/env python3
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer
import logging, json, time, os
LOGFILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'ftp.json')
logging.basicConfig(filename=LOGFILE, level=logging.INFO, format='%(message)s')

class HoneyHandler(FTPHandler):
    def on_login(self, username):
        logging.info(json.dumps({"honeypot":"ftp","timestamp":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                 "action":"login","username":username,"client":self.remote_ip}))

if __name__ == "__main__":
    auth = DummyAuthorizer(); auth.add_anonymous(".", perm="elr")
    h = HoneyHandler; h.authorizer = auth
    server = FTPServer(("0.0.0.0", 2121), h)
    server.serve_forever()
