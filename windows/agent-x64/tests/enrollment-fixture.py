"""Local CI endpoint; fixed nonsecret credentials, never shipped as an agent."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
state_path=Path(sys.argv[1])
state={"enrollments":0,"heartbeats":0,"version":None}
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_POST(self):
        data=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
        status=200
        if self.path.endswith('/enroll'):
            if data.get('enrollment_token')!='CI-ENROLLMENT': status=401
            else: state['enrollments']+=1
            response={"api_key":"CI-PROTECTED-KEY","agent_id":1}
        elif self.headers.get('Authorization')!='Bearer CI-PROTECTED-KEY':
            status=401; response={"error":"invalid fixture authorization"}
        else:
            response={"ok":True,"commands":[],"rechecks":[],"new_findings":0}
            if self.path.endswith('/heartbeat'):
                state['heartbeats']+=1; state['version']=data.get('agent_version')
        state_path.write_text(json.dumps(state))
        body=json.dumps(response).encode()
        self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
HTTPServer(('127.0.0.1',8087),Handler).serve_forever()
