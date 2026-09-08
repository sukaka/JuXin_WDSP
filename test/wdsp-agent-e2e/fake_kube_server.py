#!/usr/bin/env python3
"""Minimal TLS Kubernetes API used only by the WDSP Agent E2E test."""

import http.server
import json
import os
import socket
import ssl
import urllib.parse


TOKEN = "wdsp-e2e-service-account-token"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.send_error(401)
            return

        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if query.get("limit") != ["500"]:
            self.send_error(400, "limit must be 500")
            return

        pod_ip = socket.gethostbyname(socket.gethostname())
        if parsed.path == "/api/v1/pods":
            if query.get("fieldSelector") != ["spec.nodeName=e2e-node,status.phase=Running"]:
                self.send_error(400, "unexpected fieldSelector")
                return
            payload = {
                "metadata": {},
                "items": [{
                    "metadata": {
                        "name": "wdsp-e2e-agent-7d9f84c8bf-x7k2p",
                        "namespace": "wdsp-e2e",
                        "ownerReferences": [{"kind": "ReplicaSet", "name": "wdsp-e2e-agent-7d9f84c8bf"}],
                    },
                    "status": {"podIP": pod_ip},
                }],
            }
        elif parsed.path == "/api/v1/namespaces/wdsp-e2e/endpoints":
            # G4b：Agent 按本节点 Pod 所在 namespace 分别查询 endpoints（不再全集群分页）
            payload = {
                "metadata": {},
                "items": [{
                    "metadata": {"name": "wdsp-e2e-service", "namespace": "wdsp-e2e"},
                    "subsets": [{"addresses": [{"ip": pod_ip}]}],
                }],
            }
        elif parsed.path == "/apis/apps/v1/namespaces/wdsp-e2e/replicasets":
            # G4b：ReplicaSet → Deployment 权威归属解析
            payload = {
                "metadata": {},
                "items": [{
                    "metadata": {
                        "name": "wdsp-e2e-agent-7d9f84c8bf",
                        "namespace": "wdsp-e2e",
                        "ownerReferences": [{"kind": "Deployment", "name": "wdsp-e2e-agent"}],
                    },
                }],
            }
        else:
            self.send_error(404)
            return

        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"fake-kube: {fmt % args}", flush=True)


server = http.server.ThreadingHTTPServer(("127.0.0.1", 8443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/fake-kube.crt", "/fake-kube.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
