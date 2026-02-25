import socket
import psutil


def get_network_connections():
    connections = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            connections.append({
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                "status": conn.status,
                "pid": conn.pid,
            })
    except Exception:
        pass
    return connections
