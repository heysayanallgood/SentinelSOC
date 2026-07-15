import subprocess
import socket
import urllib.request


# --------------------------
# INTERNET CHECK
# --------------------------

def internet_status():
    try:
        urllib.request.urlopen("https://google.com", timeout=3)
        return "🟢 Connected"
    except:
        return "🔴 Offline"


# --------------------------
# LOCAL IP
# --------------------------

def local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "Unavailable"


# --------------------------
# HOSTNAME
# --------------------------

def hostname():
    try:
        return socket.gethostname()
    except:
        return "Unknown"


# --------------------------
# DISK USAGE
# --------------------------

def disk_usage():
    try:
        output = subprocess.check_output(
            ["df", "-h", "/"],
            text=True
        )
        return output.splitlines()[1]
    except:
        return "Unavailable"


# --------------------------
# MEMORY
# --------------------------

def memory_usage():
    try:
        output = subprocess.check_output(
            ["free", "-h"],
            text=True
        )
        return output
    except:
        return "Unavailable"


# --------------------------
# CPU LOAD
# --------------------------

def cpu_load():
    try:
        output = subprocess.check_output(
            ["uptime"],
            text=True
        )
        return output
    except:
        return "Unavailable"
