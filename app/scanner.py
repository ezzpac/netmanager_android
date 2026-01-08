import socket
import subprocess
import platform
import threading
import re
from queue import Queue
import json

# Predefined common OUIs for basic manufacturer identification
# In a real app, this would be a much larger dictionary or a local file
COMMON_OUIS = {
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",
    "00:15:5D": "Microsoft (Hyper-V)",
    "00:1C:42": "Parallels",
    "08:00:27": "Oracle (VirtualBox)",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:11:32": "Synology",
    "00:1D:60": "Asustor",
    "00:08:9B": "QNAP",
    "00:17:88": "Philips Hue",
    "00:04:20": "Slim Devices (Logitech)",
    "00:04:4B": "NVIDIA",
    "00:07:AD": "Cisco",
    "00:07:B4": "Cisco",
    "00:08:20": "Cisco",
    "00:08:2F": "Cisco",
    "00:08:31": "Cisco",
    "00:01:42": "Cisco",
    "00:02:4A": "Cisco",
    "00:04:4D": "Cisco",
    "00:05:5E": "Cisco",
    "00:05:9A": "Cisco",
    "00:06:52": "Cisco",
    "00:06:7C": "Cisco",
    "00:0A:41": "Cisco",
    "00:0A:8A": "Cisco",
    "00:0A:B7": "Cisco",
    "00:0A:B8": "Cisco",
    "00:0B:45": "Cisco",
    "00:0B:FD": "Cisco",
    "00:0C:30": "Cisco",
    "00:0C:CE": "Cisco",
    "00:0D:28": "Cisco",
    "00:0D:BC": "Cisco",
    "00:0D:BD": "Cisco",
    "00:0E:83": "Cisco",
    "00:0E:84": "Cisco",
    "00:0E:D6": "Cisco",
    "00:0E:D7": "Cisco",
    "00:0F:23": "Cisco",
    "00:0F:24": "Cisco",
    "00:0F:34": "Cisco",
    "00:0F:35": "Cisco",
    "00:0F:8F": "Cisco",
    "00:0F:90": "Cisco",
    "00:10:0D": "Cisco",
    "00:10:7B": "Cisco",
    "00:10:7C": "Cisco",
    "00:11:20": "Cisco",
    "00:11:21": "Cisco",
    "00:11:5C": "Cisco",
    "00:11:5D": "Cisco",
    "00:11:92": "Cisco",
    "00:11:93": "Cisco",
    "00:12:00": "Cisco",
    "00:12:01": "Cisco",
    "00:12:43": "Cisco",
    "00:12:44": "Cisco",
    "00:12:7F": "Cisco",
    "00:12:80": "Cisco",
    "00:13:19": "Cisco",
    "00:13:1A": "Cisco",
    "00:13:5F": "Cisco",
    "00:13:60": "Cisco",
    "00:13:C3": "Cisco",
    "00:13:C4": "Cisco",
    "00:14:1B": "Cisco",
    "00:14:1C": "Cisco",
    "00:14:69": "Cisco",
    "00:14:6A": "Cisco",
    "00:14:A8": "Cisco",
    "00:14:A9": "Cisco",
    "00:14:F1": "Cisco",
    "00:14:F2": "Cisco",
    # Dell
    "00:15:C5": "Dell",
    "78:2B:CB": "Dell",
    "00:0F:1F": "Dell",
    "00:1E:C9": "Dell",
    "00:26:B9": "Dell",
    "00:21:70": "Dell",
    "00:1D:09": "Dell",
    "00:14:22": "Dell",
    "F8:BC:12": "Dell",
    "D4:AE:52": "Dell",
    "00:B0:D0": "Dell",
    # HP
    "74:86:7A": "HP",
    "00:23:AE": "HP",
    "00:17:A4": "HP",
    "00:1E:0B": "HP",
    "00:0B:CD": "HP",
    "00:0F:20": "HP",
    "00:11:0A": "HP",
    "00:16:35": "HP",
    "00:21:5A": "HP",
    "00:25:B3": "HP",
    "2C:44:FD": "HP",
    "3C:D9:2B": "HP",
    "B4:B5:2F": "HP",
}

def get_wmi_model(ip):
    """Disabled on Android"""
    return None

def get_wmi_serial(ip):
    """Disabled on Android"""
    return None

def get_wmi_user(ip, config_domain=None):
    """Disabled on Android"""
    return None
        
    return username

def get_vendor(mac):
    """
    Identifies the manufacturer based on the MAC address OUI.
    """
    if not mac:
        return None
    
    # Normalize MAC address
    normalized_mac = mac.upper().replace('-', ':')
    oui = normalized_mac[:8] # Get first 3 octets
    
    return COMMON_OUIS.get(oui, "Desconhecido")

def get_mac(ip):
    """Disabled on Android due to missing ARP access"""
    return None

def get_hostname(ip):
    """
    Attempts to resolve hostname.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return None

def ping_host(ip):
    """
    Pings a host and returns True if online, False otherwise.
    Simplified for Android.
    """
    param = '-c' # Android/Linux uses -c
    command = ['ping', param, '1', '-W', '1', ip]
    
    try:
        subprocess.check_call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def scan_worker(ip_queue, results, domain=None):
    """
    Worker thread to scan IPs from the queue.
    """
    while not ip_queue.empty():
        try:
            ip = ip_queue.get_nowait()
        except:
            break
        
        # Construct ping command based on OS
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        timeout_val = '1000' if platform.system().lower() == 'windows' else '1' # ms in windows, s in unix
        
        command = ['ping', param, '1', timeout_param, timeout_val, ip]
        
        # Use CREATE_NO_WINDOW on Windows
        creationflags = 0x08000000 if platform.system().lower() == "windows" else 0
        
        try:
            # Suppress output
            subprocess.check_call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags)
            
            # If successful, host is up
            mac = get_mac(ip)
            hostname = get_hostname(ip)
            wmi_model = get_wmi_model(ip)
            vendor = get_vendor(mac)
            
            # NEW: Service Tag and User
            service_tag = get_wmi_serial(ip)
            usuario = get_wmi_user(ip, domain)
            
            # Prioritize Wmi Model (e.g. Optiplex 7010) over generic Vendor (e.g. Dell)
            final_model = wmi_model if wmi_model else vendor
            
            results.append({
                'ip': ip,
                'mac': mac,
                'hostname': hostname or "Dispositivo Desconhecido",
                'vendor': final_model,
                'status': True,
                'service_tag': service_tag,
                'usuario': usuario
            })
        except subprocess.CalledProcessError:
            # Host unreachable
            results.append({
                'ip': ip,
                'status': False
            })
        except Exception as e:
            print(f"Error scanning {ip}: {e}")
        finally:
            ip_queue.task_done()

def scan_network_range(start_ip, end_ip, domain=None):
    """
    Scans a range of IPs using threading.
    """
    # Parse start and end IPs
    start_parts = list(map(int, start_ip.split('.')))
    end_parts = list(map(int, end_ip.split('.')))
    
    # Calculate total IPs to scan (simple logic for /24 mostly, but handled generically)
    # We will iterate by converting to integer, but for simplicity in this user context
    # where user likely inputs 192.168.0.1 to 192.168.0.50, we can just iterate the last octet
    # if the first 3 match.
    
    ips_to_scan = []
    
    if start_parts[:3] == end_parts[:3]:
        # Same subnet /24 context
        base = ".".join(map(str, start_parts[:3]))
        for i in range(start_parts[3], end_parts[3] + 1):
            ips_to_scan.append(f"{base}.{i}")
    else:
        # More complex range, let's keep it simple for now or implement full int conversion
        # Supporting only simple ranges is safer for the "last octet" logic usually requested.
        # But let's verify if we need full range support.
        # Let's support simple linear iteration for now.
        import struct
        
        try:
            start_int = struct.unpack("!L", socket.inet_aton(start_ip))[0]
            end_int = struct.unpack("!L", socket.inet_aton(end_ip))[0]
            
            if end_int < start_int:
                return []
                
            # Cap at 256 IPs to prevent long hangs if user puts crazy range
            if end_int - start_int > 255:
                # Limit to first 256 for safety
                end_int = start_int + 255
            
            for ip_int in range(start_int, end_int + 1):
                ips_to_scan.append(socket.inet_ntoa(struct.pack("!L", ip_int)))
        except:
            return []

    if not ips_to_scan:
        return []

    # Threading setup
    ip_queue = Queue()
    for ip in ips_to_scan:
        ip_queue.put(ip)
    
    results = []
    threads = []
    num_threads = min(50, len(ips_to_scan)) # Max 50 threads
    
    for _ in range(num_threads):
        t = threading.Thread(target=scan_worker, args=(ip_queue, results, domain))
        t.daemon = True
        t.start()
        threads.append(t)
        
    ip_queue.join()
    
    return results
