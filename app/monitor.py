import threading
import time
import os
import subprocess
from datetime import datetime
from .scanner import ping_host
from .models import Device
from . import db

# Global for heartbeat tracking - REMOVED

def update_device_statuses(app):
    """
    Background worker that pings all devices in the database.
    """
    with app.app_context():
        while True:
            try:
                devices = Device.query.all()
                for device in devices:
                    # Ping host
                    is_online = ping_host(device.ip)
                    
                    # Update status if changed
                    if device.status != is_online:
                        device.status = is_online
                        device.data_atualizacao = datetime.utcnow()
                
                db.session.commit()
            except Exception as e:
                print(f"Error in background status monitor: {e}")
                db.session.rollback()
            
            # Wait for 5 minutes before next check
            time.sleep(300)

def start_status_monitor(app):
    """
    Starts the status monitor in a background thread.
    """
    monitor_thread = threading.Thread(target=update_device_statuses, args=(app,))
    monitor_thread.daemon = True
    monitor_thread.start()
    
    return monitor_thread
