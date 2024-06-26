import subprocess
import threading
import os
import signal
from datetime import datetime
from itertools import count

if not os.path.exists('capturas'):
    os.makedirs('capturas')

unique_counter = count(start=1)

def generate_temp_filename():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_id = next(unique_counter)
    return f"capturas/temp_captura_{timestamp}_{unique_id}.pcap"

def generate_final_filename(temp_filename):
    return temp_filename.replace("temp_", "")

def start_windump_capture():
    temp_filename = generate_temp_filename()
    cmd = ['windump', '-i', '3', '-w', temp_filename, '-c', '5000']
    print(f"Capturando en: {temp_filename}")
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE), temp_filename

def force_stop_capture(proc):
    if proc.poll() is None:
        print("Timeout: guardando captura")
        proc.terminate()

def capture_loop():
    current_process = None
    current_temp_filename = None
    try:
        while True:
            current_process, current_temp_filename = start_windump_capture()
            timer = threading.Timer(30, force_stop_capture, [current_process])
            timer.start()
            
            current_process.wait()
            timer.cancel()
            
            final_filename = generate_final_filename(current_temp_filename)
            os.rename(current_temp_filename, final_filename)
            print(f"Captura guardada: {final_filename}")
            
    except KeyboardInterrupt:
        print("Deteniendo la captura...")
        if current_process:
            current_process.terminate()
        print("Proceso finalizado")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    capture_loop()
