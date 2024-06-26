import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
import concurrent.futures
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from analisis import extract_features_from_pcap, preprocess_and_predict, model, scaler, encoder, count_predictions, send_predictions_to_db

class Watcher:
    DIRECTORY_TO_WATCH = "capturas"

    def __init__(self):
        self.observer = Observer()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)

    def run(self):
        event_handler = Handler(self.executor)
        self.observer.schedule(event_handler, self.DIRECTORY_TO_WATCH, recursive=False)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            self.observer.stop()
            print("Observer Cerrado")

        self.observer.join()
        self.executor.shutdown(wait=True)

class Handler(FileSystemEventHandler):

    def __init__(self, executor):
        self.executor = executor

    def on_moved(self, event):
        if event.is_directory:
            return None

        if event.dest_path.endswith(".pcap") and "temp_" not in os.path.basename(event.dest_path):
            print(f"Detectado fichero PCAP listo para análisis: {event.dest_path}")
            self.executor.submit(process_file, event.dest_path)

    def on_created(self, event):
        print(f"Creado: {event.src_path}")

def process_file(file_path):
    print(f"Procesando fichero: {file_path}")
    try:
        flow_features_list, total_packets = extract_features_from_pcap(file_path)
        if flow_features_list.size == 0:
            print("No se han obtenido flujos")
            return

        predictions, predicted_classes = preprocess_and_predict(flow_features_list, model, scaler, encoder)
        if predictions.size == 0:
            print("No se ejecutaron las predicciones, error con las feautures o el modelo.")
            return

        prediction_counts = count_predictions(predicted_classes)
        print(f"Clases predichas para {file_path}: {predicted_classes}")
        print("Recuento de predicciones por clase:")
        for class_name, count in prediction_counts.items():
            print(f"{class_name}: {count}")
            
        send_predictions_to_db(prediction_counts, total_packets)
    except Exception as e:
        print(f"Error en el fichero {file_path}: {str(e)}")

if __name__ == '__main__':
    w = Watcher()
    w.run()
