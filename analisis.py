from scapy.all import *
from statistics import mean, stdev
from collections import defaultdict
from tensorflow.keras.models import load_model
import numpy as np
import joblib

import psycopg2
from datetime import datetime

model = load_model('modelos/modelo.keras')
scaler = joblib.load('modelos/scaler.gz')
encoder = joblib.load('modelos/encoder.gz')

def parse_flows(pcap_file):
    packets = rdpcap(pcap_file)
    flows = defaultdict(list)
    total_packets = len(packets)
    
    for packet in packets:
        if IP in packet:
            proto = packet[IP].proto
            ips = tuple(sorted([packet[IP].src, packet[IP].dst]))
            ports = tuple(sorted([packet[TCP].sport if TCP in packet else 0, packet[TCP].dport if TCP in packet else 0]))
            flow_key = (ips, ports, proto)
            flows[flow_key].append(packet)
    
    return flows, total_packets

def analyze_flow(flow_packets, src_ip, dst_ip):
    timestamps = [pkt.time for pkt in flow_packets]
    lengths = [len(pkt) for pkt in flow_packets]
    iat_list = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    
    flags = defaultdict(int)
    for pkt in flow_packets:
        if TCP in pkt:
            tcp_flags = pkt[TCP].flags
            flags['FIN'] += int(bool(tcp_flags & 0x01))
            flags['SYN'] += int(bool(tcp_flags & 0x02))
            flags['RST'] += int(bool(tcp_flags & 0x04))
            flags['PSH'] += int(bool(tcp_flags & 0x08))
            flags['ACK'] += int(bool(tcp_flags & 0x10))
            flags['URG'] += int(bool(tcp_flags & 0x20))
            flags['CWR'] += int(bool(tcp_flags & 0x80))
            flags['ECE'] += int(bool(tcp_flags & 0x40))

    features = [0] * 23
    features[0] = flow_packets[0][IP].proto if flow_packets and IP in flow_packets[0] else 0
    duration = int((max(timestamps) - min(timestamps)) * 1000000) if timestamps else 0
    if(duration == 0): duration = 10
    fwd_packets = [pkt for pkt in flow_packets if IP in pkt and pkt[IP].src == src_ip]
    bwd_packets = [pkt for pkt in flow_packets if IP in pkt and pkt[IP].src == dst_ip]
    features[1] = duration
    features[2] = len(fwd_packets)
    features[3] = len(bwd_packets)
    features[4] = sum(len(pkt) for pkt in fwd_packets)
    features[5] = sum(len(pkt) for pkt in bwd_packets)
    if fwd_packets:
        features[6] = max(len(pkt) for pkt in fwd_packets)
        features[7] = min(len(pkt) for pkt in fwd_packets)
        features[8] = mean(len(pkt) for pkt in fwd_packets)
    if bwd_packets:
        features[9] = max(len(pkt) for pkt in bwd_packets)
        features[10] = min(len(pkt) for pkt in bwd_packets)
        features[11] = mean(len(pkt) for pkt in bwd_packets)
    features[12] = sum(lengths) / duration if duration > 0 else 0
    features[13] = len(flow_packets) / duration if duration > 0 else 0
    features[14] = mean(lengths) if lengths else 0
    
    features[15] = flags['FIN']
    features[16] = flags['SYN']
    features[17] = flags['RST']
    features[18] = flags['PSH']
    features[19] = flags['ACK']
    features[20] = flags['URG']
    features[21] = flags['CWR']
    features[22] = flags['ECE']

    return features

def extract_features_from_pcap(pcap_file):
    flows, total_packets = parse_flows(pcap_file)
    all_features = []
    
    for flow_key, packets in flows.items():
        ips, ports, proto = flow_key
        src_ip, dst_ip = ips
        flow_features = analyze_flow(packets, src_ip, dst_ip)
        all_features.append(flow_features)
         
    return np.array(all_features), total_packets

def preprocess_and_predict(features, model, scaler, encoder):
    scaled_features = scaler.transform(features)
    predictions = model.predict(scaled_features)
    predicted_classes = encoder.inverse_transform(np.argmax(predictions, axis=1))
    return predictions, predicted_classes

def count_predictions(predicted_classes):
    counter = Counter(predicted_classes)
    return counter

def connect_to_db():
    # En este proyecto se ha utilizado una BBDD local. Si se desea probar este código, se deben configurar los parámetros de abajo con los de la nueva BBDD
    return psycopg2.connect(host="localhost", port="5432", dbname="postgres", user="postgres", password="root")

def insert_prediction_data(cursor, timestamp, prediction_counts, total_packets, label):
    query = """
    INSERT INTO predicciones(timestamp, benign, ldap, mssql, syn, udp, total_paquetes, label)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    benign = 0
    ldap = 0
    mssql = 0
    syn = 0
    udp = 0

    for class_name, count in prediction_counts.items():
        if class_name == 'BENIGN':
            benign = count
        elif class_name == 'LDAP':
            ldap = count
        elif class_name == 'MSSQL':
            mssql = count
        elif class_name == 'SYN':
            syn = count
        elif class_name == 'UDP':
            udp = count

    values = (timestamp, benign, ldap, mssql, syn, udp, total_packets, label)
    cursor.execute(query, values)

def send_predictions_to_db(prediction_counts, total_packets):
    conn = connect_to_db()
    cursor = conn.cursor()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    label = False
    
    if any(attack_type in prediction_counts for attack_type in ["LDAP", "MSSQL", "SYN", "UDP"]):
        label = True
    
    
    insert_prediction_data(cursor, timestamp, prediction_counts, total_packets, label)
    conn.commit()
    cursor.close()
