from scapy.all import sniff, IP, TCP, UDP, conf
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Use non-GUI backend
import matplotlib.pyplot as plt
from flask import Flask, render_template, request, redirect, url_for
import threading
import os

# Configure Scapy to use Npcap
conf.use_pcap = True

# DataFrame to store captured packets
packet_data = pd.DataFrame(columns=["Time", "Source", "Destination", "Protocol", "Length"])
packet_data_lock = threading.Lock()
sniffing = False
sniff_thread = None

def packet_callback(packet):
    global packet_data
    if IP in packet:
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"
        new_packet = {
            "Time": packet.time,
            "Source": packet[IP].src,
            "Destination": packet[IP].dst,
            "Protocol": protocol,
            "Length": len(packet)
        }
        with packet_data_lock:
            packet_data = pd.concat([packet_data, pd.DataFrame([new_packet])], ignore_index=True)

def start_sniffing():
    global sniffing
    sniffing = True
    print("Starting packet capture...")
    sniff(prn=packet_callback, store=False)

def stop_sniffing():
    global sniffing
    sniffing = False
    print("Stopping packet capture...")

def visualize_traffic():
    global packet_data
    with packet_data_lock:
        if packet_data.empty:
            print("No packets captured yet.")
            return
        plt.figure(figsize=(10, 6))
        packet_data['Protocol'].value_counts().plot(kind='bar')
        plt.xlabel("Protocol")
        plt.ylabel("Count")
        os.makedirs("static", exist_ok=True)
        plt.savefig("static/traffic_chart.png")
        print("Traffic chart saved as 'static/traffic_chart.png'")

app = Flask(__name__)

@app.route('/')
def home():
    visualize_traffic()
    with packet_data_lock:
        return render_template('index.html', table=packet_data.tail(10).to_html(classes="table"))

@app.route('/start')
def start():
    global sniff_thread
    if not sniffing:
        sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        sniff_thread.start()
    return redirect(url_for('home'))

@app.route('/stop')
def stop():
    if sniffing:
        stop_sniffing()
    return redirect(url_for('home'))

@app.route('/filter', methods=['POST'])
def filter_packets():
    protocol = request.form.get('protocol')
    with packet_data_lock:
        filtered_data = packet_data[packet_data['Protocol'] == protocol]
        return render_template('index.html', table=filtered_data.to_html(classes="table"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host='0.0.0.0', port=port)