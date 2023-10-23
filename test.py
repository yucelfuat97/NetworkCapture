import tkinter as tk
from tkinter import ttk  # Import the ttk module for Treeview
from scapy.all import sniff, Ether, IP, TCP, UDP
import datetime
import threading

# Define the output file name
output_file = "network_traffic.txt"
capture_thread = None  # Store the capture thread
capture_running = False  # Flag to control capture
unique_log_entries = set()  # Store unique log entries

def get_protocol_name(packet):
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    else:
        return "Unknown"

# ...

def packet_callback(packet):
    if capture_running:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        source_mac = packet[Ether].src
        dest_mac = packet[Ether].dst
        source_ip, dest_ip = "N/A", "N/A"
        if IP in packet:
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
        protocol = get_protocol_name(packet)
        
        log_entry = (timestamp, source_mac, dest_mac, source_ip, dest_ip, protocol)
        
        if log_entry not in unique_log_entries:
            unique_log_entries.add(log_entry)
            
        # Check if the entry matches the filter criteria
        source_ip_filter = source_ip_entry.get()
        dest_ip_filter = dest_ip_entry.get()
        protocol_filter = protocol_entry.get()
        source_mac_filter = source_mac_entry.get()
        dest_mac_filter = dest_mac_entry.get()
        if (source_ip_filter in source_ip and dest_ip_filter in dest_ip and
            protocol_filter in protocol and source_mac_filter in source_mac and
            dest_mac_filter in dest_mac):
            # Insert matching data into the Treeview widget
            log_tree.insert("", "end", values=log_entry)

# ...


filtered_log_entries = []

def apply_filter():
    source_ip_filter = source_ip_entry.get()
    dest_ip_filter = dest_ip_entry.get()
    protocol_filter = protocol_entry.get()
    source_mac_filter = source_mac_entry.get()
    dest_mac_filter = dest_mac_entry.get()

    # Clear the Treeview widget
    log_tree.delete(*log_tree.get_children())
    
    # Clear the list of filtered data
    filtered_log_entries.clear()

    for entry in unique_log_entries:
        timestamp, source_mac, dest_mac, source_ip, dest_ip, protocol = entry

        # Check if the entry matches the filter criteria
        if (source_ip_filter in source_ip and dest_ip_filter in dest_ip and
            protocol_filter in protocol and source_mac_filter in source_mac and
            dest_mac_filter in dest_mac):
            # Insert matching data into the Treeview widget
            log_tree.insert("", "end", values=entry)
            
            # Append the matching data to the filtered list
            filtered_log_entries.append(entry)


def start_capture():
    global capture_thread, capture_running
    if capture_thread is None or not capture_thread.is_alive() or capture_running == False:
        if len(unique_log_entries) > 0:  # Check if there's any existing data
            apply_filter()  # Apply the filter to display the filtered data
        else:
            capture_running = True
            capture_thread = threading.Thread(target=run_capture)
            capture_thread.daemon = True  # Exit when the main program exits
            capture_thread.start()

def run_capture():
    try:
        while capture_running:
            sniff(iface="WiFi", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        log_area.insert(tk.END, "Capture paused. Wi-Fi traffic data saved to " + output_file + "\n")

def stop_capture():
    global capture_running
    capture_running = False

def restart_capture():
    stop_capture()  # Stop the current capture (if running)
    log_tree.delete(*log_tree.get_children())  # Clear the Treeview widget
    unique_log_entries.clear()  # Clear the set of unique log entries
    start_capture()  # Start a new capture

# Create the main window
window = tk.Tk()
window.title("Network Traffic Capture")

# Create a start button
start_button = tk.Button(window, text="Start Capture", command=start_capture)
start_button.pack()

# Create a stop button
stop_button = tk.Button(window, text="Stop Capture", command=stop_capture)
stop_button.pack()

# Create a restart button
restart_button = tk.Button(window, text="Restart Capture", command=restart_capture)
restart_button.pack()

# Create Entry fields and Apply Filter button for filtering
filter_frame = tk.Frame(window)
filter_frame.pack()

source_ip_label = tk.Label(filter_frame, text="Source IP:")
source_ip_label.grid(row=0, column=0)
source_ip_entry = tk.Entry(filter_frame)
source_ip_entry.grid(row=0, column=1)

dest_ip_label = tk.Label(filter_frame, text="Dest IP:")
dest_ip_label.grid(row=0, column=2)
dest_ip_entry = tk.Entry(filter_frame)
dest_ip_entry.grid(row=0, column=3)

protocol_label = tk.Label(filter_frame, text="Protocol:")
protocol_label.grid(row=0, column=4)
protocol_entry = tk.Entry(filter_frame)
protocol_entry.grid(row=0, column=5)

source_mac_label = tk.Label(filter_frame, text="Source MAC:")
source_mac_label.grid(row=0, column=6)
source_mac_entry = tk.Entry(filter_frame)
source_mac_entry.grid(row=0, column=7)

dest_mac_label = tk.Label(filter_frame, text="Dest MAC:")
dest_mac_label.grid(row=0, column=8)
dest_mac_entry = tk.Entry(filter_frame)
dest_mac_entry.grid(row=0, column=9)

apply_filter_button = tk.Button(filter_frame, text="Apply Filter", command=apply_filter)
apply_filter_button.grid(row=0, column=10)

# Create a Treeview widget for displaying the logs with a larger height
log_tree = ttk.Treeview(window, columns=("Timestamp", "Source MAC", "Dest MAC", "Source IP", "Dest IP", "Protocol"), height=50)
log_tree.heading("#1", text="Timestamp")
log_tree.heading("#2", text="Source MAC")
log_tree.heading("#3", text="Dest MAC")
log_tree.heading("#4", text="Source IP")
log_tree.heading("#5", text="Dest IP")
log_tree.heading("#6", text="Protocol")
log_tree.pack()

# Start the GUI main loop
window.mainloop()
