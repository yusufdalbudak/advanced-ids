import sqlite3
import csv
from collections import Counter
from datetime import datetime

# Protocol number to name mapping
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    # Add more protocol mappings as needed
}

def log_threat_to_db(threat_info):
    try:
        conn = sqlite3.connect('threats.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS threats
                     (id INTEGER PRIMARY KEY, info TEXT)''')
        c.execute("INSERT INTO threats (info) VALUES (?)", (threat_info,))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

def log_threat_to_csv(threat_info, src_ip, dst_ip, proto, filename='threats.csv'):
    try:
        with open(filename, mode='a', newline='') as file:
            writer = csv.writer(file)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow([timestamp, threat_info, src_ip, dst_ip, proto])
    except IOError as e:
        print(f"CSV error: {e}")

def analyze_log_file(filename='threats.csv'):
    with open(filename, mode='r') as file:
        reader = csv.reader(file, delimiter='|')
        src_ips = []
        dst_ips = []
        for row in reader:
            if len(row) > 1:
                src_ips.append(row[1].split(' ')[-1])
                dst_ips.append(row[1].split(' ')[-1])
        
        most_common_src = Counter(src_ips).most_common(1)
        most_common_dst = Counter(dst_ips).most_common(1)
        
        print(f"Most common source IP: {most_common_src}")
        print(f"Most common destination IP: {most_common_dst}") 

def generate_report(filename='threats.csv'):
    with open(filename, mode='r') as file:
        reader = csv.reader(file)
        report = []

        # Add column titles
        report.append(["Timestamp", "Threat Info", "Source IP", "Destination IP", "Protocol"])

        for row in reader:
            if len(row) == 5:
                # Convert protocol number to name
                proto_name = PROTOCOL_MAP.get(int(row[4]), row[4])
                report.append([row[0], row[1], row[2], row[3], proto_name])
            else:
                print(f"Skipping malformed row: {row}")
        
        with open('detailed_report.txt', 'w') as report_file:
            col_widths = [max(len(str(item)) for item in col) for col in zip(*report)]
            for entry in report:
                row = " | ".join(f"{str(item).ljust(width)}" for item, width in zip(entry, col_widths))
                report_file.write(f"{row}\n")
                report_file.write("-" * (sum(col_widths) + 3 * (len(col_widths) - 1)) + "\n")
                
    print("Report generated: detailed_report.txt")

def archive_logs(filename='threats.csv'):
    # Securely archive logs
    print(f"Archiving log file: {filename}")
    # Implement archiving logic here 