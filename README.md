# Intrusion Detection System (IDS)

This project is an Intrusion Detection System (IDS) designed to monitor network traffic and detect various types of network attacks such as SYN Flood, ICMP Flood, UDP Flood, DNS Amplification, HTTP Flood, and other anomalies. The system logs detected threats and provides a user interface for monitoring and reporting.

## Features

- **Real-time Packet Capture:** Monitors network traffic in real-time using Scapy.
- **Threat Detection:** Identifies various network attacks using custom detection algorithms.
- **Logging:** Logs detected threats to a database and CSV file for analysis.
- **Reporting:** Generates detailed reports of detected threats.
- **User Interface:** Provides a graphical user interface (GUI) for easy monitoring and control.

## Installation

### Prerequisites

- Python 3.11 or later
- Virtual environment (recommended)


### Setup

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yusufdalbudak/advanced-ids.git
   cd advanced-ids
   ```

2. **Create a Virtual Environment:**

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows, use .venv\Scripts\activate
   ```



## Usage

1. **Start the Application:**

   Run the main script to start the IDS application:

   ```bash
   python Main.py
   ```

2. **User Interface:**

   - **Start IDS:** Click the "Start IDS" button to begin monitoring network traffic.
   - **Stop IDS:** Click the "Stop IDS" button to stop monitoring.
   - **Generate Report:** Click the "Generate Report" button to create a detailed report of detected threats.

3. **Logs and Reports:**

   - Threats are logged in `threats.csv` and stored in a SQLite database (`threats.db`).
   - Reports are generated in `detailed_report.txt`.

## Configuration

- **Network Interface:** The default network interface is set to 'Ethernet'. Modify the `start_packet_capture` function in `PacketCapture.py` to change the interface if needed.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or support, please contact (mailto:yusufdalbudak2121@gmail.com).
