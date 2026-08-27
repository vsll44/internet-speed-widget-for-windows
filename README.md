# Internet Speed Widget

A lightweight and customizable **Windows Internet Speed Monitor** built with Python and PyQt6.

The widget displays real-time network information, monitors internet speed, tracks ping, shows connected devices, stores speed history, and provides notifications when the connection is lost or becomes unusually slow.

## Features

* 🚀 Live internet speed monitoring
* 📥 Passive network traffic monitoring
* 📊 Real-time speed graph
* 🏓 Ping monitoring
* 📶 Connection type detection
* 🌐 Local IP address display
* 🔥 Hotspot status and connected device count
* 🖧 LAN device discovery using ARP
* ⚠️ Low-speed notifications
* 🔴 Internet disconnection notifications
* ⚠️ Suspicious network activity detection
* 📈 Daily speed statistics
* 💾 SQLite-based speed history
* 🎨 Multiple color themes
* ⭕ Compact circular mode
* ▭ Windows taskbar mode
* ↔️ Resizable interface
* 🖱️ Drag-and-drop window movement
* 🗂️ System tray support
* 🚀 Windows startup integration
* 🔄 Background network monitoring using threads

## Screenshots



## Requirements

* Windows
* Python 3.10+
* Internet connection

### Python Dependencies

```bash
pip install PyQt6 psutil requests
```

## Installation

Clone the repository:

```bash
git clone https://github.com/USERNAME/internet-speed-widget.git
```

Enter the project directory:

```bash
cd internet-speed-widget
```

Install the required packages:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python speed_widget.py
```

## requirements.txt

```text
PyQt6
psutil
requests
```

## How It Works

The application uses several background threads to monitor different aspects of the network.

### Active Speed Test

The widget periodically downloads data from Cloudflare's speed test endpoint and calculates the approximate download speed in Mbps.

The default active test interval is:

```python
ACTIVE_TEST_INTERVAL = 10_000
```

which corresponds to 10 seconds.

### Passive Monitoring

The application also monitors system network statistics using `psutil`.

Passive monitoring updates every:

```python
PASSIVE_UPDATE_INTERVAL = 1_000
```

or once per second.

This data is used to generate the real-time graph.

### Ping

Ping is measured by establishing a connection to:

```text
8.8.8.8:53
```

The ping monitor runs every 2 seconds.

### Network Information

The application detects:

* Local IP address
* Connection type
* Hotspot status
* Approximate number of connected devices

Network information is refreshed every 15 seconds.

### LAN Device Detection

The application uses the Windows ARP table:

```text
arp -a
```

to identify devices visible on the local subnet.

This is an approximate method and does not perform a full network scan.

### Suspicious Traffic Detection

The widget checks active internet connections using `psutil`.

If a process has at least:

```python
SUSPICIOUS_CONN_THRESHOLD = 60
```

network connections, a warning notification is displayed.

This is only a heuristic and should not be considered a complete security or malware detection system.

## Speed History

Speed test results are stored locally using SQLite.

The database is automatically created as:

```text
speed_history.db
```

The application stores:

* Timestamp
* Speed in Mbps

Daily statistics include:

* Average speed
* Minimum speed
* Maximum speed
* Number of tests

## Notifications

The widget can display system tray notifications for:

* Internet connection loss
* Connection recovery
* Low internet speed
* Suspicious network activity

The default low-speed threshold is:

```python
LOW_SPEED_THRESHOLD = 2.0
```

## Themes

The widget includes several built-in themes:

* 🟠 Orange
* 🔵 Blue
* 🟢 Green
* 🟣 Purple
* 🔴 Red

Themes can be switched directly from the widget.

## Display Modes

### Normal Mode

The standard widget displays:

* Current speed
* Speed graph
* Ping
* Connection type
* IP address
* Hotspot status
* Data usage
* Status indicator

### Compact Mode

Compact mode transforms the widget into a small circular interface showing the current speed.

### Taskbar Mode

Taskbar mode creates a compact pill-style interface designed to sit inside the Windows taskbar area.

The taskbar widget displays:

* Current speed
* Mini speed graph

The width can be adjusted using the mouse wheel.

## System Tray

Closing the window does not terminate the application.

Instead, the widget is minimized to the Windows system tray.

From the tray menu you can:

* Show the widget
* Enable/disable Windows startup
* Exit the application

## Windows Startup

The application can optionally add itself to:

```text
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
```

This allows the widget to start automatically when Windows starts.

## Project Structure

```text
internet-speed-widget/
│
├── speed_widget.py
├── requirements.txt
├── README.md
└── speed_history.db
```

`speed_history.db` is generated automatically when the application starts.

It does not need to be included in the repository.

## Configuration

Several settings can be changed directly in `speed_widget.py`.

For example:

```python
ACTIVE_TEST_INTERVAL = 10_000
PASSIVE_UPDATE_INTERVAL = 1_000
PING_INTERVAL = 2_000
NET_INFO_INTERVAL = 15_000
SUSPICIOUS_CHECK_INTERVAL = 30_000
ACTIVE_TEST_SIZE = 8_000_000
GRAPH_POINTS = 30
LOW_SPEED_THRESHOLD = 2.0
SUSPICIOUS_CONN_THRESHOLD = 60
```

### Important

Lowering the active test interval increases network traffic because the application performs speed tests more frequently.

## Limitations

* Active speed testing uses internet bandwidth.
* Speed results may vary depending on the Cloudflare endpoint, network conditions, and system activity.
* ARP-based device detection only shows devices available in the local ARP cache.
* Hotspot detection depends on Windows network adapter naming.
* Suspicious traffic detection is heuristic and does not determine whether a process is actually malicious.
* Some network information may require elevated permissions on Windows.
* The taskbar mode is designed specifically for Windows.

## Technologies

* Python
* PyQt6
* psutil
* Requests
* SQLite
* Windows Registry
* Windows ARP

## License

This project is open source. You can add your preferred license here, such as MIT.

```text
MIT License
```

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Test the application
5. Commit your changes
6. Open a Pull Request

## Author

Developed as a lightweight desktop network monitoring widget for Windows.

---


by Vimo Tech

⭐ If you find this project useful, consider giving it a star on GitHub.
