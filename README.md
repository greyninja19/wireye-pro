🦅 WireEye Pro

Automated Network Forensics & PCAP Analysis Platform

    Stop staring at Wireshark streams. Start seeing the story behind the traffic.

WireEye Pro is a web-based forensics tool that transforms raw packet captures into actionable intelligence. By simply dropping a .pcap or .pcapng file into the dashboard, researchers can instantly visualize traffic patterns, identify threats, and audit network protocols without writing a single line of code.
🛠️ Key Capabilities (The 9-Tab Suite)

    📊 Overview: Real-time traffic timelines and protocol distribution (TCP/UDP).

    🚨 Threat Intelligence: Automated signature matching for malicious patterns and severities.

    🌐 Traffic & Conversations: Comprehensive mapping of internal vs. external data flow.

    🔍 DNS & HTTP Insights: Deep dive into cleartext queries and potential DNS tunneling.

    📶 ARP Security: Dedicated tab for detecting ARP spoofing and MAC address anomalies.

    📄 Exportable Reports: One-click generation of HTML, JSON, or TXT forensic summaries.

⚙️ Technical Stack

    Backend: Python 3, Scapy (Packet Dissection Engine), Flask

    Frontend: HTML5, CSS3 (Dark Mode Optimized), JavaScript (Chart.js / Plotly)

    Analysis: Automated protocol mapping and entropy-based anomaly detection.
💻 Installation

git clone https://github.com/YOUR_USERNAME/WireEye-Pro.git
cd WireEye-Pro
pip install -r requirements.txt
python app.py
