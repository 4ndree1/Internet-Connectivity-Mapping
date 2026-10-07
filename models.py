STATUS_COLORS = {
    "Online":   "#00CC66",
    "Unstable": "#FF8800",
    "Idle":     "#66AAFF",
    "Offline":  "#FF3333",
}


class NetworkDevice:
    def __init__(self, ip, mac):
        self.name = "GENERIC DEVICE"
        self.ip = ip
        self.mac = mac
        self.status = "Scanning..."
        self.color = "#808080"
        self.latency = "0ms"
        self.tcp_latency = "0ms"
        self.packet_loss = "0%"
        self.jitter = "0ms"
        self.last_check = "--:--:--"
        self.fail_count = 0
        self.unstable_count = 0
        self.status_history = []