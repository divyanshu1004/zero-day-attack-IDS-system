"""
Network Traffic Analysis Module
Analyzes network packets and flows for anomaly detection
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any
import logging
from collections import defaultdict, deque
import time
import json
import threading
from dataclasses import dataclass
import ipaddress

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available. Some features will be disabled.")

@dataclass
class FlowFeatures:
    """Network flow features for analysis"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration: float
    packet_count: int
    byte_count: int
    flow_rate: float
    packet_size_mean: float
    packet_size_std: float
    inter_arrival_time_mean: float
    inter_arrival_time_std: float
    tcp_flags: Dict[str, int]
    port_scan_score: float
    ddos_score: float
    anomaly_score: float = 0.0

class TrafficAnalyzer:
    """Analyzes network traffic for anomaly detection and attack patterns"""
    
    def __init__(self, interface: str = None, capture_filter: str = None):
        self.interface = interface
        self.capture_filter = capture_filter
        self.logger = logging.getLogger(__name__)
        
        # Flow tracking
        self.active_flows = {}
        self.completed_flows = deque(maxlen=10000)
        self.flow_timeout = 300  # 5 minutes
        
        # Statistics
        self.packet_stats = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        
        # Anomaly detection thresholds
        self.thresholds = {
            'max_packet_rate': 1000,  # packets/second
            'max_byte_rate': 1000000,  # bytes/second
            'max_connections_per_host': 100,
            'suspicious_port_threshold': 10,
            'ddos_packet_threshold': 10000
        }
        
        # Port scan detection
        self.port_scan_window = 60  # seconds
        self.host_connections = defaultdict(lambda: defaultdict(set))
        
        # DDoS detection
        self.ddos_window = 30  # seconds
        self.target_packet_count = defaultdict(lambda: deque(maxlen=1000))
        
        self.is_capturing = False
        self.capture_thread = None
    
    def extract_packet_features(self, packet) -> Dict[str, Any]:
        """Extract features from a single packet"""
        features = {
            'timestamp': time.time(),
            'size': len(packet),
            'protocol': 'unknown',
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'tcp_flags': {},
            'payload_size': 0
        }
        
        if not SCAPY_AVAILABLE:
            return features
        
        try:
            if IP in packet:
                features['src_ip'] = packet[IP].src
                features['dst_ip'] = packet[IP].dst
                features['protocol'] = packet[IP].proto
                features['payload_size'] = len(packet[IP].payload)
                
                if TCP in packet:
                    features['protocol'] = 'TCP'
                    features['src_port'] = packet[TCP].sport
                    features['dst_port'] = packet[TCP].dport
                    
                    # Extract TCP flags
                    tcp_flags = packet[TCP].flags
                    features['tcp_flags'] = {
                        'FIN': bool(tcp_flags & 0x01),
                        'SYN': bool(tcp_flags & 0x02),
                        'RST': bool(tcp_flags & 0x04),
                        'PSH': bool(tcp_flags & 0x08),
                        'ACK': bool(tcp_flags & 0x10),
                        'URG': bool(tcp_flags & 0x20)
                    }
                    
                elif UDP in packet:
                    features['protocol'] = 'UDP'
                    features['src_port'] = packet[UDP].sport
                    features['dst_port'] = packet[UDP].dport
                    
                elif ICMP in packet:
                    features['protocol'] = 'ICMP'
                    features['icmp_type'] = packet[ICMP].type
                    features['icmp_code'] = packet[ICMP].code
        
        except Exception as e:
            self.logger.error(f"Error extracting packet features: {e}")
        
        return features
    
    def update_flow_features(self, packet_features: Dict[str, Any]) -> Optional[str]:
        """Update flow statistics with new packet"""
        if not packet_features['src_ip'] or not packet_features['dst_ip']:
            return None
        
        # Create flow key
        flow_key = self.create_flow_key(packet_features)
        current_time = packet_features['timestamp']
        
        if flow_key not in self.active_flows:
            # New flow
            self.active_flows[flow_key] = {
                'start_time': current_time,
                'last_packet_time': current_time,
                'packet_count': 0,
                'byte_count': 0,
                'packet_sizes': [],
                'inter_arrival_times': [],
                'tcp_flags_count': defaultdict(int),
                'src_ip': packet_features['src_ip'],
                'dst_ip': packet_features['dst_ip'],
                'src_port': packet_features.get('src_port', 0),
                'dst_port': packet_features.get('dst_port', 0),
                'protocol': packet_features['protocol']
            }
        
        # Update flow
        flow = self.active_flows[flow_key]
        
        # Calculate inter-arrival time
        if flow['packet_count'] > 0:
            inter_arrival_time = current_time - flow['last_packet_time']
            flow['inter_arrival_times'].append(inter_arrival_time)
        
        flow['last_packet_time'] = current_time
        flow['packet_count'] += 1
        flow['byte_count'] += packet_features['size']
        flow['packet_sizes'].append(packet_features['size'])
        
        # Update TCP flags
        if packet_features['tcp_flags']:
            for flag, present in packet_features['tcp_flags'].items():
                if present:
                    flow['tcp_flags_count'][flag] += 1
        
        return flow_key
    
    def create_flow_key(self, packet_features: Dict[str, Any]) -> str:
        """Create a unique key for the flow"""
        src_ip = packet_features['src_ip']
        dst_ip = packet_features['dst_ip']
        src_port = packet_features.get('src_port', 0)
        dst_port = packet_features.get('dst_port', 0)
        protocol = packet_features['protocol']
        
        # Normalize flow direction
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def detect_port_scan(self, packet_features: Dict[str, Any]) -> float:
        """Detect port scanning activity"""
        src_ip = packet_features['src_ip']
        dst_ip = packet_features['dst_ip']
        dst_port = packet_features.get('dst_port')
        current_time = packet_features['timestamp']
        
        if not dst_port:
            return 0.0
        
        # Track connections from source to destination
        self.host_connections[src_ip][dst_ip].add(dst_port)
        
        # Clean old entries
        self.cleanup_old_connections(current_time)
        
        # Calculate port scan score
        unique_ports = len(self.host_connections[src_ip][dst_ip])
        
        if unique_ports > self.thresholds['suspicious_port_threshold']:
            score = min(unique_ports / 100.0, 1.0)  # Normalize to 0-1
            return score
        
        return 0.0
    
    def detect_ddos(self, packet_features: Dict[str, Any]) -> float:
        """Detect DDoS attacks"""
        dst_ip = packet_features['dst_ip']
        current_time = packet_features['timestamp']
        
        # Add packet to target's packet count
        self.target_packet_count[dst_ip].append(current_time)
        
        # Count packets in the last window
        window_start = current_time - self.ddos_window
        recent_packets = [t for t in self.target_packet_count[dst_ip] if t >= window_start]
        
        packet_rate = len(recent_packets) / self.ddos_window
        
        if packet_rate > self.thresholds['ddos_packet_threshold'] / self.ddos_window:
            score = min(packet_rate * self.ddos_window / self.thresholds['ddos_packet_threshold'], 1.0)
            return score
        
        return 0.0
    
    def cleanup_old_connections(self, current_time: float):
        """Clean up old connection tracking data"""
        cutoff_time = current_time - self.port_scan_window
        
        # Clean up completed flows
        while self.completed_flows and self.completed_flows[0]['end_time'] < cutoff_time:
            self.completed_flows.popleft()
    
    def get_flow_features(self, flow_key: str) -> Optional[FlowFeatures]:
        """Calculate comprehensive features for a flow"""
        if flow_key not in self.active_flows:
            return None
        
        flow = self.active_flows[flow_key]
        
        duration = flow['last_packet_time'] - flow['start_time']
        duration = max(duration, 0.001)  # Avoid division by zero
        
        # Calculate statistics
        packet_sizes = flow['packet_sizes']
        inter_arrival_times = flow['inter_arrival_times']
        
        packet_size_mean = np.mean(packet_sizes) if packet_sizes else 0
        packet_size_std = np.std(packet_sizes) if len(packet_sizes) > 1 else 0
        
        inter_arrival_mean = np.mean(inter_arrival_times) if inter_arrival_times else 0
        inter_arrival_std = np.std(inter_arrival_times) if len(inter_arrival_times) > 1 else 0
        
        flow_rate = flow['byte_count'] / duration
        
        # Create features object
        features = FlowFeatures(
            src_ip=flow['src_ip'],
            dst_ip=flow['dst_ip'],
            src_port=flow['src_port'],
            dst_port=flow['dst_port'],
            protocol=flow['protocol'],
            duration=duration,
            packet_count=flow['packet_count'],
            byte_count=flow['byte_count'],
            flow_rate=flow_rate,
            packet_size_mean=packet_size_mean,
            packet_size_std=packet_size_std,
            inter_arrival_time_mean=inter_arrival_mean,
            inter_arrival_time_std=inter_arrival_std,
            tcp_flags=dict(flow['tcp_flags_count']),
            port_scan_score=0.0,  # Will be calculated separately
            ddos_score=0.0        # Will be calculated separately
        )
        
        return features
    
    def analyze_packet(self, packet) -> Dict[str, Any]:
        """Analyze a single packet and return analysis results"""
        packet_features = self.extract_packet_features(packet)
        
        if not packet_features['src_ip']:
            return {'anomaly_score': 0.0, 'alerts': []}
        
        # Update flow
        flow_key = self.update_flow_features(packet_features)
        
        # Detect attacks
        port_scan_score = self.detect_port_scan(packet_features)
        ddos_score = self.detect_ddos(packet_features)
        
        # Update statistics
        self.packet_stats['total'] += 1
        self.protocol_stats[packet_features['protocol']] += 1
        
        if packet_features.get('dst_port'):
            self.port_stats[packet_features['dst_port']] += 1
        
        # Generate alerts
        alerts = []
        anomaly_score = 0.0
        
        if port_scan_score > 0.3:
            alerts.append({
                'type': 'port_scan',
                'severity': 'medium' if port_scan_score < 0.7 else 'high',
                'score': port_scan_score,
                'description': f"Potential port scan from {packet_features['src_ip']}"
            })
            anomaly_score = max(anomaly_score, port_scan_score)
        
        if ddos_score > 0.3:
            alerts.append({
                'type': 'ddos',
                'severity': 'medium' if ddos_score < 0.7 else 'high',
                'score': ddos_score,
                'description': f"Potential DDoS attack on {packet_features['dst_ip']}"
            })
            anomaly_score = max(anomaly_score, ddos_score)
        
        return {
            'packet_features': packet_features,
            'flow_key': flow_key,
            'anomaly_score': anomaly_score,
            'alerts': alerts,
            'port_scan_score': port_scan_score,
            'ddos_score': ddos_score
        }
    
    def start_live_capture(self, packet_handler=None):
        """Start live packet capture"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available. Cannot start live capture.")
            return False
        
        self.is_capturing = True
        
        def capture_packets():
            try:
                def packet_callback(packet):
                    if self.is_capturing:
                        analysis = self.analyze_packet(packet)
                        if packet_handler:
                            packet_handler(analysis)
                        else:
                            self.default_packet_handler(analysis)
                
                sniff(iface=self.interface, filter=self.capture_filter, 
                      prn=packet_callback, store=False)
                      
            except Exception as e:
                self.logger.error(f"Error in packet capture: {e}")
                self.is_capturing = False
        
        self.capture_thread = threading.Thread(target=capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        self.logger.info("Live packet capture started")
        return True
    
    def stop_live_capture(self):
        """Stop live packet capture"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        self.logger.info("Live packet capture stopped")
    
    def default_packet_handler(self, analysis: Dict[str, Any]):
        """Default packet handler for live capture"""
        if analysis['alerts']:
            for alert in analysis['alerts']:
                self.logger.warning(f"ALERT: {alert['description']} (Score: {alert['score']:.2f})")
        
        if analysis['anomaly_score'] > 0.5:
            self.logger.info(f"High anomaly score: {analysis['anomaly_score']:.2f}")
    
    def get_flow_statistics(self) -> Dict[str, Any]:
        """Get current flow statistics"""
        active_flow_count = len(self.active_flows)
        completed_flow_count = len(self.completed_flows)
        
        return {
            'active_flows': active_flow_count,
            'completed_flows': completed_flow_count,
            'total_packets': self.packet_stats['total'],
            'protocol_distribution': dict(self.protocol_stats),
            'top_ports': dict(sorted(self.port_stats.items(), 
                                   key=lambda x: x[1], reverse=True)[:10])
        }
    
    def export_flows_to_csv(self, filename: str) -> bool:
        """Export flow data to CSV for analysis"""
        try:
            flows_data = []
            
            for flow_key, flow in self.active_flows.items():
                features = self.get_flow_features(flow_key)
                if features:
                    flows_data.append({
                        'src_ip': features.src_ip,
                        'dst_ip': features.dst_ip,
                        'src_port': features.src_port,
                        'dst_port': features.dst_port,
                        'protocol': features.protocol,
                        'duration': features.duration,
                        'packet_count': features.packet_count,
                        'byte_count': features.byte_count,
                        'flow_rate': features.flow_rate,
                        'packet_size_mean': features.packet_size_mean,
                        'packet_size_std': features.packet_size_std,
                        'inter_arrival_mean': features.inter_arrival_time_mean,
                        'inter_arrival_std': features.inter_arrival_time_std,
                        'anomaly_score': features.anomaly_score
                    })
            
            df = pd.DataFrame(flows_data)
            df.to_csv(filename, index=False)
            self.logger.info(f"Exported {len(flows_data)} flows to {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting flows: {e}")
            return False
    
    def analyze_pcap_file(self, pcap_file: str) -> List[Dict[str, Any]]:
        """Analyze a PCAP file and return analysis results"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available. Cannot analyze PCAP file.")
            return []
        
        try:
            from scapy.all import rdpcap
            
            packets = rdpcap(pcap_file)
            analyses = []
            
            for packet in packets:
                analysis = self.analyze_packet(packet)
                analyses.append(analysis)
            
            self.logger.info(f"Analyzed {len(packets)} packets from {pcap_file}")
            return analyses
            
        except Exception as e:
            self.logger.error(f"Error analyzing PCAP file: {e}")
            return []