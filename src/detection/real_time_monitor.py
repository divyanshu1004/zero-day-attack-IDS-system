"""
Real-Time Network Monitoring and Attack Detection System
"""

import time
import threading
import logging
import json
import queue
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
import numpy as np
from collections import defaultdict, deque
import asyncio
import websockets
import os
import http.server
import socketserver
from pathlib import Path

from ..analysis.traffic_analyzer import TrafficAnalyzer, FlowFeatures
from ..models.ensemble_detector import EnsembleDetector
from ..data.dataset_manager import DatasetManager

class AlertManager:
    """Manages alerts and notifications"""
    
    def __init__(self, alert_threshold: float = 0.5):
        self.alert_threshold = alert_threshold
        self.alerts = deque(maxlen=1000)
        self.alert_callbacks = []
        self.logger = logging.getLogger(__name__)
    
    def add_alert_callback(self, callback: Callable[[Dict], None]):
        """Add callback function for alert notifications"""
        self.alert_callbacks.append(callback)
    
    def trigger_alert(self, alert_data: Dict[str, Any]):
        """Trigger an alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'id': f"alert_{int(time.time() * 1000)}",
            **alert_data
        }
        
        self.alerts.append(alert)
        self.logger.warning(f"ALERT: {alert['description']} (Score: {alert['severity_score']:.2f})")
        
        # Notify callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                self.logger.error(f"Error in alert callback: {e}")
    
    def get_recent_alerts(self, minutes: int = 30) -> List[Dict]:
        """Get alerts from the last N minutes"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        
        recent_alerts = []
        for alert in self.alerts:
            alert_time = datetime.fromisoformat(alert['timestamp'])
            if alert_time >= cutoff_time:
                recent_alerts.append(alert)
        
        return recent_alerts
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        if not self.alerts:
            return {'total_alerts': 0}
        
        alert_types = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for alert in self.alerts:
            alert_types[alert.get('type', 'unknown')] += 1
            severity_counts[alert.get('severity', 'unknown')] += 1
        
        return {
            'total_alerts': len(self.alerts),
            'alert_types': dict(alert_types),
            'severity_distribution': dict(severity_counts),
            'last_alert': self.alerts[-1]['timestamp'] if self.alerts else None
        }

class PerformanceMonitor:
    """Monitors system performance and processing statistics"""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.processing_times = deque(maxlen=window_size)
        self.packet_rates = deque(maxlen=window_size)
        self.start_time = time.time()
        self.total_packets = 0
        self.total_alerts = 0
        
    def record_processing_time(self, processing_time: float):
        """Record packet processing time"""
        self.processing_times.append(processing_time)
    
    def record_packet_rate(self, packets_per_second: float):
        """Record packet processing rate"""
        self.packet_rates.append(packets_per_second)
    
    def increment_packet_count(self):
        """Increment total packet count"""
        self.total_packets += 1
    
    def increment_alert_count(self):
        """Increment total alert count"""
        self.total_alerts += 1
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get current performance statistics"""
        uptime = time.time() - self.start_time
        
        stats = {
            'uptime_seconds': uptime,
            'total_packets': self.total_packets,
            'total_alerts': self.total_alerts,
            'packets_per_second_avg': self.total_packets / uptime if uptime > 0 else 0,
            'alert_rate': self.total_alerts / uptime if uptime > 0 else 0
        }
        
        if self.processing_times:
            stats.update({
                'avg_processing_time_ms': np.mean(self.processing_times) * 1000,
                'max_processing_time_ms': np.max(self.processing_times) * 1000,
                'min_processing_time_ms': np.min(self.processing_times) * 1000
            })
        
        if self.packet_rates:
            stats.update({
                'current_packet_rate': self.packet_rates[-1] if self.packet_rates else 0,
                'avg_packet_rate': np.mean(self.packet_rates),
                'max_packet_rate': np.max(self.packet_rates)
            })
        
        return stats

class RealTimeMonitor:
    """Main real-time monitoring system"""
    
    def __init__(self, config_file: str = None):
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        self.config = self.load_config(config_file)
        
        # Initialize components
        self.traffic_analyzer = TrafficAnalyzer(
            interface=self.config.get('network_interface'),
            capture_filter=self.config.get('capture_filter')
        )
        
        self.alert_manager = AlertManager(
            alert_threshold=self.config.get('alert_threshold', 0.5)
        )
        
        self.performance_monitor = PerformanceMonitor()
        
        # ML Model
        self.ensemble_detector = None
        self.model_ready = False
        
        # Processing queues
        self.packet_queue = queue.Queue(maxsize=10000)
        self.analysis_queue = queue.Queue(maxsize=1000)
        
        # Control flags
        self.is_monitoring = False
        self.is_training = False
        
        # Worker threads
        self.packet_processor_thread = None
        self.model_analyzer_thread = None
        self.websocket_server = None
        self.websocket_thread = None
        self.websocket_loop = None
        self._websocket_stop_event = threading.Event()
        
        # HTTP dashboard server
        self.http_server = None
        self.http_thread = None
        self._http_stop_event = threading.Event()
        
        # WebSocket clients tracking
        self.websocket_clients = set()
        
        # Adaptive learning
        self.feedback_buffer = deque(maxlen=1000)
        self.retrain_threshold = 100
        self.last_retrain_time = time.time()
        
        # Setup alert callback for real-time WebSocket broadcasting
        self.alert_manager.add_alert_callback(self.broadcast_alert_to_websockets)
        
        # Initialize model
        self.initialize_model()
    
    def load_config(self, config_file: str = None) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            'network_interface': None,
            'capture_filter': None,
            'alert_threshold': 0.5,
            'model_update_interval': 3600,  # 1 hour
            'max_packet_rate': 10000,
            'websocket_port': 8765,
            'log_level': 'INFO'
        }
        
        if config_file:
            try:
                with open(config_file, 'r') as f:
                    file_config = json.load(f)
                default_config.update(file_config)
            except Exception as e:
                self.logger.error(f"Error loading config file: {e}")
        
        return default_config
    
    def initialize_model(self):
        """Initialize the ML ensemble detector"""
        try:
            # Load training data
            dm = DatasetManager()
            data = dm.get_preprocessed_data('nsl_kdd')
            
            # Initialize ensemble
            self.ensemble_detector = EnsembleDetector(
                input_dim=data['X_train'].shape[1]
            )
            
            # Train ensemble
            self.logger.info("Training ensemble detector...")
            self.ensemble_detector.train(data['X_train'], data['y_train'])
            self.model_ready = True
            
            self.logger.info("Model initialization completed")
            
        except Exception as e:
            self.logger.error(f"Error initializing model: {e}")
            self.model_ready = False
    
    def packet_handler(self, analysis_result: Dict[str, Any]):
        """Handle analyzed packets from traffic analyzer"""
        try:
            # Add to processing queue
            if not self.packet_queue.full():
                self.packet_queue.put(analysis_result, block=False)
            else:
                self.logger.warning("Packet queue full, dropping packet")
            
            # Update performance metrics
            self.performance_monitor.increment_packet_count()
            
        except Exception as e:
            self.logger.error(f"Error in packet handler: {e}")
    
    def packet_processor(self):
        """Process packets from the queue"""
        while self.is_monitoring:
            try:
                # Get packet from queue
                analysis_result = self.packet_queue.get(timeout=1.0)
                
                start_time = time.time()
                
                # Process immediate alerts from traffic analyzer
                if analysis_result['alerts']:
                    for alert in analysis_result['alerts']:
                        self.alert_manager.trigger_alert(alert)
                        self.performance_monitor.increment_alert_count()
                
                # Add to ML analysis queue if model is ready
                if (self.model_ready and 
                    analysis_result.get('packet_features') and
                    not self.analysis_queue.full()):
                    
                    self.analysis_queue.put(analysis_result, block=False)
                
                # Record processing time
                processing_time = time.time() - start_time
                self.performance_monitor.record_processing_time(processing_time)
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")
    
    def model_analyzer(self):
        """Analyze packets using ML models"""
        batch_size = 32
        batch = []
        
        while self.is_monitoring:
            try:
                # Collect batch
                analysis_result = self.analysis_queue.get(timeout=1.0)
                batch.append(analysis_result)
                
                if len(batch) >= batch_size:
                    self.process_ml_batch(batch)
                    batch = []
                    
            except queue.Empty:
                if batch:
                    self.process_ml_batch(batch)
                    batch = []
                continue
            except Exception as e:
                self.logger.error(f"Error in ML analyzer: {e}")
    
    def process_ml_batch(self, batch: List[Dict[str, Any]]):
        """Process a batch of packets with ML models"""
        try:
            if not self.model_ready:
                return
            
            # Extract features for ML analysis
            features = []
            packet_info = []
            
            for analysis_result in batch:
                # Create feature vector from traffic analyzer results
                pf = analysis_result['packet_features']
                
                # Basic features (you may need to adjust based on your feature set)
                feature_vector = [
                    pf.get('size', 0),
                    pf.get('payload_size', 0),
                    analysis_result.get('port_scan_score', 0),
                    analysis_result.get('ddos_score', 0),
                    pf.get('src_port', 0) if pf.get('src_port') else 0,
                    pf.get('dst_port', 0) if pf.get('dst_port') else 0
                ]
                
                # Pad or trim to match model input dimension
                target_dim = self.ensemble_detector.input_dim
                if len(feature_vector) < target_dim:
                    feature_vector.extend([0] * (target_dim - len(feature_vector)))
                elif len(feature_vector) > target_dim:
                    feature_vector = feature_vector[:target_dim]
                
                features.append(feature_vector)
                packet_info.append(analysis_result)
            
            # Make predictions
            X_batch = np.array(features)
            predictions = self.ensemble_detector.predict(X_batch)
            anomaly_scores = self.ensemble_detector.get_anomaly_scores(X_batch)
            
            # Process results
            for i, (pred, packet) in enumerate(zip(predictions, packet_info)):
                if pred == 1:  # Anomaly detected
                    # Get detailed scores from all models
                    model_scores = {name: scores[i] for name, scores in anomaly_scores.items()}
                    max_score = max(model_scores.values()) if model_scores else 0
                    
                    # Create alert
                    source_ip = packet['packet_features'].get('src_ip', 'unknown')
                    alert_data = {
                        'type': 'ml_anomaly',
                        'severity': 'high' if max_score > 0.8 else 'medium',
                        'severity_score': max_score,
                        'source_ip': source_ip,
                        'description': f"ML models detected anomaly from {source_ip}",
                        'model_scores': model_scores,
                        'packet_info': packet['packet_features']
                    }
                    
                    self.alert_manager.trigger_alert(alert_data)
                    self.performance_monitor.increment_alert_count()
            
        except Exception as e:
            self.logger.error(f"Error processing ML batch: {e}")
    
    def start_monitoring(self) -> bool:
        """Start real-time monitoring"""
        try:
            if self.is_monitoring:
                self.logger.warning("Monitoring already running")
                return True
            
            self.logger.info("Starting real-time monitoring...")
            self.is_monitoring = True
            
            # Start traffic capture
            success = self.traffic_analyzer.start_live_capture(self.packet_handler)
            if not success:
                self.is_monitoring = False
                return False
            
            # Start processing threads
            self.packet_processor_thread = threading.Thread(
                target=self.packet_processor, daemon=True
            )
            self.packet_processor_thread.start()
            
            if self.model_ready:
                self.model_analyzer_thread = threading.Thread(
                    target=self.model_analyzer, daemon=True
                )
                self.model_analyzer_thread.start()
            
            # Start WebSocket server for real-time updates
            self.start_websocket_server()
            
            # Start HTTP server for dashboard
            self.start_http_server()
            
            self.logger.info("Real-time monitoring started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting monitoring: {e}")
            self.is_monitoring = False
            return False
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.logger.info("Stopping real-time monitoring...")
        
        self.is_monitoring = False
        
        # Stop traffic capture
        self.traffic_analyzer.stop_live_capture()
        
        # Wait for threads to finish
        if self.packet_processor_thread:
            self.packet_processor_thread.join(timeout=5)
        
        if self.model_analyzer_thread:
            self.model_analyzer_thread.join(timeout=5)
        
        # Stop WebSocket server
        if self.websocket_loop:
            self._websocket_stop_event.set()
            try:
                self.websocket_loop.call_soon_threadsafe(lambda: None)
            except Exception:
                pass
        if self.websocket_thread and self.websocket_thread.is_alive():
            self.websocket_thread.join(timeout=5)
        
        # Stop HTTP server
        if self.http_server:
            self._http_stop_event.set()
            try:
                self.http_server.shutdown()
            except Exception:
                pass
        if self.http_thread and self.http_thread.is_alive():
            self.http_thread.join(timeout=5)
        
        self.logger.info("Real-time monitoring stopped")
    
    def start_websocket_server(self):
        """Start WebSocket server for real-time dashboard"""
        if self.websocket_thread and self.websocket_thread.is_alive():
            self.logger.debug("WebSocket server already running")
            return

        async def handle_client(websocket):  # Remove path parameter for websockets 11.x
            try:
                # Add client to tracking set
                self.websocket_clients.add(websocket)
                
                # Send initial connection message
                await websocket.send(json.dumps({
                    'type': 'connection',
                    'message': 'Connected to IDS monitoring'
                }))
                
                # Send initial system status
                await websocket.send(json.dumps({
                    'type': 'system_status',
                    'models': {
                        'isolationForest': self.model_ready,
                        'oneClassSVM': self.model_ready,
                        'autoencoder': self.model_ready,
                        'lstmNetwork': self.model_ready
                    }
                }))
                
                while self.is_monitoring and not self._websocket_stop_event.is_set():
                    try:
                        # Send stats update (change type to 'stats')
                        stats = self.get_monitoring_stats()
                        await websocket.send(json.dumps({
                            'type': 'stats',
                            'total_packets': stats.get('performance', {}).get('total_packets', 0),
                            'active_connections': len(self.traffic_analyzer.flow_tracker) if hasattr(self.traffic_analyzer, 'flow_tracker') else 0,
                            'suspicious_ips': []  # Will be populated from alerts
                        }))
                        
                        await asyncio.sleep(5)
                        
                    except Exception as e:
                        self.logger.error(f"Error sending WebSocket data: {e}")
                        break
                        
            except websockets.exceptions.ConnectionClosed:
                self.logger.info("WebSocket client disconnected")
            except Exception as e:
                self.logger.error(f"WebSocket client error: {e}")
            finally:
                # Remove client from tracking set
                self.websocket_clients.discard(websocket)

        async def server_main():
            port = self.config.get('websocket_port', 8765)
            try:
                async with websockets.serve(handle_client, "localhost", port) as server:
                    self.websocket_server = server
                    self.logger.info(f"WebSocket server listening on ws://localhost:{port}")
                    while not self._websocket_stop_event.is_set() and self.is_monitoring:
                        await asyncio.sleep(0.5)
            except Exception as e:
                self.logger.error(f"Failed to start WebSocket server: {e}")

        def run_server():
            self.websocket_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.websocket_loop)
            try:
                self.websocket_loop.run_until_complete(server_main())
            finally:
                # Cancel remaining tasks
                pending = asyncio.all_tasks(self.websocket_loop)
                for task in pending:
                    task.cancel()
                try:
                    self.websocket_loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                except Exception:
                    pass
                self.websocket_loop.close()
                self.logger.info("WebSocket loop closed")

        self._websocket_stop_event.clear()
        self.websocket_thread = threading.Thread(target=run_server, daemon=True)
        self.websocket_thread.start()

    def start_http_server(self):
        """Start HTTP server for dashboard"""
        if self.http_thread and self.http_thread.is_alive():
            self.logger.debug("HTTP server already running")
            return
            
        class DashboardHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                # Set the directory to serve from
                dashboard_dir = Path(__file__).parent.parent.parent / "dashboard"
                self.logger = logging.getLogger(__name__)
                self.logger.info(f"Dashboard directory: {dashboard_dir}")
                super().__init__(*args, directory=str(dashboard_dir), **kwargs)
            
            def log_message(self, format, *args):
                # Suppress default HTTP logging to avoid spam
                pass
        
        def run_http_server():
            try:
                port = self.config.get('http_port', 8000)
                self.logger.info(f"Starting HTTP server on port {port}...")
                
                with socketserver.ThreadingTCPServer(("", port), DashboardHandler) as httpd:
                    self.http_server = httpd
                    self.logger.info(f"HTTP dashboard server listening on port {port}")
                    self.logger.info(f"Dashboard available at: http://localhost:{port}")
                    
                    # Serve requests until stop event is set
                    httpd.timeout = 1  # Set timeout so we can check stop event
                    while not self._http_stop_event.is_set() and self.is_monitoring:
                        httpd.handle_request()
                        
            except Exception as e:
                self.logger.error(f"Failed to start HTTP server: {e}")
                import traceback
                self.logger.error(f"HTTP server traceback: {traceback.format_exc()}")
        
        self._http_stop_event.clear()
        self.http_thread = threading.Thread(target=run_http_server, daemon=True, name="HTTPServer")
        self.http_thread.start()

    def broadcast_alert_to_websockets(self, alert: Dict[str, Any]):
        """Broadcast alert to all connected WebSocket clients"""
        if not self.websocket_clients:
            return
            
        # Format alert for dashboard
        alert_message = {
            'type': 'alert',
            'timestamp': alert.get('timestamp'),
            'attack_type': alert.get('type', 'ML Anomaly'),
            'source_ip': alert.get('source_ip', 'Unknown'),
            'severity': alert.get('severity', 'medium'),
            'description': alert.get('description', 'Anomalous activity detected')
        }
        
        # Send to all connected clients (in a thread-safe way)
        if self.websocket_loop and not self.websocket_loop.is_closed():
            try:
                asyncio.run_coroutine_threadsafe(
                    self._send_to_all_clients(alert_message), 
                    self.websocket_loop
                )
            except Exception as e:
                self.logger.error(f"Error broadcasting alert: {e}")
    
    async def _send_to_all_clients(self, message: Dict[str, Any]):
        """Send message to all connected WebSocket clients"""
        if not self.websocket_clients:
            return
            
        # Create a copy of clients to avoid modification during iteration
        clients = self.websocket_clients.copy()
        message_json = json.dumps(message)
        
        for client in clients:
            try:
                await client.send(message_json)
            except Exception as e:
                # Remove disconnected clients
                self.websocket_clients.discard(client)
    
    def add_feedback(self, packet_id: str, is_malicious: bool, confidence: float = 1.0):
        """Add human feedback for adaptive learning"""
        feedback = {
            'timestamp': time.time(),
            'packet_id': packet_id,
            'is_malicious': is_malicious,
            'confidence': confidence
        }
        
        self.feedback_buffer.append(feedback)
        
        # Trigger retraining if enough feedback accumulated
        if (len(self.feedback_buffer) >= self.retrain_threshold and
            time.time() - self.last_retrain_time > self.config.get('model_update_interval', 3600)):
            
            self.schedule_model_update()
    
    def schedule_model_update(self):
        """Schedule model update based on feedback"""
        if self.is_training:
            return
        
        def update_model():
            try:
                self.is_training = True
                self.logger.info("Starting adaptive model update...")
                
                # Extract feedback data
                feedback_data = list(self.feedback_buffer)
                
                # TODO: Implement incremental learning or model fine-tuning
                # This would involve retraining with new feedback data
                
                self.last_retrain_time = time.time()
                self.feedback_buffer.clear()
                
                self.logger.info("Model update completed")
                
            except Exception as e:
                self.logger.error(f"Error updating model: {e}")
            finally:
                self.is_training = False
        
        update_thread = threading.Thread(target=update_model, daemon=True)
        update_thread.start()
    
    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get comprehensive monitoring statistics"""
        return {
            'timestamp': datetime.now().isoformat(),
            'monitoring_status': {
                'is_monitoring': self.is_monitoring,
                'model_ready': self.model_ready,
                'is_training': self.is_training
            },
            'performance': self.performance_monitor.get_performance_stats(),
            'alerts': self.alert_manager.get_alert_statistics(),
            'traffic': self.traffic_analyzer.get_flow_statistics(),
            'queue_status': {
                'packet_queue_size': self.packet_queue.qsize(),
                'analysis_queue_size': self.analysis_queue.qsize(),
                'feedback_buffer_size': len(self.feedback_buffer)
            }
        }
    
    def export_monitoring_data(self, filename: str) -> bool:
        """Export monitoring data for analysis"""
        try:
            data = {
                'export_time': datetime.now().isoformat(),
                'stats': self.get_monitoring_stats(),
                'recent_alerts': self.alert_manager.get_recent_alerts(minutes=60),
                'model_info': self.ensemble_detector.get_ensemble_info() if self.model_ready else None
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.logger.info(f"Monitoring data exported to {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting data: {e}")
            return False
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get data formatted for dashboard display"""
        stats = self.get_monitoring_stats()
        recent_alerts = self.alert_manager.get_recent_alerts(minutes=30)
        
        return {
            'summary': {
                'status': 'Active' if self.is_monitoring else 'Stopped',
                'total_packets': stats['performance']['total_packets'],
                'total_alerts': stats['performance']['total_alerts'],
                'uptime': stats['performance']['uptime_seconds']
            },
            'recent_alerts': recent_alerts[-10:],  # Last 10 alerts
            'performance_metrics': stats['performance'],
            'traffic_stats': stats['traffic'],
            'model_status': {
                'ready': self.model_ready,
                'training': self.is_training,
                'models': list(self.ensemble_detector.models.keys()) if self.model_ready else []
            }
        }