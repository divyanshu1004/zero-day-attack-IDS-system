"""
Zero-Day Attack Detection IDS
A comprehensive self-learning Intrusion Detection System
"""

__version__ = "1.0.0"
__author__ = "IDS Development Team"

from src.models.ensemble_detector import EnsembleDetector
from src.detection.real_time_monitor import RealTimeMonitor
from src.data.dataset_manager import DatasetManager
from src.analysis.traffic_analyzer import TrafficAnalyzer

__all__ = [
    'EnsembleDetector',
    'RealTimeMonitor', 
    'DatasetManager',
    'TrafficAnalyzer'
]