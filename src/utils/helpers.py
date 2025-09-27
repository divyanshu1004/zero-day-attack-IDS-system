"""
Utility functions for the IDS system
"""

import os
import json
import logging
import pickle
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import hashlib
import yaml

def setup_logging(log_level: str = "INFO", log_file: str = None) -> logging.Logger:
    """Setup logging configuration"""
    
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_level.upper()))
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, log_level.upper()))
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from JSON or YAML file"""
    
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    try:
        with open(config_path, 'r') as f:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                config = yaml.safe_load(f)
            else:
                config = json.load(f)
        
        return config
    
    except Exception as e:
        raise ValueError(f"Error loading configuration: {e}")

def save_config(config: Dict[str, Any], config_path: str):
    """Save configuration to JSON file"""
    
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
    
    except Exception as e:
        raise ValueError(f"Error saving configuration: {e}")

def normalize_features(X: np.ndarray, scaler=None, method: str = "standard") -> Tuple[np.ndarray, Any]:
    """Normalize feature matrix"""
    
    if method == "standard":
        from sklearn.preprocessing import StandardScaler
        if scaler is None:
            scaler = StandardScaler()
            X_normalized = scaler.fit_transform(X)
        else:
            X_normalized = scaler.transform(X)
    
    elif method == "minmax":
        from sklearn.preprocessing import MinMaxScaler
        if scaler is None:
            scaler = MinMaxScaler()
            X_normalized = scaler.fit_transform(X)
        else:
            X_normalized = scaler.transform(X)
    
    elif method == "robust":
        from sklearn.preprocessing import RobustScaler
        if scaler is None:
            scaler = RobustScaler()
            X_normalized = scaler.fit_transform(X)
        else:
            X_normalized = scaler.transform(X)
    
    else:
        raise ValueError(f"Unknown normalization method: {method}")
    
    return X_normalized, scaler

def calculate_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_scores: np.ndarray = None) -> Dict[str, float]:
    """Calculate classification metrics"""
    
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, roc_auc_score, average_precision_score
    )
    
    metrics = {
        'accuracy': accuracy_score(y_true, y_pred),
        'precision': precision_score(y_true, y_pred, average='weighted', zero_division=0),
        'recall': recall_score(y_true, y_pred, average='weighted', zero_division=0),
        'f1_score': f1_score(y_true, y_pred, average='weighted', zero_division=0)
    }
    
    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    metrics['confusion_matrix'] = cm.tolist()
    
    # ROC AUC if scores available
    if y_scores is not None:
        try:
            if len(np.unique(y_true)) == 2:  # Binary classification
                metrics['roc_auc'] = roc_auc_score(y_true, y_scores)
                metrics['average_precision'] = average_precision_score(y_true, y_scores)
            else:  # Multi-class
                metrics['roc_auc'] = roc_auc_score(y_true, y_scores, multi_class='ovr', average='weighted')
        except ValueError as e:
            logging.warning(f"Could not calculate ROC AUC: {e}")
    
    return metrics

def create_feature_importance_plot(feature_names: List[str], importances: np.ndarray, 
                                 title: str = "Feature Importance", save_path: str = None):
    """Create feature importance plot"""
    
    try:
        import matplotlib.pyplot as plt
        
        # Sort features by importance
        indices = np.argsort(importances)[::-1]
        
        plt.figure(figsize=(12, 8))
        plt.title(title)
        plt.bar(range(len(importances)), importances[indices])
        plt.xticks(range(len(importances)), [feature_names[i] for i in indices], rotation=45, ha='right')
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path)
        else:
            plt.show()
        
        plt.close()
    
    except ImportError:
        logging.warning("Matplotlib not available. Cannot create plot.")

def generate_report(metrics: Dict[str, Any], output_path: str = None) -> str:
    """Generate evaluation report"""
    
    report = f"""
# IDS Evaluation Report
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Performance Metrics

### Classification Performance
- **Accuracy**: {metrics.get('accuracy', 'N/A'):.4f}
- **Precision**: {metrics.get('precision', 'N/A'):.4f}
- **Recall**: {metrics.get('recall', 'N/A'):.4f}
- **F1 Score**: {metrics.get('f1_score', 'N/A'):.4f}

### Additional Metrics
- **ROC AUC**: {metrics.get('roc_auc', 'N/A'):.4f}
- **Average Precision**: {metrics.get('average_precision', 'N/A'):.4f}

### Confusion Matrix
{metrics.get('confusion_matrix', 'N/A')}

## Model Information
- **Model Type**: {metrics.get('model_type', 'Unknown')}
- **Training Time**: {metrics.get('training_time', 'N/A')} seconds
- **Number of Features**: {metrics.get('num_features', 'N/A')}
- **Training Samples**: {metrics.get('num_training_samples', 'N/A')}
- **Test Samples**: {metrics.get('num_test_samples', 'N/A')}

## Dataset Information
- **Dataset**: {metrics.get('dataset_name', 'Unknown')}
- **Attack Types**: {metrics.get('attack_types', 'N/A')}
- **Normal/Attack Ratio**: {metrics.get('class_distribution', 'N/A')}

## Notes
{metrics.get('notes', 'No additional notes.')}
"""
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(report)
    
    return report

def hash_file(file_path: str) -> str:
    """Calculate SHA-256 hash of file"""
    
    hasher = hashlib.sha256()
    
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    except Exception as e:
        logging.error(f"Error hashing file {file_path}: {e}")
        return ""

def save_model(model: Any, model_path: str, metadata: Dict[str, Any] = None):
    """Save model with metadata"""
    
    try:
        # Save model
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        
        # Save metadata
        if metadata:
            metadata_path = model_path.replace('.pkl', '_metadata.json')
            metadata['file_hash'] = hash_file(model_path)
            metadata['save_timestamp'] = datetime.now().isoformat()
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
        
        logging.info(f"Model saved to {model_path}")
    
    except Exception as e:
        logging.error(f"Error saving model: {e}")
        raise

def load_model(model_path: str) -> Tuple[Any, Dict[str, Any]]:
    """Load model with metadata"""
    
    try:
        # Load model
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        
        # Load metadata if available
        metadata = {}
        metadata_path = model_path.replace('.pkl', '_metadata.json')
        
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Verify file integrity
            current_hash = hash_file(model_path)
            if metadata.get('file_hash') != current_hash:
                logging.warning("Model file hash mismatch. File may be corrupted.")
        
        logging.info(f"Model loaded from {model_path}")
        return model, metadata
    
    except Exception as e:
        logging.error(f"Error loading model: {e}")
        raise

def create_directories(paths: List[str]):
    """Create directories if they don't exist"""
    
    for path in paths:
        try:
            os.makedirs(path, exist_ok=True)
            logging.info(f"Directory created: {path}")
        except Exception as e:
            logging.error(f"Error creating directory {path}: {e}")

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    
    try:
        import ipaddress
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def validate_port(port: int) -> bool:
    """Validate port number"""
    
    return 1 <= port <= 65535

def format_bytes(bytes_value: int) -> str:
    """Format bytes to human readable format"""
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    
    return f"{bytes_value:.1f} PB"

def format_duration(seconds: float) -> str:
    """Format duration to human readable format"""
    
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours"

def get_system_info() -> Dict[str, Any]:
    """Get system information"""
    
    import platform
    import psutil
    
    return {
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'cpu_count': psutil.cpu_count(),
        'memory_total': format_bytes(psutil.virtual_memory().total),
        'memory_available': format_bytes(psutil.virtual_memory().available),
        'disk_usage': format_bytes(psutil.disk_usage('/').free) if os.name != 'nt' else format_bytes(psutil.disk_usage('C:\\').free)
    }

def export_to_csv(data: List[Dict[str, Any]], filename: str, columns: List[str] = None):
    """Export data to CSV file"""
    
    try:
        df = pd.DataFrame(data)
        
        if columns:
            df = df[columns]
        
        df.to_csv(filename, index=False)
        logging.info(f"Data exported to {filename}")
    
    except Exception as e:
        logging.error(f"Error exporting to CSV: {e}")

def import_from_csv(filename: str) -> pd.DataFrame:
    """Import data from CSV file"""
    
    try:
        df = pd.read_csv(filename)
        logging.info(f"Data imported from {filename}")
        return df
    
    except Exception as e:
        logging.error(f"Error importing from CSV: {e}")
        raise

class Timer:
    """Context manager for timing operations"""
    
    def __init__(self, description: str = "Operation"):
        self.description = description
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.time()
        duration = self.end_time - self.start_time
        logging.info(f"{self.description} completed in {format_duration(duration)}")
    
    @property
    def elapsed_time(self) -> float:
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return 0.0

def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """Split list into chunks of specified size"""
    
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def safe_division(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Perform safe division avoiding division by zero"""
    
    try:
        if denominator == 0:
            return default
        return numerator / denominator
    except (TypeError, ValueError):
        return default