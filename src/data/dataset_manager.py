"""
Dataset Manager for handling various cybersecurity datasets
"""

import os
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Optional
import requests
import zipfile
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import logging

class DatasetManager:
    """Manages downloading, preprocessing, and loading of cybersecurity datasets"""
    
    def __init__(self, data_dir: str = "datasets"):
        self.data_dir = data_dir
        self.logger = logging.getLogger(__name__)
        self.datasets = {
            'nsl_kdd': {
                'train_url': 'https://www.unb.ca/cic/datasets/nsl.html',
                'test_url': 'https://www.unb.ca/cic/datasets/nsl.html',
                'features': 41,
                'classes': ['normal', 'dos', 'probe', 'r2l', 'u2r']
            },
            'cicids2017': {
                'url': 'https://www.unb.ca/cic/datasets/ids-2017.html',
                'features': 78,
                'classes': ['BENIGN', 'DoS', 'PortScan', 'Bot', 'Infiltration', 'Web Attack', 'Brute Force']
            },
            'unsw_nb15': {
                'url': 'https://research.unsw.edu.au/projects/unsw-nb15-dataset',
                'features': 49,
                'classes': ['Normal', 'Fuzzers', 'Analysis', 'Backdoors', 'DoS', 'Exploits', 'Generic', 'Reconnaissance', 'Shellcode', 'Worms']
            }
        }
        
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
    
    def download_nsl_kdd(self) -> bool:
        """Download NSL-KDD dataset"""
        try:
            # NSL-KDD dataset URLs (example - replace with actual URLs)
            train_url = "https://github.com/jmnwong/NSL-KDD-Dataset/raw/master/KDDTrain+.txt"
            test_url = "https://github.com/jmnwong/NSL-KDD-Dataset/raw/master/KDDTest+.txt"
            
            train_file = os.path.join(self.data_dir, "KDDTrain+.txt")
            test_file = os.path.join(self.data_dir, "KDDTest+.txt")
            
            if not os.path.exists(train_file):
                self.logger.info("Downloading NSL-KDD training data...")
                response = requests.get(train_url)
                with open(train_file, 'wb') as f:
                    f.write(response.content)
            
            if not os.path.exists(test_file):
                self.logger.info("Downloading NSL-KDD test data...")
                response = requests.get(test_url)
                with open(test_file, 'wb') as f:
                    f.write(response.content)
            
            return True
        except Exception as e:
            self.logger.error(f"Error downloading NSL-KDD: {e}")
            return False
    
    def load_nsl_kdd(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Load and preprocess NSL-KDD dataset"""
        try:
            # Column names for NSL-KDD dataset
            column_names = [
                'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
                'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
                'num_failed_logins', 'logged_in', 'num_compromised',
                'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
                'num_shells', 'num_access_files', 'num_outbound_cmds',
                'is_host_login', 'is_guest_login', 'count', 'srv_count',
                'serror_rate', 'srv_serror_rate', 'rerror_rate',
                'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
                'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
                'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
                'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
                'dst_host_serror_rate', 'dst_host_srv_serror_rate',
                'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
                'attack_type', 'difficulty'
            ]
            
            train_file = os.path.join(self.data_dir, "KDDTrain+.txt")
            test_file = os.path.join(self.data_dir, "KDDTest+.txt")
            
            # Create sample data if files don't exist
            if not os.path.exists(train_file):
                self.create_sample_nsl_kdd_data()
            
            train_df = pd.read_csv(train_file, names=column_names)
            test_df = pd.read_csv(test_file, names=column_names)
            
            # Preprocess the data
            train_df = self.preprocess_nsl_kdd(train_df)
            test_df = self.preprocess_nsl_kdd(test_df)
            
            return train_df, test_df
            
        except Exception as e:
            self.logger.error(f"Error loading NSL-KDD: {e}")
            return self.create_sample_nsl_kdd_data()
    
    def create_sample_nsl_kdd_data(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Create sample NSL-KDD data for testing purposes"""
        np.random.seed(42)
        
        # Generate sample data
        n_samples = 10000
        n_features = 41
        
        # Create feature names
        feature_names = [f'feature_{i}' for i in range(n_features)]
        
        # Generate random data
        X = np.random.randn(n_samples, n_features)
        
        # Create labels (80% normal, 20% attacks)
        attack_types = ['normal', 'dos', 'probe', 'r2l', 'u2r']
        y = np.random.choice(attack_types, n_samples, p=[0.8, 0.1, 0.05, 0.025, 0.025])
        
        # Create DataFrame
        data = pd.DataFrame(X, columns=feature_names)
        data['attack_type'] = y
        
        # Split into train/test
        train_df, test_df = train_test_split(data, test_size=0.2, random_state=42, stratify=y)
        
        # Save to files
        train_file = os.path.join(self.data_dir, "KDDTrain+.txt")
        test_file = os.path.join(self.data_dir, "KDDTest+.txt")
        
        train_df.to_csv(train_file, index=False, header=False)
        test_df.to_csv(test_file, index=False, header=False)
        
        self.logger.info("Created sample NSL-KDD data")
        return train_df, test_df
    
    def preprocess_nsl_kdd(self, df: pd.DataFrame) -> pd.DataFrame:
        """Preprocess NSL-KDD dataset"""
        # Handle categorical features
        categorical_features = ['protocol_type', 'service', 'flag']
        
        for feature in categorical_features:
            if feature in df.columns:
                df[feature] = pd.Categorical(df[feature]).codes
        
        # Create binary classification (normal vs attack)
        if 'attack_type' in df.columns:
            df['is_attack'] = (df['attack_type'] != 'normal').astype(int)
            
            # Map attack types to categories
            attack_mapping = {
                'normal': 0,
                'dos': 1, 'neptune': 1, 'smurf': 1, 'pod': 1, 'teardrop': 1,
                'back': 1, 'land': 1, 'apache2': 1, 'processtable': 1, 'mailbomb': 1,
                'probe': 2, 'satan': 2, 'ipsweep': 2, 'nmap': 2, 'portsweep': 2,
                'saint': 2, 'mscan': 2,
                'r2l': 3, 'guess_passwd': 3, 'ftp_write': 3, 'imap': 3, 'phf': 3,
                'multihop': 3, 'warezmaster': 3, 'warezclient': 3, 'spy': 3,
                'xlock': 3, 'xsnoop': 3, 'snmpread': 3, 'snmpgetattack': 3,
                'httptunnel': 3, 'sendmail': 3, 'named': 3,
                'u2r': 4, 'buffer_overflow': 4, 'loadmodule': 4, 'perl': 4,
                'rootkit': 4, 'ps': 4, 'sqlattack': 4, 'xterm': 4
            }
            
            df['attack_category'] = df['attack_type'].map(attack_mapping).fillna(0)
        
        return df
    
    def get_preprocessed_data(self, dataset_name: str = 'nsl_kdd') -> Dict:
        """Get preprocessed data ready for training"""
        if dataset_name == 'nsl_kdd':
            train_df, test_df = self.load_nsl_kdd()
        else:
            raise ValueError(f"Dataset {dataset_name} not supported yet")
        
        # Separate features and labels
        feature_cols = [col for col in train_df.columns if col not in ['attack_type', 'is_attack', 'attack_category', 'difficulty']]
        
        X_train = train_df[feature_cols].values
        y_train = train_df['is_attack'].values if 'is_attack' in train_df.columns else train_df['attack_category'].values
        
        X_test = test_df[feature_cols].values
        y_test = test_df['is_attack'].values if 'is_attack' in test_df.columns else test_df['attack_category'].values
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        return {
            'X_train': X_train_scaled,
            'X_test': X_test_scaled,
            'y_train': y_train,
            'y_test': y_test,
            'feature_names': feature_cols,
            'scaler': self.scaler
        }
    
    def download_datasets(self) -> bool:
        """Download all supported datasets"""
        success = True
        
        try:
            self.logger.info("Downloading datasets...")
            if not self.download_nsl_kdd():
                success = False
            
            # Add more datasets here
            
            self.logger.info("Dataset download completed")
            return success
            
        except Exception as e:
            self.logger.error(f"Error downloading datasets: {e}")
            return False
    
    def get_dataset_info(self) -> Dict:
        """Get information about available datasets"""
        return self.datasets
    
    def create_synthetic_anomaly_data(self, base_data: np.ndarray, anomaly_ratio: float = 0.1) -> Tuple[np.ndarray, np.ndarray]:
        """Create synthetic anomaly data for testing zero-day detection"""
        n_samples = base_data.shape[0]
        n_anomalies = int(n_samples * anomaly_ratio)
        
        # Create normal data labels
        labels = np.zeros(n_samples)
        
        # Add synthetic anomalies
        anomaly_indices = np.random.choice(n_samples, n_anomalies, replace=False)
        
        # Modify features to create anomalies
        anomaly_data = base_data.copy()
        for idx in anomaly_indices:
            # Add noise or scale certain features to create anomalies
            noise = np.random.normal(0, 2, base_data.shape[1])
            anomaly_data[idx] += noise
            labels[idx] = 1
        
        return anomaly_data, labels