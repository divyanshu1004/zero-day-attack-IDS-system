"""
Ensemble Detector - Combines multiple ML models for robust zero-day attack detection
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any
import logging
import joblib
import json
from datetime import datetime
import os

# Machine Learning imports
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split

# Deep Learning imports
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, models
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    logging.warning("TensorFlow not available. Deep learning models will be disabled.")

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logging.warning("PyTorch not available. PyTorch models will be disabled.")

class AutoEncoder:
    """TensorFlow-based Autoencoder for anomaly detection"""
    
    def __init__(self, input_dim: int, encoding_dim: int = 32):
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.model = None
        self.threshold = None
        
        if TF_AVAILABLE:
            self.build_model()
    
    def build_model(self):
        """Build autoencoder architecture"""
        # Encoder
        input_layer = keras.Input(shape=(self.input_dim,))
        encoded = layers.Dense(128, activation='relu')(input_layer)
        encoded = layers.Dense(64, activation='relu')(encoded)
        encoded = layers.Dense(self.encoding_dim, activation='relu')(encoded)
        
        # Decoder
        decoded = layers.Dense(64, activation='relu')(encoded)
        decoded = layers.Dense(128, activation='relu')(decoded)
        decoded = layers.Dense(self.input_dim, activation='sigmoid')(decoded)
        
        self.model = keras.Model(input_layer, decoded)
        self.model.compile(optimizer='adam', loss='mse')
    
    def train(self, X_train: np.ndarray, epochs: int = 100, validation_split: float = 0.2):
        """Train the autoencoder"""
        if not TF_AVAILABLE or self.model is None:
            return
        
        history = self.model.fit(
            X_train, X_train,
            epochs=epochs,
            batch_size=256,
            validation_split=validation_split,
            verbose=0
        )
        
        # Calculate reconstruction error threshold
        reconstructions = self.model.predict(X_train)
        mse = np.mean(np.power(X_train - reconstructions, 2), axis=1)
        self.threshold = np.percentile(mse, 95)
        
        return history
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomalies based on reconstruction error"""
        if not TF_AVAILABLE or self.model is None:
            return np.zeros(len(X))
        
        reconstructions = self.model.predict(X)
        mse = np.mean(np.power(X - reconstructions, 2), axis=1)
        
        return (mse > self.threshold).astype(int)
    
    def get_anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores (reconstruction errors)"""
        if not TF_AVAILABLE or self.model is None:
            return np.zeros(len(X))
        
        reconstructions = self.model.predict(X)
        mse = np.mean(np.power(X - reconstructions, 2), axis=1)
        
        # Normalize scores to 0-1 range
        if self.threshold is not None:
            return np.minimum(mse / self.threshold, 1.0)
        return mse

class LSTMDetector:
    """LSTM-based sequence anomaly detector"""
    
    def __init__(self, input_dim: int, sequence_length: int = 10, lstm_units: int = 50):
        self.input_dim = input_dim
        self.sequence_length = sequence_length
        self.lstm_units = lstm_units
        self.model = None
        self.threshold = None
        
        if TF_AVAILABLE:
            self.build_model()
    
    def build_model(self):
        """Build LSTM model"""
        model = keras.Sequential([
            layers.LSTM(self.lstm_units, return_sequences=True, 
                       input_shape=(self.sequence_length, self.input_dim)),
            layers.LSTM(self.lstm_units // 2, return_sequences=False),
            layers.Dense(32, activation='relu'),
            layers.Dense(self.input_dim, activation='sigmoid')
        ])
        
        model.compile(optimizer='adam', loss='mse')
        self.model = model
    
    def prepare_sequences(self, X: np.ndarray) -> np.ndarray:
        """Prepare data for LSTM training"""
        sequences = []
        for i in range(len(X) - self.sequence_length + 1):
            sequences.append(X[i:(i + self.sequence_length)])
        return np.array(sequences)
    
    def train(self, X_train: np.ndarray, epochs: int = 50):
        """Train LSTM model"""
        if not TF_AVAILABLE or self.model is None:
            return
        
        X_seq = self.prepare_sequences(X_train)
        y_seq = X_train[self.sequence_length-1:]
        
        history = self.model.fit(
            X_seq, y_seq,
            epochs=epochs,
            batch_size=64,
            validation_split=0.2,
            verbose=0
        )
        
        # Calculate threshold
        predictions = self.model.predict(X_seq)
        mse = np.mean(np.power(y_seq - predictions, 2), axis=1)
        self.threshold = np.percentile(mse, 95)
        
        return history
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomalies"""
        if not TF_AVAILABLE or self.model is None:
            return np.zeros(len(X))
        
        X_seq = self.prepare_sequences(X)
        if len(X_seq) == 0:
            return np.zeros(len(X))
        
        predictions = self.model.predict(X_seq)
        y_actual = X[self.sequence_length-1:]
        
        mse = np.mean(np.power(y_actual - predictions, 2), axis=1)
        anomalies = (mse > self.threshold).astype(int)
        
        # Pad with zeros for the first sequence_length-1 samples
        result = np.zeros(len(X))
        result[self.sequence_length-1:] = anomalies
        
        return result

class PyTorchAutoEncoder(nn.Module):
    """PyTorch-based Autoencoder"""
    
    def __init__(self, input_dim: int, encoding_dim: int = 32):
        super(PyTorchAutoEncoder, self).__init__()
        
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, encoding_dim),
            nn.ReLU()
        )
        
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(encoding_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Linear(128, input_dim),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

class PyTorchDetector:
    """PyTorch-based anomaly detector wrapper"""
    
    def __init__(self, input_dim: int, encoding_dim: int = 32):
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.model = None
        self.threshold = None
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        if TORCH_AVAILABLE:
            self.model = PyTorchAutoEncoder(input_dim, encoding_dim).to(self.device)
    
    def train(self, X_train: np.ndarray, epochs: int = 100, lr: float = 0.001):
        """Train PyTorch model"""
        if not TORCH_AVAILABLE or self.model is None:
            return
        
        # Prepare data
        X_tensor = torch.FloatTensor(X_train).to(self.device)
        dataset = TensorDataset(X_tensor, X_tensor)
        dataloader = DataLoader(dataset, batch_size=256, shuffle=True)
        
        # Training setup
        criterion = nn.MSELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=lr)
        
        # Training loop
        self.model.train()
        for epoch in range(epochs):
            total_loss = 0
            for batch_data, batch_target in dataloader:
                optimizer.zero_grad()
                outputs = self.model(batch_data)
                loss = criterion(outputs, batch_target)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
        
        # Calculate threshold
        self.model.eval()
        with torch.no_grad():
            reconstructions = self.model(X_tensor).cpu().numpy()
            mse = np.mean(np.power(X_train - reconstructions, 2), axis=1)
            self.threshold = np.percentile(mse, 95)
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomalies"""
        if not TORCH_AVAILABLE or self.model is None:
            return np.zeros(len(X))
        
        self.model.eval()
        with torch.no_grad():
            X_tensor = torch.FloatTensor(X).to(self.device)
            reconstructions = self.model(X_tensor).cpu().numpy()
            mse = np.mean(np.power(X - reconstructions, 2), axis=1)
            
            return (mse > self.threshold).astype(int)
    
    def get_anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores"""
        if not TORCH_AVAILABLE or self.model is None:
            return np.zeros(len(X))
        
        self.model.eval()
        with torch.no_grad():
            X_tensor = torch.FloatTensor(X).to(self.device)
            reconstructions = self.model(X_tensor).cpu().numpy()
            mse = np.mean(np.power(X - reconstructions, 2), axis=1)
            
            if self.threshold is not None:
                return np.minimum(mse / self.threshold, 1.0)
            return mse

class EnsembleDetector:
    """Ensemble of multiple anomaly detection models"""
    
    def __init__(self, input_dim: int, models_config: Dict = None):
        self.input_dim = input_dim
        self.logger = logging.getLogger(__name__)
        
        # Default configuration
        if models_config is None:
            models_config = {
                'isolation_forest': {'contamination': 0.1},
                'one_class_svm': {'nu': 0.1},
                'autoencoder': {'encoding_dim': 32},
                'lstm': {'sequence_length': 10},
                'pytorch_ae': {'encoding_dim': 32}
            }
        
        self.models_config = models_config
        self.models = {}
        self.model_weights = {}
        self.is_trained = False
        
        self.initialize_models()
    
    def initialize_models(self):
        """Initialize all models"""
        # Isolation Forest
        if 'isolation_forest' in self.models_config:
            self.models['isolation_forest'] = IsolationForest(
                **self.models_config['isolation_forest'],
                random_state=42
            )
        
        # One-Class SVM
        if 'one_class_svm' in self.models_config:
            self.models['one_class_svm'] = OneClassSVM(
                **self.models_config['one_class_svm']
            )
        
        # AutoEncoder
        if 'autoencoder' in self.models_config and TF_AVAILABLE:
            self.models['autoencoder'] = AutoEncoder(
                self.input_dim,
                **self.models_config['autoencoder']
            )
        
        # LSTM
        if 'lstm' in self.models_config and TF_AVAILABLE:
            self.models['lstm'] = LSTMDetector(
                self.input_dim,
                **self.models_config['lstm']
            )
        
        # PyTorch AutoEncoder
        if 'pytorch_ae' in self.models_config and TORCH_AVAILABLE:
            self.models['pytorch_ae'] = PyTorchDetector(
                self.input_dim,
                **self.models_config['pytorch_ae']
            )
        
        # Initialize equal weights
        self.model_weights = {name: 1.0 for name in self.models.keys()}
        
        self.logger.info(f"Initialized {len(self.models)} models: {list(self.models.keys())}")
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray = None, 
              validation_split: float = 0.2) -> Dict[str, Any]:
        """Train all models in the ensemble"""
        
        if validation_split > 0 and y_train is not None:
            X_tr, X_val, y_tr, y_val = train_test_split(
                X_train, y_train, test_size=validation_split, 
                random_state=42, stratify=y_train
            )
        else:
            X_tr, X_val, y_tr, y_val = X_train, None, y_train, None
        
        training_results = {}
        
        for name, model in self.models.items():
            try:
                self.logger.info(f"Training {name}...")
                
                if name == 'isolation_forest':
                    model.fit(X_tr)
                    
                elif name == 'one_class_svm':
                    # Train only on normal data for one-class SVM
                    if y_tr is not None:
                        normal_data = X_tr[y_tr == 0]
                        model.fit(normal_data)
                    else:
                        model.fit(X_tr)
                
                elif name == 'autoencoder':
                    history = model.train(X_tr, epochs=100)
                    training_results[name] = {'history': history}
                
                elif name == 'lstm':
                    history = model.train(X_tr, epochs=50)
                    training_results[name] = {'history': history}
                
                elif name == 'pytorch_ae':
                    model.train(X_tr, epochs=100)
                
                self.logger.info(f"Successfully trained {name}")
                
                # Validate if validation data is available
                if X_val is not None and y_val is not None:
                    val_score = self.validate_model(model, name, X_val, y_val)
                    training_results[name] = training_results.get(name, {})
                    training_results[name]['validation_score'] = val_score
                
            except Exception as e:
                self.logger.error(f"Error training {name}: {e}")
                # Remove failed model
                if name in self.model_weights:
                    del self.model_weights[name]
        
        self.is_trained = True
        self.logger.info("Ensemble training completed")
        
        return training_results
    
    def validate_model(self, model, model_name: str, X_val: np.ndarray, y_val: np.ndarray) -> float:
        """Validate individual model performance"""
        try:
            if model_name in ['isolation_forest', 'one_class_svm']:
                predictions = model.predict(X_val)
                # Convert sklearn output (-1, 1) to (1, 0)
                predictions = (predictions == -1).astype(int)
            else:
                predictions = model.predict(X_val)
            
            # Calculate AUC if possible
            if len(np.unique(y_val)) > 1:
                auc = roc_auc_score(y_val, predictions)
                return auc
            else:
                return 0.5  # No discrimination possible
                
        except Exception as e:
            self.logger.error(f"Error validating {model_name}: {e}")
            return 0.5
    
    def predict(self, X: np.ndarray, method: str = 'weighted_vote') -> np.ndarray:
        """Make ensemble predictions"""
        if not self.is_trained:
            raise ValueError("Ensemble must be trained before making predictions")
        
        predictions = {}
        
        # Get predictions from all models
        for name, model in self.models.items():
            try:
                if name == 'isolation_forest':
                    pred = model.predict(X)
                    predictions[name] = (pred == -1).astype(int)
                
                elif name == 'one_class_svm':
                    pred = model.predict(X)
                    predictions[name] = (pred == -1).astype(int)
                
                else:
                    predictions[name] = model.predict(X)
                    
            except Exception as e:
                self.logger.error(f"Error getting predictions from {name}: {e}")
                continue
        
        if not predictions:
            return np.zeros(len(X))
        
        # Combine predictions
        if method == 'weighted_vote':
            return self._weighted_vote(predictions)
        elif method == 'majority_vote':
            return self._majority_vote(predictions)
        elif method == 'max_score':
            return self._max_score_vote(predictions)
        else:
            return self._weighted_vote(predictions)
    
    def _weighted_vote(self, predictions: Dict[str, np.ndarray]) -> np.ndarray:
        """Weighted voting ensemble"""
        total_weight = 0
        weighted_sum = np.zeros(len(next(iter(predictions.values()))))
        
        for name, pred in predictions.items():
            weight = self.model_weights.get(name, 1.0)
            weighted_sum += weight * pred
            total_weight += weight
        
        return (weighted_sum / total_weight > 0.5).astype(int)
    
    def _majority_vote(self, predictions: Dict[str, np.ndarray]) -> np.ndarray:
        """Majority voting ensemble"""
        pred_sum = np.sum(list(predictions.values()), axis=0)
        return (pred_sum > len(predictions) / 2).astype(int)
    
    def _max_score_vote(self, predictions: Dict[str, np.ndarray]) -> np.ndarray:
        """Maximum score voting"""
        return np.max(list(predictions.values()), axis=0).astype(int)
    
    def get_anomaly_scores(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """Get detailed anomaly scores from all models"""
        scores = {}
        
        for name, model in self.models.items():
            try:
                if hasattr(model, 'get_anomaly_scores'):
                    scores[name] = model.get_anomaly_scores(X)
                elif hasattr(model, 'decision_function'):
                    # For sklearn models
                    decision_scores = model.decision_function(X)
                    # Normalize to 0-1 range
                    scores[name] = 1 / (1 + np.exp(-decision_scores))
                else:
                    # Fallback to binary predictions
                    if name in ['isolation_forest', 'one_class_svm']:
                        pred = model.predict(X)
                        scores[name] = (pred == -1).astype(float)
                    else:
                        scores[name] = model.predict(X).astype(float)
                        
            except Exception as e:
                self.logger.error(f"Error getting scores from {name}: {e}")
                scores[name] = np.zeros(len(X))
        
        return scores
    
    def update_model_weights(self, validation_scores: Dict[str, float]):
        """Update model weights based on validation performance"""
        total_score = sum(validation_scores.values())
        
        if total_score > 0:
            for name in self.model_weights:
                if name in validation_scores:
                    self.model_weights[name] = validation_scores[name] / total_score
        
        self.logger.info(f"Updated model weights: {self.model_weights}")
    
    def save_models(self, save_dir: str):
        """Save all trained models"""
        os.makedirs(save_dir, exist_ok=True)
        
        # Save sklearn models
        for name, model in self.models.items():
            if name in ['isolation_forest', 'one_class_svm']:
                joblib.dump(model, os.path.join(save_dir, f"{name}.pkl"))
            elif name == 'autoencoder' and hasattr(model, 'model') and model.model:
                model.model.save(os.path.join(save_dir, f"{name}.h5"))
            elif name == 'lstm' and hasattr(model, 'model') and model.model:
                model.model.save(os.path.join(save_dir, f"{name}.h5"))
            elif name == 'pytorch_ae' and hasattr(model, 'model') and model.model:
                torch.save(model.model.state_dict(), 
                          os.path.join(save_dir, f"{name}.pth"))
        
        # Save configuration and weights
        config = {
            'input_dim': self.input_dim,
            'models_config': self.models_config,
            'model_weights': self.model_weights,
            'is_trained': self.is_trained
        }
        
        with open(os.path.join(save_dir, 'ensemble_config.json'), 'w') as f:
            json.dump(config, f, indent=2)
        
        self.logger.info(f"Models saved to {save_dir}")
    
    def get_ensemble_info(self) -> Dict[str, Any]:
        """Get information about the ensemble"""
        return {
            'input_dim': self.input_dim,
            'models': list(self.models.keys()),
            'model_weights': self.model_weights,
            'is_trained': self.is_trained,
            'tensorflow_available': TF_AVAILABLE,
            'pytorch_available': TORCH_AVAILABLE
        }