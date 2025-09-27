# 🛡️ Zero-Day Attack Detection IDS

A sophisticated **self-learning Intrusion Detection System (IDS)** designed to detect zero-day attacks using cutting-edge deep learning, ensemble methods, and advanced network traffic analysis techniques.

## 🌟 Overview

This comprehensive IDS system implements state-of-the-art machine learning approaches to identify previously unknown (zero-day) cyber attacks through:

- **Multi-layer Deep Learning**: TensorFlow/Keras autoencoders and PyTorch LSTM networks
- **Ensemble Detection**: Isolation Forest, One-Class SVM, and neural network fusion
- **Real-time Analysis**: Live network traffic monitoring and pattern recognition
- **Attack Simulation**: Custom zero-day attack scenario generation and testing
- **Self-Learning**: Continuous model adaptation and improvement

## 🚀 Key Features

### 🧠 Advanced Machine Learning

- **Deep Learning Models**: Autoencoder anomaly detection, LSTM sequence analysis
- **Ensemble Methods**: Multiple algorithms with weighted voting
- **Unsupervised Learning**: Detect unknown attack patterns without labeled data
- **Transfer Learning**: Adapt models to new network environments

### 🌐 Network Traffic Analysis

- **Real-time Monitoring**: Live packet capture and analysis using Scapy
- **Flow-based Detection**: Track connection patterns and behaviors
- **Protocol Analysis**: Deep packet inspection across multiple protocols
- **Statistical Profiling**: Advanced network flow statistics and metrics

### 🎯 Attack Detection & Simulation

- **Zero-day Detection**: Identify previously unknown attack vectors
- **Custom Attack Scenarios**: Generate sophisticated attack simulations
- **Multi-vector Analysis**: DoS, DDoS, port scanning, brute force, and more
- **Behavioral Analysis**: Detect subtle anomalies in network behavior

### 📊 Comprehensive Analysis

- **Interactive Dashboards**: Real-time visualization and monitoring
- **Performance Metrics**: Detailed accuracy, precision, recall analysis
- **Attack Taxonomy**: Classification of detected threats
- **Historical Analysis**: Trend analysis and attack pattern evolution

## Architecture

```
├── src/
│   ├── models/           # Deep learning models
│   ├── data/            # Data processing and dataset handlers
│   ├── analysis/        # Network traffic analysis
│   ├── simulation/      # Attack simulation framework
│   ├── detection/       # Detection engines
│   └── utils/          # Utility functions
├── datasets/           # Public datasets and preprocessed data
├── configs/           # Configuration files
├── tests/            # Unit and integration tests
├── docs/             # Documentation
└── notebooks/        # Jupyter notebooks for analysis
```

## Installation

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Quick Start

1. **Data Preparation**:

   ```python
   from src.data.dataset_manager import DatasetManager
   dm = DatasetManager()
   dm.download_datasets()
   ```

2. **Train Models**:

   ```python
   from src.models.ensemble_detector import EnsembleDetector
   detector = EnsembleDetector()
   detector.train()
   ```

3. **Real-Time Detection**:
   ```python
   from src.detection.real_time_monitor import RealTimeMonitor
   monitor = RealTimeMonitor()
   monitor.start_monitoring()
   ```

## Dataset Support

- NSL-KDD
- CICIDS2017/2018
- UNSW-NB15
- CSE-CIC-IDS2018
- Custom dataset formats

## Models Implemented

- **Autoencoders**: For anomaly detection
- **LSTM Networks**: For sequence analysis
- **CNN-LSTM Hybrid**: For spatiotemporal patterns
- **Isolation Forest**: For outlier detection
- **One-Class SVM**: For novelty detection
- **Ensemble Methods**: Combining multiple models

## Usage

See the `notebooks/` directory for detailed examples and tutorials.

## Contributing

Please read CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
