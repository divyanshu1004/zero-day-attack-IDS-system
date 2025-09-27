#!/usr/bin/env python3
"""
Test suite for Zero-Day Attack Detection IDS
"""

import unittest
import numpy as np
import pandas as pd
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from data.dataset_manager import DatasetManager
    from models.ensemble_detector import EnsembleDetector
    from analysis.traffic_analyzer import TrafficAnalyzer
    from simulation.attack_simulator import AttackSimulator, AttackScenario
    from detection.real_time_monitor import RealTimeMonitor
    from utils.helpers import setup_logging, calculate_metrics
    MODULES_AVAILABLE = True
except ImportError:
    MODULES_AVAILABLE = False

class TestDatasetManager(unittest.TestCase):
    """Test cases for DatasetManager"""
    
    def setUp(self):
        self.dm = DatasetManager(data_dir="test_datasets")
    
    def test_initialization(self):
        """Test DatasetManager initialization"""
        self.assertIsInstance(self.dm, DatasetManager)
        self.assertTrue(os.path.exists(self.dm.data_dir))
    
    def test_sample_data_generation(self):
        """Test sample data generation"""
        train_df, test_df = self.dm.create_sample_nsl_kdd_data()
        
        self.assertIsInstance(train_df, pd.DataFrame)
        self.assertIsInstance(test_df, pd.DataFrame)
        self.assertGreater(len(train_df), 0)
        self.assertGreater(len(test_df), 0)
        self.assertTrue('attack_type' in train_df.columns)
    
    def test_data_preprocessing(self):
        """Test data preprocessing pipeline"""
        data = self.dm.get_preprocessed_data('nsl_kdd')
        
        self.assertIn('X_train', data)
        self.assertIn('X_test', data)
        self.assertIn('y_train', data)
        self.assertIn('y_test', data)
        
        # Check data shapes
        X_train, X_test = data['X_train'], data['X_test']
        y_train, y_test = data['y_train'], data['y_test']
        
        self.assertEqual(len(X_train), len(y_train))
        self.assertEqual(len(X_test), len(y_test))
        self.assertEqual(X_train.shape[1], X_test.shape[1])

class TestEnsembleDetector(unittest.TestCase):
    """Test cases for EnsembleDetector"""
    
    def setUp(self):
        self.input_dim = 10
        self.ensemble = EnsembleDetector(
            input_dim=self.input_dim,
            models_config={
                'isolation_forest': {'contamination': 0.1},
                'one_class_svm': {'nu': 0.1}
            }
        )
        
        # Generate sample data
        np.random.seed(42)
        self.X_train = np.random.randn(1000, self.input_dim)
        self.y_train = np.random.choice([0, 1], size=1000, p=[0.8, 0.2])
        self.X_test = np.random.randn(200, self.input_dim)
        self.y_test = np.random.choice([0, 1], size=200, p=[0.8, 0.2])
    
    def test_initialization(self):
        """Test ensemble initialization"""
        self.assertEqual(self.ensemble.input_dim, self.input_dim)
        self.assertGreater(len(self.ensemble.models), 0)
        self.assertFalse(self.ensemble.is_trained)
    
    def test_training(self):
        """Test ensemble training"""
        results = self.ensemble.train(self.X_train, self.y_train)
        
        self.assertTrue(self.ensemble.is_trained)
        self.assertIsInstance(results, dict)
    
    def test_prediction(self):
        """Test ensemble prediction"""
        # Train first
        self.ensemble.train(self.X_train, self.y_train)
        
        # Make predictions
        predictions = self.ensemble.predict(self.X_test)
        
        self.assertEqual(len(predictions), len(self.X_test))
        self.assertTrue(all(p in [0, 1] for p in predictions))
    
    def test_anomaly_scores(self):
        """Test anomaly score generation"""
        self.ensemble.train(self.X_train, self.y_train)
        scores = self.ensemble.get_anomaly_scores(self.X_test)
        
        self.assertIsInstance(scores, dict)
        self.assertGreater(len(scores), 0)

class TestTrafficAnalyzer(unittest.TestCase):
    """Test cases for TrafficAnalyzer"""
    
    def setUp(self):
        self.analyzer = TrafficAnalyzer()
    
    def test_initialization(self):
        """Test traffic analyzer initialization"""
        self.assertIsInstance(self.analyzer, TrafficAnalyzer)
        self.assertEqual(len(self.analyzer.active_flows), 0)
        self.assertFalse(self.analyzer.is_capturing)
    
    def test_flow_key_creation(self):
        """Test flow key creation"""
        packet_features = {
            'src_ip': '192.168.1.1',
            'dst_ip': '192.168.1.2',
            'src_port': 1234,
            'dst_port': 80,
            'protocol': 'TCP'
        }
        
        flow_key = self.analyzer.create_flow_key(packet_features)
        self.assertIsInstance(flow_key, str)
        self.assertIn('192.168.1', flow_key)
    
    def test_statistics_collection(self):
        """Test statistics collection"""
        stats = self.analyzer.get_flow_statistics()
        
        self.assertIsInstance(stats, dict)
        self.assertIn('active_flows', stats)
        self.assertIn('total_packets', stats)

class TestAttackSimulator(unittest.TestCase):
    """Test cases for AttackSimulator"""
    
    def setUp(self):
        self.simulator = AttackSimulator()
    
    def test_initialization(self):
        """Test attack simulator initialization"""
        self.assertIsInstance(self.simulator, AttackSimulator)
        self.assertIsInstance(self.simulator.source_ip, str)
    
    def test_training_data_generation(self):
        """Test synthetic training data generation"""
        X, y = self.simulator.generate_training_data(num_samples=100)
        
        self.assertEqual(len(X), 100)
        self.assertEqual(len(y), 100)
        self.assertTrue(all(label in [0, 1] for label in y))
        self.assertGreater(X.shape[1], 0)
    
    def test_attack_scenario_creation(self):
        """Test attack scenario creation"""
        scenario_config = {
            'name': 'Test Attack',
            'type': 'dos',
            'target_ip': '192.168.1.100',
            'duration': 60
        }
        
        scenario = self.simulator.create_attack_scenario_from_config(scenario_config)
        
        self.assertIsInstance(scenario, AttackScenario)
        self.assertEqual(scenario.name, 'Test Attack')
        self.assertEqual(scenario.attack_type, 'dos')

class TestUtilityFunctions(unittest.TestCase):
    """Test cases for utility functions"""
    
    def test_metrics_calculation(self):
        """Test metrics calculation"""
        y_true = np.array([0, 0, 1, 1, 0, 1])
        y_pred = np.array([0, 1, 1, 1, 0, 0])
        
        metrics = calculate_metrics(y_true, y_pred)
        
        self.assertIn('accuracy', metrics)
        self.assertIn('precision', metrics)
        self.assertIn('recall', metrics)
        self.assertIn('f1_score', metrics)
        
        # Check metric ranges
        for metric in ['accuracy', 'precision', 'recall', 'f1_score']:
            self.assertGreaterEqual(metrics[metric], 0.0)
            self.assertLessEqual(metrics[metric], 1.0)

class TestIntegration(unittest.TestCase):
    """Integration tests for the complete IDS system"""
    
    def test_end_to_end_pipeline(self):
        """Test complete end-to-end pipeline"""
        # 1. Load data
        dm = DatasetManager(data_dir="test_datasets")
        data = dm.get_preprocessed_data('nsl_kdd')
        
        # 2. Train models
        ensemble = EnsembleDetector(
            input_dim=data['X_train'].shape[1],
            models_config={'isolation_forest': {'contamination': 0.1}}
        )
        ensemble.train(data['X_train'][:500], data['y_train'][:500])  # Use subset for speed
        
        # 3. Make predictions
        predictions = ensemble.predict(data['X_test'][:100])
        
        # 4. Calculate metrics
        metrics = calculate_metrics(data['y_test'][:100], predictions)
        
        # Verify pipeline worked
        self.assertGreater(metrics['accuracy'], 0.5)  # Should be better than random
        self.assertEqual(len(predictions), 100)
    
    def test_attack_simulation_and_detection(self):
        """Test attack simulation and detection pipeline"""
        # Generate synthetic attack data
        simulator = AttackSimulator()
        X_synthetic, y_synthetic = simulator.generate_training_data(num_samples=500)
        
        # Train detector on synthetic data
        ensemble = EnsembleDetector(
            input_dim=X_synthetic.shape[1],
            models_config={'isolation_forest': {'contamination': 0.2}}
        )
        ensemble.train(X_synthetic, y_synthetic)
        
        # Generate new attack scenarios
        test_X, test_y = simulator.generate_training_data(num_samples=100)
        predictions = ensemble.predict(test_X)
        
        # Verify detection capability
        self.assertEqual(len(predictions), 100)
        self.assertTrue(any(p == 1 for p in predictions))  # Should detect some attacks

def run_performance_benchmarks():
    """Run performance benchmarks for the IDS system"""
    print("\n🔄 Running Performance Benchmarks...")
    print("=" * 50)
    
    # Data loading benchmark
    start_time = time.time()
    dm = DatasetManager()
    data = dm.get_preprocessed_data('nsl_kdd')
    load_time = time.time() - start_time
    print(f"📊 Data loading time: {load_time:.2f}s")
    
    # Model training benchmark
    start_time = time.time()
    ensemble = EnsembleDetector(
        input_dim=data['X_train'].shape[1],
        models_config={
            'isolation_forest': {'contamination': 0.1},
            'one_class_svm': {'nu': 0.1}
        }
    )
    ensemble.train(data['X_train'][:1000], data['y_train'][:1000])
    train_time = time.time() - start_time
    print(f"🧠 Model training time: {train_time:.2f}s")
    
    # Prediction benchmark
    start_time = time.time()
    predictions = ensemble.predict(data['X_test'][:1000])
    predict_time = time.time() - start_time
    throughput = 1000 / predict_time
    print(f"🚀 Prediction time: {predict_time:.2f}s")
    print(f"⚡ Throughput: {throughput:.0f} samples/second")
    
    # Memory usage estimation
    import psutil
    import os
    process = psutil.Process(os.getpid())
    memory_mb = process.memory_info().rss / 1024 / 1024
    print(f"💾 Memory usage: {memory_mb:.1f} MB")
    
    return {
        'load_time': load_time,
        'train_time': train_time,
        'predict_time': predict_time,
        'throughput': throughput,
        'memory_mb': memory_mb
    }

def run_all_tests():
    """Run all tests and benchmarks"""
    print("🧪 Zero-Day Attack Detection IDS - Test Suite")
    print("=" * 60)
    
    if not MODULES_AVAILABLE:
        print("❌ Required modules not available. Skipping tests.")
        return False
    
    # Run unit tests
    test_suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)
    
    # Run performance benchmarks
    if result.wasSuccessful():
        benchmarks = run_performance_benchmarks()
        
        print("\n✅ All tests passed successfully!")
        print(f"⚡ System ready for deployment with {benchmarks['throughput']:.0f} samples/sec throughput")
        return True
    else:
        print("\n❌ Some tests failed. Please review the issues above.")
        return False

if __name__ == "__main__":
    import time
    success = run_all_tests()
    sys.exit(0 if success else 1)