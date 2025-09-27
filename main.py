#!/usr/bin/env python3
"""
Zero-Day Attack Detection IDS - Main Application
"""

import argparse
import sys
import os
import logging
import asyncio
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.detection.real_time_monitor import RealTimeMonitor
from src.models.ensemble_detector import EnsembleDetector
from src.data.dataset_manager import DatasetManager
from src.analysis.traffic_analyzer import TrafficAnalyzer
from src.simulation.attack_simulator import AttackSimulator, AttackScenario
from src.utils.helpers import setup_logging, load_config, create_directories

def setup_environment():
    """Setup necessary directories and environment"""
    directories = [
        'logs',
        'datasets', 
        'models',
        'results',
        'reports'
    ]
    
    create_directories(directories)

def train_models(config_path: str = None):
    """Train the IDS models"""
    print("🚀 Training IDS Models...")
    
    # Load configuration
    config = {}
    if config_path and os.path.exists(config_path):
        config = load_config(config_path)
    
    # Setup logging
    setup_logging(
        log_level=config.get('system', {}).get('log_level', 'INFO'),
        log_file=config.get('system', {}).get('log_file', 'logs/training.log')
    )
    
    try:
        # Load and preprocess data
        print("📊 Loading datasets...")
        dm = DatasetManager()
        data = dm.get_preprocessed_data('nsl_kdd')
        
        print(f"✓ Loaded {len(data['X_train'])} training samples and {len(data['X_test'])} test samples")
        
        # Initialize and train ensemble
        print("🧠 Training ensemble models...")
        
        models_config = config.get('models', {}).get('ensemble_config', {})
        ensemble = EnsembleDetector(data['X_train'].shape[1], models_config)
        
        training_results = ensemble.train(data['X_train'], data['y_train'])
        
        print("🧪 Evaluating models...")
        predictions = ensemble.predict(data['X_test'])
        anomaly_scores = ensemble.get_anomaly_scores(data['X_test'])
        
        # Calculate metrics
        from sklearn.metrics import classification_report, confusion_matrix
        print("\n📈 Performance Results:")
        print(classification_report(data['y_test'], predictions))
        print("\nConfusion Matrix:")
        print(confusion_matrix(data['y_test'], predictions))
        
        # Save models
        print("💾 Saving trained models...")
        models_dir = config.get('system', {}).get('models_dir', 'models')
        ensemble.save_models(models_dir)
        
        print("✅ Model training completed successfully!")
        
    except Exception as e:
        logging.error(f"Error in model training: {e}")
        print(f"❌ Training failed: {e}")
        sys.exit(1)

def start_monitoring(config_path: str = None):
    """Start real-time monitoring"""
    print("🛡️  Starting Real-Time IDS Monitoring...")
    
    # Setup logging
    setup_logging(log_level='INFO', log_file='logs/monitoring.log')
    
    try:
        # Initialize monitor
        monitor = RealTimeMonitor(config_path)
        
        # Start monitoring
        success = monitor.start_monitoring()
        
        if success:
            print("✅ Real-time monitoring started successfully!")
            print("📊 Dashboard available at: http://localhost:8765")
            print("📝 Logs available at: logs/monitoring.log")
            print("\nPress Ctrl+C to stop monitoring...")
            
            # Keep running
            try:
                while True:
                    import time
                    time.sleep(1)
                    
                    # Print periodic stats
                    stats = monitor.get_monitoring_stats()
                    if stats['performance']['total_packets'] % 1000 == 0 and stats['performance']['total_packets'] > 0:
                        print(f"📊 Processed {stats['performance']['total_packets']} packets, "
                              f"Generated {stats['performance']['total_alerts']} alerts")
            
            except KeyboardInterrupt:
                print("\n🛑 Stopping monitoring...")
                monitor.stop_monitoring()
                print("✅ Monitoring stopped successfully!")
        
        else:
            print("❌ Failed to start monitoring")
            sys.exit(1)
    
    except Exception as e:
        logging.error(f"Error in monitoring: {e}")
        print(f"❌ Monitoring failed: {e}")
        sys.exit(1)

def simulate_attacks(config_path: str = None, scenario_file: str = None):
    """Simulate attack scenarios"""
    print("💥 Starting Attack Simulation...")
    
    # Setup logging
    setup_logging(log_level='INFO', log_file='logs/simulation.log')
    
    try:
        # Initialize simulator
        simulator = AttackSimulator()
        simulator.start_simulation()
        
        # Load scenarios
        scenarios = []
        if scenario_file and os.path.exists(scenario_file):
            scenarios = simulator.load_attack_scenarios(scenario_file)
        else:
            # Create default scenarios
            scenarios = [
                AttackScenario(
                    name="Sample DoS Attack",
                    attack_type="dos",
                    description="Sample DoS attack for testing",
                    target_ip="127.0.0.1",
                    target_port=80,
                    duration_seconds=30,
                    intensity="low"
                ),
                AttackScenario(
                    name="Sample Port Scan",
                    attack_type="port_scan", 
                    description="Sample port scan for testing",
                    target_ip="127.0.0.1",
                    duration_seconds=20,
                    intensity="low"
                )
            ]
        
        print(f"🎯 Loaded {len(scenarios)} attack scenarios")
        
        # Run scenarios
        results = []
        for i, scenario in enumerate(scenarios, 1):
            print(f"\n🚀 Running scenario {i}/{len(scenarios)}: {scenario.name}")
            
            result = simulator.run_attack_scenario(scenario)
            results.append(result)
            
            if result['success']:
                print(f"✅ Scenario completed successfully")
            else:
                print(f"❌ Scenario failed: {result.get('error', 'Unknown error')}")
        
        # Summary
        successful = sum(1 for r in results if r['success'])
        print(f"\n📊 Simulation Summary:")
        print(f"   Total scenarios: {len(scenarios)}")
        print(f"   Successful: {successful}")
        print(f"   Failed: {len(scenarios) - successful}")
        
        simulator.stop_simulation()
        print("✅ Attack simulation completed!")
    
    except Exception as e:
        logging.error(f"Error in attack simulation: {e}")
        print(f"❌ Simulation failed: {e}")
        sys.exit(1)

def analyze_traffic(pcap_file: str):
    """Analyze PCAP file"""
    print(f"🔍 Analyzing traffic from: {pcap_file}")
    
    if not os.path.exists(pcap_file):
        print(f"❌ PCAP file not found: {pcap_file}")
        sys.exit(1)
    
    # Setup logging
    setup_logging(log_level='INFO', log_file='logs/analysis.log')
    
    try:
        # Initialize analyzer
        analyzer = TrafficAnalyzer()
        
        # Analyze PCAP
        analyses = analyzer.analyze_pcap_file(pcap_file)
        
        if analyses:
            print(f"✅ Analyzed {len(analyses)} packets")
            
            # Summary statistics
            alerts = [a for analysis in analyses for a in analysis['alerts']]
            anomaly_scores = [analysis['anomaly_score'] for analysis in analyses]
            
            print(f"🚨 Total alerts: {len(alerts)}")
            print(f"📊 Average anomaly score: {sum(anomaly_scores)/len(anomaly_scores):.3f}")
            print(f"🔥 Max anomaly score: {max(anomaly_scores):.3f}")
            
            # Alert breakdown
            alert_types = {}
            for alert in alerts:
                alert_type = alert.get('type', 'unknown')
                alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
            
            if alert_types:
                print("📋 Alert breakdown:")
                for alert_type, count in alert_types.items():
                    print(f"   {alert_type}: {count}")
            
            # Export results
            output_file = f"results/analysis_{Path(pcap_file).stem}.csv"
            analyzer.export_flows_to_csv(output_file)
            print(f"💾 Results exported to: {output_file}")
        
        else:
            print("❌ No packets could be analyzed")
    
    except Exception as e:
        logging.error(f"Error analyzing traffic: {e}")
        print(f"❌ Analysis failed: {e}")
        sys.exit(1)

def generate_training_data(output_file: str = "datasets/synthetic_training_data.csv", num_samples: int = 10000):
    """Generate synthetic training data"""
    print(f"🔄 Generating {num_samples} synthetic training samples...")
    
    try:
        # Initialize simulator
        simulator = AttackSimulator()
        
        # Generate data
        X, y = simulator.generate_training_data(num_samples)
        
        # Save to CSV
        import pandas as pd
        
        # Create feature names
        feature_names = [f'feature_{i}' for i in range(X.shape[1])]
        
        df = pd.DataFrame(X, columns=feature_names)
        df['label'] = y
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        df.to_csv(output_file, index=False)
        
        print(f"✅ Generated {len(df)} samples saved to: {output_file}")
        print(f"📊 Normal samples: {sum(y == 0)}")
        print(f"🚨 Attack samples: {sum(y == 1)}")
    
    except Exception as e:
        logging.error(f"Error generating training data: {e}")
        print(f"❌ Data generation failed: {e}")
        sys.exit(1)

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description="Zero-Day Attack Detection IDS")
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train IDS models')
    train_parser.add_argument('--config', type=str, help='Configuration file path')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Start real-time monitoring')
    monitor_parser.add_argument('--config', type=str, help='Configuration file path')
    
    # Simulate command
    simulate_parser = subparsers.add_parser('simulate', help='Simulate attacks')
    simulate_parser.add_argument('--config', type=str, help='Configuration file path')
    simulate_parser.add_argument('--scenarios', type=str, help='Attack scenarios file')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze PCAP file')
    analyze_parser.add_argument('pcap_file', type=str, help='PCAP file to analyze')
    
    # Generate data command
    generate_parser = subparsers.add_parser('generate-data', help='Generate synthetic training data')
    generate_parser.add_argument('--output', type=str, default='datasets/synthetic_training_data.csv',
                                help='Output file path')
    generate_parser.add_argument('--samples', type=int, default=10000,
                                help='Number of samples to generate')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Setup environment
    setup_environment()
    
    if args.command == 'train':
        train_models(args.config)
    
    elif args.command == 'monitor':
        start_monitoring(args.config)
    
    elif args.command == 'simulate':
        simulate_attacks(args.config, args.scenarios)
    
    elif args.command == 'analyze':
        analyze_traffic(args.pcap_file)
    
    elif args.command == 'generate-data':
        generate_training_data(args.output, args.samples)
    
    else:
        print("🛡️  Zero-Day Attack Detection IDS")
        print("=====================================")
        print()
        print("Available commands:")
        print("  train        - Train IDS models")
        print("  monitor      - Start real-time monitoring")
        print("  simulate     - Simulate attacks")
        print("  analyze      - Analyze PCAP file")
        print("  generate-data - Generate synthetic training data")
        print()
        print("Use --help with any command for more information.")
        print()
        print("Example usage:")
        print("  python main.py train --config configs/default_config.json")
        print("  python main.py monitor")
        print("  python main.py simulate --scenarios configs/attack_scenarios.json")

if __name__ == "__main__":
    main()