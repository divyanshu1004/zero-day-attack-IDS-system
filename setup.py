#!/usr/bin/env python3
"""
Setup script for Zero-Day Attack Detection IDS
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version}")
    return True

def install_requirements():
    """Install required packages"""
    print("\n📦 Installing required packages...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("✅ Successfully installed all requirements")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing requirements: {e}")
        return False

def setup_directories():
    """Create necessary directories"""
    print("\n📁 Setting up directories...")
    directories = [
        "data/raw",
        "data/processed",
        "data/models",
        "logs",
        "outputs",
        "datasets",
        "test_datasets"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"  ✓ {directory}")
    
    print("✅ Directories created successfully")

def check_optional_dependencies():
    """Check availability of optional dependencies"""
    print("\n🔍 Checking optional dependencies...")
    
    optional_deps = {
        'tensorflow': 'Deep Learning support',
        'torch': 'PyTorch support',
        'scapy': 'Network traffic analysis',
        'psutil': 'System monitoring',
        'jupyter': 'Notebook support'
    }
    
    available = {}
    for package, description in optional_deps.items():
        try:
            __import__(package)
            print(f"  ✅ {package}: {description}")
            available[package] = True
        except ImportError:
            print(f"  ⚠️  {package}: {description} (not available)")
            available[package] = False
    
    return available

def create_config_files():
    """Create default configuration files"""
    print("\n⚙️  Creating configuration files...")
    
    # Create logging config
    logging_config = """
[loggers]
keys=root,ids

[handlers]
keys=consoleHandler,fileHandler

[formatters]
keys=simpleFormatter

[logger_root]
level=DEBUG
handlers=consoleHandler

[logger_ids]
level=DEBUG
handlers=consoleHandler,fileHandler
qualname=ids
propagate=0

[handler_consoleHandler]
class=StreamHandler
level=INFO
formatter=simpleFormatter
args=(sys.stdout,)

[handler_fileHandler]
class=FileHandler
level=DEBUG
formatter=simpleFormatter
args=('logs/ids.log',)

[formatter_simpleFormatter]
format=%(asctime)s - %(name)s - %(levelname)s - %(message)s
"""
    
    with open('configs/logging.conf', 'w') as f:
        f.write(logging_config)
    
    print("  ✓ logging.conf")
    print("✅ Configuration files created")

def run_basic_tests():
    """Run basic system tests"""
    print("\n🧪 Running basic system tests...")
    
    try:
        # Test imports
        sys.path.insert(0, 'src')
        from data.dataset_manager import DatasetManager
        from models.ensemble_detector import EnsembleDetector
        print("  ✅ Core modules import successfully")
        
        # Test data manager
        dm = DatasetManager()
        print("  ✅ DatasetManager initialized")
        
        # Test ensemble detector
        ensemble = EnsembleDetector(input_dim=10)
        print("  ✅ EnsembleDetector initialized")
        
        print("✅ All basic tests passed")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

def display_system_info():
    """Display system information"""
    print("\n💻 System Information:")
    print(f"  Platform: {platform.system()} {platform.release()}")
    print(f"  Architecture: {platform.machine()}")
    print(f"  Python: {sys.version}")
    print(f"  Working directory: {os.getcwd()}")

def main():
    """Main setup function"""
    print("🚀 Zero-Day Attack Detection IDS Setup")
    print("=" * 50)
    
    # Display system info
    display_system_info()
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Setup directories
    setup_directories()
    
    # Install requirements
    if not install_requirements():
        print("\n⚠️  Warning: Some packages failed to install.")
        print("The system will still work with reduced functionality.")
    
    # Check optional dependencies
    available_deps = check_optional_dependencies()
    
    # Create config files
    create_config_files()
    
    # Run basic tests
    if run_basic_tests():
        print("\n🎉 Setup completed successfully!")
        print("\n📋 Next steps:")
        print("1. Run the main application: python main.py --help")
        print("2. Start with data analysis: jupyter notebook analysis/ids_comprehensive_analysis.ipynb")
        print("3. Train models: python main.py train --dataset nsl_kdd")
        print("4. Start monitoring: python main.py monitor")
        print("5. Run simulations: python main.py simulate --attack-type dos")
        
        # Show capability summary based on available dependencies
        print("\n🔧 Available capabilities:")
        if available_deps.get('tensorflow', False):
            print("  ✅ TensorFlow deep learning models")
        if available_deps.get('torch', False):
            print("  ✅ PyTorch neural networks")
        if available_deps.get('scapy', False):
            print("  ✅ Real-time network traffic analysis")
        if available_deps.get('jupyter', False):
            print("  ✅ Interactive analysis notebooks")
        
        print("\n📚 Documentation:")
        print("  - README.md: Complete usage guide")
        print("  - analysis/ids_comprehensive_analysis.ipynb: Interactive tutorial")
        print("  - configs/: Configuration files")
        print("  - tests/: Test suite")
        
        return True
    else:
        print("\n❌ Setup completed with errors. Please check the logs above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)