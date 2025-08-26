#!/usr/bin/env python3
"""
Advanced ML APK Security Analyzer Setup Script
===============================================

This script sets up the complete environment for the APK analyzer,
including dependencies, model training, and configuration.

Usage: python setup.py [options]
"""

import os
import sys
import subprocess
import json
import yaml
import argparse
from pathlib import Path
import urllib.request
import zipfile
import shutil

class APKAnalyzerSetup:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.models_dir = self.project_root / "models"
        self.logs_dir = self.project_root / "logs" 
        self.exports_dir = self.project_root / "exports"
        self.data_dir = self.project_root / "data"
        
    def check_python_version(self):
        """Check if Python version is compatible"""
        print("🐍 Checking Python version...")
        
        if sys.version_info < (3, 8):
            print("❌ Error: Python 3.8 or higher is required")
            print(f"   Current version: {sys.version}")
            return False
            
        print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
        return True
    
    def create_directories(self):
        """Create necessary directories"""
        print("📁 Creating project directories...")
        
        directories = [
            self.models_dir,
            self.logs_dir,
            self.exports_dir,
            self.data_dir,
            self.data_dir / "samples",
            self.data_dir / "test_apks"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"   Created: {directory}")
        
        print("✅ Directory structure created")
    
    def install_dependencies(self, dev_mode=False):
        """Install Python dependencies"""
        print("📦 Installing Python dependencies...")
        
        try:
            # Upgrade pip first
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "--upgrade", "pip"
            ])
            
            # Install main requirements
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
            ])
            
            # Install development dependencies if requested
            if dev_mode:
                dev_packages = [
                    "pytest>=7.4.0",
                    "pytest-cov>=4.1.0", 
                    "black>=23.7.0",
                    "flake8>=6.0.0",
                    "jupyter>=1.0.0"
                ]
                
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install"
                ] + dev_packages)
                
                print("✅ Development dependencies installed")
            
            print("✅ Dependencies installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Error installing dependencies: {e}")
            return False
    
    def setup_configuration(self):
        """Setup configuration files"""
        print("⚙️ Setting up configuration...")
        
        # Check if config.yaml exists
        config_file = self.project_root / "config.yaml"
        if not config_file.exists():
            print("❌ config.yaml not found. Please ensure it's in the project directory.")
            return False
        
        # Load and validate configuration
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            # Update paths in config
            config['ml']['models']['save_path'] = str(self.models_dir) + "/"
            config['logging']['file'] = str(self.logs_dir / "apk_analyzer.log")
            
            # Save updated config
            with open(config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
            
            print("✅ Configuration updated")
            return True
            
        except Exception as e:
            print(f"❌ Error setting up configuration: {e}")
            return False
    
    def download_sample_data(self):
        """Download sample APK files for testing (optional)"""
        print("📥 Setting up sample data...")
        
        # Create sample threat database if it doesn't exist
        threat_db_file = self.project_root / "threat_db.json"
        if not threat_db_file.exists():
            print("❌ threat_db.json not found. Please ensure it's in the project directory.")
            return False
        
        print("✅ Sample data ready")
        return True
    
    def train_initial_models(self):
        """Train initial ML models"""
        print("🤖 Training initial ML models...")
        
        try:
            # Import the ML analyzer
            sys.path.append(str(self.project_root))
            from ml_analyzer import MLSecurityAnalyzer
            
            # Initialize and train
            analyzer = MLSecurityAnalyzer()
            print("✅ ML models trained and saved")
            return True
            
        except Exception as e:
            print(f"❌ Error training models: {e}")
            print("   This is normal on first setup. Models will be trained on first use.")
            return True  # Don't fail setup for this
    
    def create_desktop_shortcut(self):
        """Create desktop shortcut (Windows/Linux)"""
        print("🖥️ Creating desktop shortcut...")
        
        try:
            if sys.platform == "win32":
                # Windows shortcut
                import winshell
                from win32com.client import Dispatch
                
                desktop = winshell.desktop()
                shortcut_path = os.path.join(desktop, "APK Analyzer.lnk")
                
                shell = Dispatch('WScript.Shell')
                shortcut = shell.CreateShortCut(shortcut_path)
                shortcut.Targetpath = sys.executable
                shortcut.Arguments = str(self.project_root / "advanced_gui.py")
                shortcut.WorkingDirectory = str(self.project_root)
                shortcut.IconLocation = sys.executable
                shortcut.save()
                
                print("✅ Windows shortcut created")
                
            elif sys.platform.startswith("linux"):
                # Linux desktop entry
                desktop_entry = f"""[Desktop Entry]
Name=APK Analyzer
Comment=Advanced ML APK Security Analyzer
Exec={sys.executable} {self.project_root}/advanced_gui.py
Icon=security
Terminal=false
Type=Application
Categories=Development;Security;
"""
                
                desktop_file = Path.home() / "Desktop" / "APK-Analyzer.desktop"
                with open(desktop_file, 'w') as f:
                    f.write(desktop_entry)
                
                # Make executable
                os.chmod(desktop_file, 0o755)
                print("✅ Linux desktop entry created")
                
        except Exception as e:
            print(f"⚠️ Could not create desktop shortcut: {e}")
            print("   You can run the application with: python advanced_gui.py")
    
    def run_tests(self):
        """Run basic tests to verify setup"""
        print("🧪 Running setup verification tests...")
        
        try:
            # Test imports
            import tkinter as tk
            import sklearn
            import pandas as pd
            import numpy as np
            import matplotlib.pyplot as plt
            import seaborn as sns
            from androguard.core.bytecodes.apk import APK
            
            print("✅ All imports successful")
            
            # Test GUI creation (without showing)
            root = tk.Tk()
            root.withdraw()  # Hide window
            root.destroy()
            
            print("✅ GUI framework working")
            
            # Test model loading/creation
            sys.path.append(str(self.project_root))
            from ml_analyzer import MLSecurityAnalyzer
            
            analyzer = MLSecurityAnalyzer()
            print("✅ ML analyzer initialized")
            
            return True
            
        except Exception as e:
            print(f"❌ Test failed: {e}")
            return False
    
    def setup_environment(self, dev_mode=False, skip_models=False):
        """Complete setup process"""
        print("🚀 Starting Advanced ML APK Analyzer setup...")
        print("=" * 50)
        
        # Step-by-step setup
        steps = [
            ("Python version check", self.check_python_version),
            ("Directory creation", self.create_directories),
            ("Dependency installation", lambda: self.install_dependencies(dev_mode)),
            ("Configuration setup", self.setup_configuration),
            ("Sample data setup", self.download_sample_data),
        ]
        
        if not skip_models:
            steps.append(("ML model training", self.train_initial_models))
        
        steps.extend([
            ("Desktop shortcut", self.create_desktop_shortcut),
            ("Setup verification", self.run_tests)
        ])
        
        failed_steps = []
        
        for step_name, step_func in steps:
            print(f"\n{step_name}...")
            if not step_func():
                failed_steps.append(step_name)
        
        # Summary
        print("\n" + "=" * 50)
        print("🏁 Setup Summary")
        print("=" * 50)
        
        if not failed_steps:
            print("✅ Setup completed successfully!")
            print("\n🎉 You can now run the APK analyzer:")
            print(f"   python {self.project_root}/advanced_gui.py")
            
        else:
            print("⚠️ Setup completed with warnings:")
            for step in failed_steps:
                print(f"   - {step}")
            print("\n💡 The application may still work despite these warnings.")
        
        print(f"\n📁 Project directory: {self.project_root}")
        print(f"📊 Models directory: {self.models_dir}")
        print(f"📋 Logs directory: {self.logs_dir}")
        
        return len(failed_steps) == 0

def main():
    """Main setup function"""
    parser = argparse.ArgumentParser(
        description="Setup Advanced ML APK Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python setup.py                    # Basic setup
  python setup.py --dev             # Setup with development tools
  python setup.py --skip-models     # Skip ML model training
        """
    )
    
    parser.add_argument(
        '--dev', 
        action='store_true',
        help='Install development dependencies'
    )
    
    parser.add_argument(
        '--skip-models',
        action='store_true', 
        help='Skip ML model training (faster setup)'
    )
    
    parser.add_argument(
        '--test-only',
        action='store_true',
        help='Run verification tests only'
    )
    
    args = parser.parse_args()
    
    setup = APKAnalyzerSetup()
    
    if args.test_only:
        print("🧪 Running verification tests only...")
        success = setup.run_tests()
        sys.exit(0 if success else 1)
    
    success = setup.setup_environment(
        dev_mode=args.dev,
        skip_models=args.skip_models
    )
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()