#!/usr/bin/env python3
"""
Advanced ML APK Security Analyzer Launcher
==========================================

This script provides an easy way to launch the APK analyzer with
proper error handling and environment checking.

Usage: python run_analyzer.py [options]
"""

import os
import sys
import argparse
import subprocess
import logging
from pathlib import Path
import tkinter as tk
from tkinter import messagebox
import traceback

def setup_logging():
    """Setup logging configuration"""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'launcher.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger(__name__)

def check_dependencies():
    """Check if all required dependencies are installed"""
    logger = logging.getLogger(__name__)
    logger.info("Checking dependencies...")
    
    required_packages = [
        'tkinter',
        'sklearn', 
        'numpy',
        'pandas',
        'matplotlib',
        'seaborn',
        'androguard',
        'joblib'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'tkinter':
                import tkinter
            elif package == 'sklearn':
                import sklearn
            elif package == 'numpy':
                import numpy
            elif package == 'pandas':
                import pandas
            elif package == 'matplotlib':
                import matplotlib
            elif package == 'seaborn':
                import seaborn
            elif package == 'androguard':
                import androguard
            elif package == 'joblib':
                import joblib
                
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        logger.error(f"Missing dependencies: {', '.join(missing_packages)}")
        return False, missing_packages
    
    logger.info("✅ All dependencies found")
    return True, []

def check_project_structure():
    """Check if project files are in place"""
    logger = logging.getLogger(__name__)
    logger.info("Checking project structure...")
    
    required_files = [
        'ml_analyzer.py',
        'advanced_gui.py', 
        'config.yaml',
        'threat_db.json'
    ]
    
    missing_files = []
    
    for file in required_files:
        if not Path(file).exists():
            missing_files.append(file)
    
    if missing_files:
        logger.error(f"Missing files: {', '.join(missing_files)}")
        return False, missing_files
    
    logger.info("✅ Project structure valid")
    return True, []

def check_directories():
    """Create necessary directories if they don't exist"""
    logger = logging.getLogger(__name__)
    logger.info("Checking directories...")
    
    directories = ['models', 'logs', 'exports', 'data']
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        logger.info(f"Directory ready: {directory}")
    
    return True

def show_error_dialog(title, message, details=None):
    """Show error dialog to user"""
    root = tk.Tk()
    root.withdraw()  # Hide main window
    
    if details:
        full_message = f"{message}\n\nDetails:\n{details}"
    else:
        full_message = message
    
    messagebox.showerror(title, full_message)
    root.destroy()

def launch_analyzer(debug_mode=False, safe_mode=False):
    """Launch the main analyzer application"""
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("🚀 Launching Advanced ML APK Security Analyzer...")
        
        # Set environment variables
        env = os.environ.copy()
        if debug_mode:
            env['APK_ANALYZER_DEBUG'] = '1'
        if safe_mode:
            env['APK_ANALYZER_SAFE_MODE'] = '1'
        
        # Import and run the main application
        sys.path.insert(0, str(Path(__file__).parent))
        
        if safe_mode:
            logger.info("Running in safe mode (basic features only)")
        
        from advanced_gui import main as gui_main
        
        logger.info("✅ Application launched successfully")
        gui_main()
        
    except ImportError as e:
        error_msg = f"Failed to import application modules: {e}"
        logger.error(error_msg)
        show_error_dialog(
            "Import Error", 
            "Failed to start the application due to missing modules.",
            str(e)
        )
        return False
        
    except Exception as e:
        error_msg = f"Unexpected error launching application: {e}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        
        show_error_dialog(
            "Application Error",
            "An unexpected error occurred while starting the application.",
            f"{type(e).__name__}: {e}"
        )
        return False
    
    return True

def install_missing_dependencies(packages):
    """Attempt to install missing dependencies"""
    logger = logging.getLogger(__name__)
    logger.info(f"Attempting to install missing packages: {packages}")
    
    try:
        # Try to install missing packages
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install'
        ] + packages)
        
        logger.info("✅ Dependencies installed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install dependencies: {e}")
        return False

def run_setup():
    """Run the setup script"""
    logger = logging.getLogger(__name__)
    logger.info("Running setup script...")
    
    try:
        subprocess.check_call([sys.executable, 'setup.py'])
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        logger.warning("Setup script not found")
        return False

def main():
    """Main launcher function"""
    parser = argparse.ArgumentParser(
        description="Launch Advanced ML APK Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Run in debug mode with verbose logging'
    )
    
    parser.add_argument(
        '--safe-mode',
        action='store_true',
        help='Run in safe mode (disable ML features if problematic)'
    )
    
    parser.add_argument(
        '--check-only',
        action='store_true',
        help='Only check dependencies and exit'
    )
    
    parser.add_argument(
        '--setup',
        action='store_true',
        help='Run setup before launching'
    )
    
    parser.add_argument(
        '--install-deps',
        action='store_true',
        help='Attempt to install missing dependencies'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.info("Debug mode enabled")
    
    logger.info("=" * 50)
    logger.info("🤖 Advanced ML APK Security Analyzer Launcher")
    logger.info("=" * 50)
    
    # Run setup if requested
    if args.setup:
        if not run_setup():
            logger.error("Setup failed")
            return 1
    
    # Check dependencies
    deps_ok, missing_deps = check_dependencies()
    
    if not deps_ok:
        if args.install_deps:
            logger.info("Attempting to install missing dependencies...")
            if install_missing_dependencies(missing_deps):
                deps_ok, missing_deps = check_dependencies()
            
        if not deps_ok:
            error_msg = f"Missing required dependencies: {', '.join(missing_deps)}"
            logger.error(error_msg)
            
            show_error_dialog(
                "Missing Dependencies",
                "The application cannot start due to missing dependencies.",
                f"Missing packages: {', '.join(missing_deps)}\n\n" +
                "Please run: pip install -r requirements.txt\n" +
                "Or use: python run_analyzer.py --install-deps"
            )
            return 1
    
    # Check project structure
    structure_ok, missing_files = check_project_structure()
    if not structure_ok:
        error_msg = f"Missing required files: {', '.join(missing_files)}"
        logger.error(error_msg)
        
        show_error_dialog(
            "Incomplete Installation", 
            "The application is missing required files.",
            f"Missing files: {', '.join(missing_files)}\n\n" +
            "Please ensure all project files are present."
        )
        return 1
    
    # Create directories
    check_directories()
    
    if args.check_only:
        logger.info("✅ All checks passed - application ready to run")
        return 0
    

    # Launch the application
    success = launch_analyzer(
        debug_mode=args.debug,
        safe_mode=args.safe_mode
    )
    
    return 0 if success else 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n⚠️ Application startup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Critical error in launcher: {e}")
        print(traceback.format_exc())
        sys.exit(1)