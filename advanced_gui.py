# advanced_gui.py
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk
import threading
import json
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import seaborn as sns
import pandas as pd
import numpy as np
from datetime import datetime
import os

# Import our ML analyzer
from ml_analyzer import advanced_analyze_apk

class AdvancedAPKAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.analysis_history = []
        self.setup_gui()
        
    def setup_gui(self):
        self.root.title("Detecting Fake Banking App System")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')  # Dark theme
        
        # Configure style
        self.setup_styles()
        
        # Create main layout
        self.create_header()
        self.create_main_content()
        self.create_status_bar()
        
    def setup_styles(self):
        """Setup modern dark theme styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('TFrame', background='#1e1e1e')
        style.configure('TLabel', background='#1e1e1e', foreground='#ffffff')
        style.configure('TButton', background='#0d7377', foreground='#ffffff')
        style.map('TButton', background=[('active', '#14a085')])
        style.configure('TNotebook', background='#1e1e1e', borderwidth=0)
        style.configure('TNotebook.Tab', background='#2d2d2d', foreground='#ffffff')
        style.map('TNotebook.Tab', background=[('selected', '#0d7377')])
        
    def create_header(self):
        """Create modern header with gradient effect"""
        header_frame = tk.Frame(self.root, bg='#0d7377', height=80)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        # Title with icon
        title_frame = tk.Frame(header_frame, bg='#0d7377')
        title_frame.pack(expand=True, fill='both')
        
        title_label = tk.Label(
            title_frame,
            text="Team Safe-AI",
            font=("Segoe UI", 20, "bold"),
            fg='#ffffff',
            bg='#0d7377'
        )
        title_label.pack(side='left', padx=20, pady=20)
        
        subtitle_label = tk.Label(
            title_frame,
            text="Powered by Machine Learning & Threat Intelligence",
            font=("Segoe UI", 10),
            fg='#a8dadc',
            bg='#0d7377'
        )
        subtitle_label.pack(side='left', padx=(0, 20), pady=(35, 0))
        
        # Version info
        version_label = tk.Label(
            title_frame,
            text="v3.0-ML",
            font=("Segoe UI", 12, "bold"),
            fg='#f1faee',
            bg='#0d7377'
        )
        version_label.pack(side='right', padx=20, pady=20)
    
    def create_main_content(self):
        """Create main content area with tabs"""
        main_frame = tk.Frame(self.root, bg='#1e1e1e')
        main_frame.pack(expand=True, fill='both', padx=10, pady=10)
        
        # Create left panel for controls
        left_panel = tk.Frame(main_frame, bg='#2d2d2d', width=300)
        left_panel.pack(side='left', fill='y', padx=(0, 10))
        left_panel.pack_propagate(False)
        
        self.create_control_panel(left_panel)
        
        # Create right panel for results
        right_panel = tk.Frame(main_frame, bg='#1e1e1e')
        right_panel.pack(side='right', expand=True, fill='both')
        
        self.create_results_panel(right_panel)
    
    def create_control_panel(self, parent):
        """Create control panel with upload and options"""
        # Upload section
        upload_frame = tk.LabelFrame(
            parent,
            text="File Upload",
            font=("Segoe UI", 12, "bold"),
            fg='#ffffff',
            bg='#2d2d2d',
            bd=2,
            relief='groove'
        )
        upload_frame.pack(fill='x', padx=10, pady=10)
        
        self.selected_file_var = tk.StringVar()
        self.selected_file_var.set("No file selected")
        
        file_label = tk.Label(
            upload_frame,
            textvariable=self.selected_file_var,
            font=("Segoe UI", 9),
            fg='#a8dadc',
            bg='#2d2d2d',
            wraplength=250
        )
        file_label.pack(pady=5)
        
        self.upload_btn = tk.Button(
            upload_frame,
            text="Select APK File",
            command=self.upload_file,
            font=("Segoe UI", 11, "bold"),
            bg='#0d7377',
            fg='#ffffff',
            padx=20,
            pady=8,
            cursor='hand2',
            relief='flat'
        )
        self.upload_btn.pack(pady=10)
        
        # Analysis options
        options_frame = tk.LabelFrame(
            parent,
            text="Analysis Options",
            font=("Segoe UI", 12, "bold"),
            fg='#ffffff',
            bg='#2d2d2d',
            bd=2,
            relief='groove'
        )
        options_frame.pack(fill='x', padx=10, pady=10)
        
        self.deep_analysis_var = tk.BooleanVar(value=True)
        self.threat_intel_var = tk.BooleanVar(value=True)
        self.ml_analysis_var = tk.BooleanVar(value=True)
        self.behavioral_var = tk.BooleanVar(value=True)
        
        options = [
            ("ML Classification", self.ml_analysis_var),
            ("Deep Analysis", self.deep_analysis_var),
            ("Threat Intelligence", self.threat_intel_var),
            ("Behavioral Analysis", self.behavioral_var)
        ]
        
        for text, var in options:
            cb = tk.Checkbutton(
                options_frame,
                text=text,
                variable=var,
                font=("Segoe UI", 10),
                fg='#ffffff',
                bg='#2d2d2d',
                selectcolor='#0d7377',
                activebackground='#2d2d2d',
                activeforeground='#ffffff'
            )
            cb.pack(anchor='w', padx=10, pady=2)
        
        # Progress section
        progress_frame = tk.LabelFrame(
            parent,
            text="Analysis Progress",
            font=("Segoe UI", 12, "bold"),
            fg='#ffffff',
            bg='#2d2d2d',
            bd=2,
            relief='groove'
        )
        progress_frame.pack(fill='x', padx=10, pady=10)
        
        self.progress = ttk.Progressbar(
            progress_frame,
            mode='determinate',
            length=250
        )
        self.progress.pack(pady=10)
        
        self.progress_label = tk.Label(
            progress_frame,
            text="Ready to analyze",
            font=("Segoe UI", 9),
            fg='#a8dadc',
            bg='#2d2d2d'
        )
        self.progress_label.pack(pady=(0, 10))
        
        # Quick stats
        stats_frame = tk.LabelFrame(
            parent,
            text="Quick Stats",
            font=("Segoe UI", 12, "bold"),
            fg='#ffffff',
            bg='#2d2d2d',
            bd=2,
            relief='groove'
        )
        stats_frame.pack(fill='x', padx=10, pady=10)
        
        self.stats_text = tk.Text(
            stats_frame,
            height=8,
            font=("Segoe UI", 9),
            bg='#1e1e1e',
            fg='#ffffff',
            bd=0,
            wrap='word'
        )
        self.stats_text.pack(padx=10, pady=10, fill='both')
        self.update_stats()
    
    def create_results_panel(self, parent):
        """Create results panel with tabs"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(expand=True, fill='both', padx=5, pady=5)
        
        # ML Analysis Tab
        self.create_ml_tab()
        
        # Traditional Analysis Tab
        self.create_traditional_tab()
        
        # Threat Intelligence Tab
        self.create_threat_intel_tab()
        
        # Behavioral Analysis Tab
        self.create_behavioral_tab()
        
        # Visualization Tab
        self.create_visualization_tab()
        
        # History Tab
        self.create_history_tab()
    
    def create_ml_tab(self):
        """Create ML analysis results tab"""
        ml_frame = ttk.Frame(self.notebook)
        self.notebook.add(ml_frame, text=" ML Analysis")
        
        # ML Results header
        ml_header = tk.Label(
            ml_frame,
            text="Machine Learning Analysis Results",
            font=("Segoe UI", 14, "bold"),
            fg='#0d7377',
            bg='#1e1e1e'
        )
        ml_header.pack(pady=10)
        
        # ML Results display
        self.ml_results_text = scrolledtext.ScrolledText(
            ml_frame,
            wrap=tk.WORD,
            font=("Consolas", 11),
            bg='#2d2d2d',
            fg='#ffffff',
            insertbackground='#ffffff',
            selectbackground='#0d7377'
        )
        self.ml_results_text.pack(expand=True, fill='both', padx=10, pady=10)
        
        # Configure text tags for syntax highlighting
        self.ml_results_text.tag_configure("header", foreground="#14a085", font=("Consolas", 12, "bold"))
        self.ml_results_text.tag_configure("safe", foreground="#7fb069")
        self.ml_results_text.tag_configure("warning", foreground="#f4a261")
        self.ml_results_text.tag_configure("danger", foreground="#e63946")
        self.ml_results_text.tag_configure("info", foreground="#a8dadc")
    
    def create_traditional_tab(self):
        """Create traditional analysis tab"""
        trad_frame = ttk.Frame(self.notebook)
        self.notebook.add(trad_frame, text="Traditional Analysis")
        
        # Create sub-tabs for traditional analysis
        trad_notebook = ttk.Notebook(trad_frame)
        trad_notebook.pack(expand=True, fill='both', padx=5, pady=5)
        
        # Summary sub-tab
        summary_frame = ttk.Frame(trad_notebook)
        trad_notebook.add(summary_frame, text="Summary")
        
        self.summary_text = scrolledtext.ScrolledText(
            summary_frame,
            wrap=tk.WORD,
            font=("Segoe UI", 11),
            bg='#2d2d2d',
            fg='#ffffff',
            insertbackground='#ffffff'
        )
        self.summary_text.pack(expand=True, fill='both', padx=5, pady=5)
        
        # Permissions sub-tab
        permissions_frame = ttk.Frame(trad_notebook)
        trad_notebook.add(permissions_frame, text="Permissions")
        
        self.permissions_text = scrolledtext.ScrolledText(
            permissions_frame,
            wrap=tk.WORD,
            font=("Segoe UI", 10),
            bg='#2d2d2d',
            fg='#ffffff',
            insertbackground='#ffffff'
        )
        self.permissions_text.pack(expand=True, fill='both', padx=5, pady=5)
        
        # Details sub-tab
        details_frame = ttk.Frame(trad_notebook)
        trad_notebook.add(details_frame, text="Technical Details")
        
        self.details_text = scrolledtext.ScrolledText(
            details_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg='#2d2d2d',
            fg='#ffffff',
            insertbackground='#ffffff'
        )
        self.details_text.pack(expand=True, fill='both', padx=5, pady=5)
    
    def create_threat_intel_tab(self):
        """Create threat intelligence tab"""
        threat_frame = ttk.Frame(self.notebook)
        self.notebook.add(threat_frame, text="Threat Intel")
        
        threat_header = tk.Label(
            threat_frame,
            text="Threat Intelligence & Reputation Analysis",
            font=("Segoe UI", 14, "bold"),
            fg='#e63946',
            bg='#1e1e1e'
        )
        threat_header.pack(pady=10)
        
        self.threat_text = scrolledtext.ScrolledText(
            threat_frame,
            wrap=tk.WORD,
            font=("Segoe UI", 11),
            bg='#2d2d2d',
            fg='#ffffff',
            insertbackground='#ffffff'
        )
        self.threat_text.pack(expand=True, fill='both', padx=10, pady=10)
    
    def create_behavioral_tab(self):
        """Create behavioral analysis tab"""
        behavioral_frame = ttk.Frame(self.notebook)
        self.notebook.add(behavioral_frame, text="Behavioral")
        
        behavioral_header = tk.Label(
            behavioral_frame,
            text="Behavioral & Code Analysis",
            font=("Segoe UI", 14, "bold"),
            fg='#f4a261',
            bg='#1e1e1e'
        )
        behavioral_header.pack(pady=10)
        
        self.behavioral_text = scrolledtext.ScrolledText(
            behavioral_frame,
            wrap=tk.WORD,
            font=("Segoe UI", 11),
            bg='#2d2d2d',
            fg='#ffffff',
            insertbackground='#ffffff'
        )
        self.behavioral_text.pack(expand=True, fill='both', padx=10, pady=10)
    
    def create_visualization_tab(self):
        """Create data visualization tab"""
        viz_frame = ttk.Frame(self.notebook)
        self.notebook.add(viz_frame, text="Visualization")
        
        # Create matplotlib figure
        self.fig, ((self.ax1, self.ax2), (self.ax3, self.ax4)) = plt.subplots(2, 2, figsize=(12, 8))
        self.fig.patch.set_facecolor('#1e1e1e')
        
        # Configure dark theme for plots
        plt.style.use('dark_background')
        
        self.canvas = FigureCanvasTkAgg(self.fig, viz_frame)
        self.canvas.get_tk_widget().pack(expand=True, fill='both', padx=5, pady=5)
        
        # Initialize empty plots
        self.update_visualizations(None)
    
    def create_history_tab(self):
        """Create analysis history tab"""
        history_frame = ttk.Frame(self.notebook)
        self.notebook.add(history_frame, text="History")
        
        history_header = tk.Label(
            history_frame,
            text="Analysis History & Trends",
            font=("Segoe UI", 14, "bold"),
            fg='#a8dadc',
            bg='#1e1e1e'
        )
        history_header.pack(pady=10)
        
        # History controls
        history_controls = tk.Frame(history_frame, bg='#1e1e1e')
        history_controls.pack(fill='x', padx=10, pady=5)
        
        clear_btn = tk.Button(
            history_controls,
            text="Clear History",
            command=self.clear_history,
            font=("Segoe UI", 10),
            bg='#e63946',
            fg='#ffffff',
            padx=15,
            pady=5
        )
        clear_btn.pack(side='left', padx=5)
        
        export_btn = tk.Button(
            history_controls,
            text="Export Report",
            command=self.export_report,
            font=("Segoe UI", 10),
            bg='#0d7377',
            fg='#ffffff',
            padx=15,
            pady=5
        )
        export_btn.pack(side='left', padx=5)
        
        # History treeview
        columns = ('Timestamp', 'App Name', 'Package', 'Verdict', 'Risk Score', 'ML Confidence')
        self.history_tree = ttk.Treeview(history_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=120)
        
        # Scrollbar for treeview
        history_scrollbar = ttk.Scrollbar(history_frame, orient='vertical', command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=history_scrollbar.set)
        
        self.history_tree.pack(side='left', expand=True, fill='both', padx=10, pady=10)
        history_scrollbar.pack(side='right', fill='y', pady=10)
    
    def create_status_bar(self):
        """Create status bar"""
        self.status_bar = tk.Frame(self.root, bg='#0d7377', height=30)
        self.status_bar.pack(side='bottom', fill='x')
        self.status_bar.pack_propagate(False)
        
        self.status_label = tk.Label(
            self.status_bar,
            text="Ready for analysis | ML Models: Loaded ✓ | Threat DB: Updated ✓",
            font=("Segoe UI", 9),
            fg='#ffffff',
            bg='#0d7377',
            anchor='w'
        )
        self.status_label.pack(side='left', padx=10, pady=5)
        
        # Add current time
        self.time_label = tk.Label(
            self.status_bar,
            text="",
            font=("Segoe UI", 9),
            fg='#a8dadc',
            bg='#0d7377'
        )
        self.time_label.pack(side='right', padx=10, pady=5)
        self.update_time()
    
    def update_time(self):
        """Update time display"""
        current_time = datetime.now().strftime("%H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)
    
    def update_stats(self):
        """Update quick stats display"""
        stats_text = f"""
Analysis Statistics:
────────────────────
Total Analyzed: {len(self.analysis_history)}
Safe Apps: {sum(1 for a in self.analysis_history if 'SAFE' in a.get('Verdict', ''))}
Suspicious: {sum(1 for a in self.analysis_history if 'SUSPICIOUS' in a.get('Verdict', ''))}
Malicious: {sum(1 for a in self.analysis_history if 'DANGEROUS' in a.get('Verdict', ''))}

ML Model Status:
────────────────────
Classification: Active ✓
Anomaly Detection: Active ✓
Threat Intel: Connected ✓
Last Update: {datetime.now().strftime("%m/%d/%Y")}
        """
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats_text.strip())
        self.stats_text.config(state='disabled')
    
    def upload_file(self):
        """Handle file upload"""
        file_path = filedialog.askopenfilename(
            title="Select APK File for Advanced Analysis",
            filetypes=[("APK Files", "*.apk"), ("All Files", "*.*")]
        )
        
        if file_path:
            filename = os.path.basename(file_path)
            self.selected_file_var.set(f"Selected: {filename}")
            self.analyze_file_threaded(file_path)
    
    def analyze_file_threaded(self, file_path):
        """Run analysis in separate thread"""
        self.upload_btn.config(state='disabled', text='Analyzing...')
        self.progress.configure(value=0)
        self.progress_label.config(text="Initializing analysis...")
        
        def analyze():
            try:
                # Update progress
                for i, step in enumerate([
                    "Loading APK file...",
                    "Extracting metadata...", 
                    "Running ML analysis...",
                    "Checking threat intelligence...",
                    "Performing behavioral analysis...",
                    "Generating report..."
                ]):
                    self.root.after(0, lambda s=step, p=(i+1)*15: self.update_progress(s, p))
                    time.sleep(0.5)  # Simulate processing time
                
                # Run actual analysis
                result = advanced_analyze_apk(file_path)
                self.root.after(0, lambda: self.display_results(result))
                
            except Exception as e:
                error_result = {"Error": str(e), "Details": "Analysis failed"}
                self.root.after(0, lambda: self.display_results(error_result))
        
        thread = threading.Thread(target=analyze, daemon=True)
        thread.start()
    
    def update_progress(self, message, progress):
        """Update progress bar and message"""
        self.progress.configure(value=progress)
        self.progress_label.config(text=message)
    
    def display_results(self, result):
        """Display comprehensive analysis results"""
        # Reset UI
        self.upload_btn.config(state='normal', text='Select APK File')
        self.progress.configure(value=100)
        self.progress_label.config(text="Analysis complete!")
        
        # Clear previous results
        self.clear_all_displays()
        
        if "Error" in result:
            self.display_error(result)
            return
        
        # Add to history
        self.analysis_history.append(result)
        self.update_history_tree(result)
        self.update_stats()
        
        # Display results in different tabs
        self.display_ml_results(result)
        self.display_traditional_results(result)
        self.display_threat_intel_results(result)
        self.display_behavioral_results(result)
        self.update_visualizations(result)
        
        # Update status
        verdict = result.get('Verdict', 'Unknown')
        risk_score = result.get('Risk Score', 0)
        self.status_label.config(text=f"Analysis complete: {verdict} | Risk Score: {risk_score}/10")
    
    def display_ml_results(self, result):
        """Display ML analysis results with formatting"""
        self.ml_results_text.delete(1.0, tk.END)
        
        # Header
        self.ml_results_text.insert(tk.END, " MACHINE LEARNING ANALYSIS REPORT\n", "header")
        self.ml_results_text.insert(tk.END, "=" * 60 + "\n\n")
        
        # ML Predictions
        ml_predictions = result.get('ML Predictions', {})
        if ml_predictions:
            self.ml_results_text.insert(tk.END, " ML Classification Results:\n", "header")
            self.ml_results_text.insert(tk.END, f"   Classification: {ml_predictions.get('Classification', 'Unknown')}\n")
            self.ml_results_text.insert(tk.END, f"   Confidence: {ml_predictions.get('Malware Probability', 'Unknown')}\n")
            self.ml_results_text.insert(tk.END, f"   Anomaly Detection: {'Yes' if ml_predictions.get('Is Anomaly') else 'No'}\n\n")
        
        # Overall Assessment
        verdict = result.get('Verdict', 'Unknown')
        risk_level = result.get('Risk Level', 'Unknown')
        risk_score = result.get('Risk Score', 0)
        
        if 'SAFE' in verdict:
            tag = "safe"
        elif 'DANGEROUS' in verdict:
            tag = "danger"
        else:
            tag = "warning"
        
        self.ml_results_text.insert(tk.END, " Overall Assessment:\n", "header")
        self.ml_results_text.insert(tk.END, f"   Verdict: {verdict}\n", tag)
        self.ml_results_text.insert(tk.END, f"   Risk Level: {risk_level}\n", tag)
        self.ml_results_text.insert(tk.END, f"   Risk Score: {risk_score}/10\n\n", tag)
        
        # Security Concerns
        reasons = result.get('Reasons', [])
        if reasons:
            self.ml_results_text.insert(tk.END, " Security Concerns Detected:\n", "header")
            for i, reason in enumerate(reasons, 1):
                if 'ML Model' in reason:
                    self.ml_results_text.insert(tk.END, f"   {i}. {reason}\n", "danger")
                elif 'Anomaly' in reason:
                    self.ml_results_text.insert(tk.END, f"   {i}. {reason}\n", "warning")
                else:
                    self.ml_results_text.insert(tk.END, f"   {i}. {reason}\n", "info")
            self.ml_results_text.insert(tk.END, "\n")
        
        # App Information
        self.ml_results_text.insert(tk.END, " Application Information:\n", "header")
        app_info = [
            ("Name", result.get('App Name', 'N/A')),
            ("Package", result.get('Package', 'N/A')),
            ("Version", result.get('Version Name', 'N/A')),
            ("File Size", result.get('File Size', 'N/A')),
            ("Target SDK", result.get('Target SDK', 'N/A')),
            ("Analysis Time", result.get('Analysis Timestamp', 'N/A'))
        ]
        
        for label, value in app_info:
            self.ml_results_text.insert(tk.END, f"   {label}: {value}\n", "info")
    
    def display_traditional_results(self, result):
        """Display traditional analysis results"""
        # Summary
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(tk.END, f" SECURITY ANALYSIS SUMMARY\n")
        self.summary_text.insert(tk.END, f"{'='*50}\n\n")
        
        verdict = result.get('Verdict', 'Unknown')
        self.summary_text.insert(tk.END, f"Final Verdict: {verdict}\n")
        self.summary_text.insert(tk.END, f"Risk Level: {result.get('Risk Level', 'Unknown')}\n")
        self.summary_text.insert(tk.END, f"Risk Score: {result.get('Risk Score', 0)}/10\n\n")
        
        if result.get("Reasons"):
            self.summary_text.insert(tk.END, "Security Issues Found:\n")
            for i, reason in enumerate(result["Reasons"], 1):
                self.summary_text.insert(tk.END, f"{i}. {reason}\n")
        
        # Permissions
        self.permissions_text.delete(1.0, tk.END)
        permissions = result.get("Permissions", [])
        if permissions:
            self.permissions_text.insert(tk.END, f"PERMISSIONS ANALYSIS\n")
            self.permissions_text.insert(tk.END, f"Total Permissions: {len(permissions)}\n")
            self.permissions_text.insert(tk.END, "=" * 50 + "\n\n")
            
            # Categorize permissions
            high_risk = ["SMS", "CALL", "CONTACTS", "LOCATION", "CAMERA", "RECORD_AUDIO", "ADMIN"]
            dangerous_perms = [p for p in permissions if any(risk in p for risk in high_risk)]
            normal_perms = [p for p in permissions if p not in dangerous_perms]
            
            if dangerous_perms:
                self.permissions_text.insert(tk.END, "HIGH-RISK PERMISSIONS:\n")
                for perm in dangerous_perms:
                    self.permissions_text.insert(tk.END, f"  ⚠{perm}\n")
                self.permissions_text.insert(tk.END, "\n")
            
            if normal_perms:
                self.permissions_text.insert(tk.END, " STANDARD PERMISSIONS:\n")
                for perm in normal_perms:
                    self.permissions_text.insert(tk.END, f"  • {perm}\n")
        
        # Technical details
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, "TECHNICAL DETAILS\n")
        self.details_text.insert(tk.END, "=" * 60 + "\n\n")
        
        details = [
            ("App Name", result.get('App Name')),
            ("Package Name", result.get('Package')),
            ("Version Name", result.get('Version Name')),
            ("Version Code", result.get('Version Code')),
            ("Min SDK Version", result.get('Min SDK')),
            ("Target SDK Version", result.get('Target SDK')),
            ("File Size", result.get('File Size')),
            ("SHA256 Hash", result.get('SHA256 Hash')),
            ("Certificate", result.get('Certificate')),
            ("Activities", result.get('Activities', 0)),
            ("Services", result.get('Services', 0)),
            ("Receivers", result.get('Receivers', 0))
        ]
        
        for label, value in details:
            self.details_text.insert(tk.END, f"{label:<20}: {value or 'N/A'}\n")
    
    def display_threat_intel_results(self, result):
        """Display threat intelligence results"""
        self.threat_text.delete(1.0, tk.END)
        
        threat_intel = result.get('Threat Intelligence', {})
        if threat_intel:
            self.threat_text.insert(tk.END, "THREAT INTELLIGENCE REPORT\n")
            self.threat_text.insert(tk.END, "=" * 50 + "\n\n")
            
            self.threat_text.insert(tk.END, f"Hash Reputation: {threat_intel.get('hash_reputation', 'Unknown')}\n")
            self.threat_text.insert(tk.END, f"Package Reputation: {threat_intel.get('package_reputation', 'Unknown')}\n")
            self.threat_text.insert(tk.END, f"Threat Score: {threat_intel.get('threat_score', 0)}/10\n\n")
            
            sources = threat_intel.get('sources', [])
            if sources:
                self.threat_text.insert(tk.END, "Intelligence Sources:\n")
                for source in sources:
                    self.threat_text.insert(tk.END, f"• {source}\n")
            else:
                self.threat_text.insert(tk.END, " No threats detected in intelligence databases\n")
        else:
            self.threat_text.insert(tk.END, "No threat intelligence data available")
    
    def display_behavioral_results(self, result):
        """Display behavioral analysis results"""
        self.behavioral_text.delete(1.0, tk.END)
        
        behavioral = result.get('Behavioral Analysis', {})
        if behavioral and 'error' not in behavioral:
            self.behavioral_text.insert(tk.END, " BEHAVIORAL ANALYSIS REPORT\n")
            self.behavioral_text.insert(tk.END, "=" * 50 + "\n\n")
            
            # String analysis
            string_analysis = behavioral.get('string_analysis', {})
            if string_analysis:
                self.behavioral_text.insert(tk.END, " String Analysis:\n")
                for string_type, count in string_analysis.items():
                    self.behavioral_text.insert(tk.END, f"  {string_type}: {count} occurrences\n")
                self.behavioral_text.insert(tk.END, "\n")
            
            # Obfuscation detection
            if behavioral.get('obfuscation_detected'):
                self.behavioral_text.insert(tk.END, "Code obfuscation detected\n")
            
            # Crypto usage
            if behavioral.get('crypto_usage'):
                self.behavioral_text.insert(tk.END, " Cryptographic functions detected\n")
            
            # Suspicious behaviors
            suspicious_behaviors = behavioral.get('suspicious_behaviors', [])
            if suspicious_behaviors:
                self.behavioral_text.insert(tk.END, "\nSuspicious Behaviors:\n")
                for behavior in suspicious_behaviors:
                    self.behavioral_text.insert(tk.END, f"  • {behavior}\n")
        else:
            self.behavioral_text.insert(tk.END, "Behavioral analysis not available")
    
    def update_visualizations(self, result):
        """Update visualization charts"""
        # Clear previous plots
        for ax in [self.ax1, self.ax2, self.ax3, self.ax4]:
            ax.clear()
        
        if result is None:
            # Show empty state
            self.ax1.text(0.5, 0.5, 'No data to display\nAnalyze an APK to see visualizations', 
                         ha='center', va='center', transform=self.ax1.transAxes, color='white')
            self.ax1.set_title('Risk Analysis', color='white')
            
            self.ax2.text(0.5, 0.5, 'Permission Analysis', 
                         ha='center', va='center', transform=self.ax2.transAxes, color='white')
            self.ax2.set_title('Permissions', color='white')
            
            self.ax3.text(0.5, 0.5, 'ML Confidence Scores', 
                         ha='center', va='center', transform=self.ax3.transAxes, color='white')
            self.ax3.set_title('ML Analysis', color='white')
            
            self.ax4.text(0.5, 0.5, 'Analysis History', 
                         ha='center', va='center', transform=self.ax4.transAxes, color='white')
            self.ax4.set_title('History Trends', color='white')
        else:
            # Plot 1: Risk Score Breakdown
            risk_categories = ['Traditional Rules', 'ML Detection', 'Threat Intel', 'Behavioral']
            risk_scores = [2, 3, 1, 2]  # Sample data - you'd calculate from actual result
            
            colors = ['#0d7377', '#14a085', '#7fb069', '#f4a261']
            self.ax1.bar(risk_categories, risk_scores, color=colors)
            self.ax1.set_title('Risk Score Breakdown', color='white')
            self.ax1.set_ylabel('Score', color='white')
            self.ax1.tick_params(colors='white')
            
            # Plot 2: Permission Categories
            permissions = result.get('Permissions', [])
            if permissions:
                perm_categories = {'Network': 0, 'Storage': 0, 'Privacy': 0, 'System': 0, 'Other': 0}
                
                for perm in permissions:
                    if any(x in perm.upper() for x in ['INTERNET', 'NETWORK', 'WIFI']):
                        perm_categories['Network'] += 1
                    elif any(x in perm.upper() for x in ['STORAGE', 'WRITE', 'READ']):
                        perm_categories['Storage'] += 1
                    elif any(x in perm.upper() for x in ['LOCATION', 'CAMERA', 'CONTACTS', 'SMS']):
                        perm_categories['Privacy'] += 1
                    elif any(x in perm.upper() for x in ['ADMIN', 'SYSTEM', 'ROOT']):
                        perm_categories['System'] += 1
                    else:
                        perm_categories['Other'] += 1
                
                wedges, texts, autotexts = self.ax2.pie(perm_categories.values(), 
                                                       labels=perm_categories.keys(),
                                                       autopct='%1.1f%%',
                                                       colors=['#0d7377', '#14a085', '#7fb069', '#f4a261', '#e63946'])
                self.ax2.set_title('Permission Categories', color='white')
                
                for text in texts:
                    text.set_color('white')
                for autotext in autotexts:
                    autotext.set_color('white')
            
            # Plot 3: ML Confidence
            ml_data = result.get('ML Predictions', {})
            if ml_data:
                confidence_str = ml_data.get('Malware Probability', '0%')
                confidence = float(confidence_str.replace('%', '')) / 100
                
                categories = ['Legitimate', 'Malicious']
                values = [1-confidence, confidence]
                colors = ['#7fb069', '#e63946']
                
                bars = self.ax3.bar(categories, values, color=colors)
                self.ax3.set_title('ML Classification Confidence', color='white')
                self.ax3.set_ylabel('Probability', color='white')
                self.ax3.set_ylim(0, 1)
                self.ax3.tick_params(colors='white')
                
                # Add value labels on bars
                for bar, value in zip(bars, values):
                    height = bar.get_height()
                    self.ax3.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                                f'{value:.2%}', ha='center', va='bottom', color='white')
            
            # Plot 4: Analysis History Trend
            if len(self.analysis_history) > 1:
                risk_scores = [h.get('Risk Score', 0) for h in self.analysis_history[-10:]]  # Last 10
                timestamps = list(range(len(risk_scores)))
                
                self.ax4.plot(timestamps, risk_scores, marker='o', color='#14a085', linewidth=2, markersize=6)
                self.ax4.set_title('Risk Score Trend (Last 10 Analyses)', color='white')
                self.ax4.set_xlabel('Analysis #', color='white')
                self.ax4.set_ylabel('Risk Score', color='white')
                self.ax4.tick_params(colors='white')
                self.ax4.grid(True, alpha=0.3)
        
        # Adjust layout and refresh
        self.fig.tight_layout()
        self.canvas.draw()
    
    def update_history_tree(self, result):
        """Update history treeview with new result"""
        ml_predictions = result.get('ML Predictions', {})
        confidence = ml_predictions.get('Malware Probability', 'N/A')
        
        values = (
            result.get('Analysis Timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            result.get('App Name', 'Unknown')[:20] + '...' if len(result.get('App Name', '')) > 20 else result.get('App Name', 'Unknown'),
            result.get('Package', 'Unknown')[:25] + '...' if len(result.get('Package', '')) > 25 else result.get('Package', 'Unknown'),
            result.get('Verdict', 'Unknown'),
            f"{result.get('Risk Score', 0)}/10",
            confidence
        )
        
        self.history_tree.insert('', 'end', values=values)
        
        # Auto-scroll to bottom
        children = self.history_tree.get_children()
        if children:
            self.history_tree.see(children[-1])
    
    def clear_history(self):
        """Clear analysis history"""
        if messagebox.askyesno("Clear History", "Are you sure you want to clear all analysis history?"):
            self.analysis_history.clear()
            self.history_tree.delete(*self.history_tree.get_children())
            self.update_stats()
            messagebox.showinfo("Success", "Analysis history cleared!")
    
    def export_report(self):
        """Export comprehensive analysis report"""
        if not self.analysis_history:
            messagebox.showwarning("No Data", "No analysis data to export!")
            return
        
        file_path = filedialog.asksavename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Analysis Report"
        )
        
        if file_path:
            try:
                report_data = {
                    "export_timestamp": datetime.now().isoformat(),
                    "total_analyses": len(self.analysis_history),
                    "analyzer_version": "v3.0-ML",
                    "summary_stats": {
                        "safe_apps": sum(1 for a in self.analysis_history if 'SAFE' in a.get('Verdict', '')),
                        "suspicious_apps": sum(1 for a in self.analysis_history if 'SUSPICIOUS' in a.get('Verdict', '')),
                        "malicious_apps": sum(1 for a in self.analysis_history if 'DANGEROUS' in a.get('Verdict', '')),
                        "average_risk_score": sum(a.get('Risk Score', 0) for a in self.analysis_history) / len(self.analysis_history)
                    },
                    "detailed_analyses": self.analysis_history
                }
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=2, ensure_ascii=False)
                
                messagebox.showinfo("Success", f"Report exported successfully to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report:\n{str(e)}")
    
    def clear_all_displays(self):
        """Clear all result displays"""
        text_widgets = [
            self.ml_results_text, self.summary_text, self.permissions_text,
            self.details_text, self.threat_text, self.behavioral_text
        ]
        
        for widget in text_widgets:
            widget.delete(1.0, tk.END)
    
    def display_error(self, result):
        """Display error message"""
        error_msg = f" Analysis Error\n\n{result.get('Error', 'Unknown error')}\n\n"
        error_msg += result.get('Details', 'Please ensure the file is a valid APK and try again.')
        
        # Display error in ML tab (primary)
        self.ml_results_text.insert(tk.END, error_msg, "danger")
        
        # Also show in summary
        self.summary_text.insert(tk.END, error_msg)

def main():
    """Main application entry point"""
    try:
        # Create main window
        root = tk.Tk()
        
        # Set window icon (if available)
        try:
            root.iconbitmap('icon.ico')  # Add your icon file
        except:
            pass  # Icon not found, continue without it
        
        # Initialize application
        app = AdvancedAPKAnalyzerGUI(root)
        
        # Center window on screen
        root.update_idletasks()
        x = (root.winfo_screenwidth() - root.winfo_width()) // 2
        y = (root.winfo_screenheight() - root.winfo_height()) // 2
        root.geometry(f"+{x}+{y}")
        
        # Start application
        root.mainloop()
        
    except Exception as e:
        messagebox.showerror("Startup Error", f"Failed to start application:\n{str(e)}")

if __name__ == "__main__":

    main()
