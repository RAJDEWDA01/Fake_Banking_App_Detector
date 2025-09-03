# ml_analyzer.py
import hashlib
import os
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import requests
import time
from datetime import datetime
import re
from typing import Dict, List, Tuple, Any
from androguard.core.apk import APK
from androguard.core.analysis.analysis import Analysis
from androguard.core.dex import DEX  # Fixed import for Androguard 4.1.3

import warnings
warnings.filterwarnings('ignore')

class MLSecurityAnalyzer:
    def __init__(self):
        self.feature_scaler = StandardScaler()
        self.malware_classifier = None
        self.anomaly_detector = None
        self.threat_db = {}
        self.load_or_train_models()
        
    def load_or_train_models(self):
        """Load existing models or train new ones"""
        try:
            # Try to load pre-trained models
            self.malware_classifier = joblib.load('models/malware_classifier.pkl')
            self.anomaly_detector = joblib.load('models/anomaly_detector.pkl')
            self.feature_scaler = joblib.load('models/feature_scaler.pkl')
            print("✅ Loaded pre-trained ML models")
        except FileNotFoundError:
            print("🔄 Training new ML models...")
            self.train_models()
    
    def generate_synthetic_training_data(self, n_samples=2000):
        """Generate more realistic synthetic training data"""
        np.random.seed(42)
        
        features = []
        labels = []
        
        # Generate features for legitimate apps (80% of dataset - more realistic)
        for _ in range(int(n_samples * 0.8)):
            feature_vector = [
                np.random.randint(3, 60),    # num_permissions (wider range)
                np.random.randint(5, 150),   # file_size_mb (more realistic range)
                np.random.randint(21, 34),   # target_sdk (modern SDKs)
                np.random.randint(16, 28),   # min_sdk (reasonable range)
                np.random.randint(0, 5),     # suspicious_permissions (even legit apps have some)
                np.random.randint(1, 2),     # has_certificate (most legit apps are signed)
                np.random.randint(1, 100),   # version_code (wider range)
                np.random.randint(0, 2),     # network_permissions
                np.random.randint(0, 1),     # admin_permissions (rare in legit apps)
                np.random.randint(10, 1000), # num_activities (more realistic range)
            ]
            features.append(feature_vector)
            labels.append(0)  # Legitimate
        
        # Generate features for malicious apps (20% of dataset)
        for _ in range(int(n_samples * 0.2)):
            feature_vector = [
                np.random.randint(20, 100),  # num_permissions (excessive permissions)
                np.random.randint(1, 30),    # file_size_mb (often smaller, packed)
                np.random.randint(10, 23),   # target_sdk (outdated)
                np.random.randint(8, 19),    # min_sdk (very old)
                np.random.randint(5, 15),    # suspicious_permissions (clearly excessive)
                np.random.randint(0, 1),     # has_certificate (many unsigned)
                np.random.randint(1, 5),     # version_code (low versions)
                np.random.randint(1, 3),     # network_permissions
                np.random.randint(1, 3),     # admin_permissions (often present)
                np.random.randint(1, 50),    # num_activities (minimal legitimate functionality)
            ]
            features.append(feature_vector)
            labels.append(1)  # Malicious
        
        return np.array(features), np.array(labels)
    
    def train_models(self):
        """Train ML models with synthetic data"""
        # Generate synthetic training data
        X, y = self.generate_synthetic_training_data()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        X_train_scaled = self.feature_scaler.fit_transform(X_train)
        X_test_scaled = self.feature_scaler.transform(X_test)
        
        # Train malware classifier with better parameters
        self.malware_classifier = RandomForestClassifier(
            n_estimators=200, 
            random_state=42,
            max_depth=15,
            min_samples_split=10,
            min_samples_leaf=5,
            class_weight='balanced'  # Handle imbalanced dataset
        )
        self.malware_classifier.fit(X_train_scaled, y_train)
        
        # Train anomaly detector with less sensitivity
        self.anomaly_detector = IsolationForest(
            contamination=0.05,  # Reduced from 0.1 - less sensitive
            random_state=42,
            n_estimators=200
        )
        self.anomaly_detector.fit(X_train_scaled[y_train == 0])  # Train on legitimate apps only
        
        # Evaluate models
        y_pred = self.malware_classifier.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"✅ ML Model trained with {accuracy:.2%} accuracy")
        
        # Save models
        os.makedirs('models', exist_ok=True)
        joblib.dump(self.malware_classifier, 'models/malware_classifier.pkl')
        joblib.dump(self.anomaly_detector, 'models/anomaly_detector.pkl')
        joblib.dump(self.feature_scaler, 'models/feature_scaler.pkl')
    
    def extract_ml_features(self, apk_analysis: Dict) -> np.ndarray:
        """Extract features for ML models"""
        permissions = apk_analysis.get('Permissions', [])
        
        # Count different types of permissions
        suspicious_perms = ['SMS', 'CALL', 'CONTACTS', 'LOCATION', 'CAMERA', 'RECORD_AUDIO', 'ADMIN', 'SYSTEM_ALERT']
        network_perms = ['INTERNET', 'ACCESS_NETWORK_STATE', 'ACCESS_WIFI_STATE']
        admin_perms = ['DEVICE_ADMIN', 'BIND_DEVICE_ADMIN']
        
        suspicious_count = sum(1 for perm in permissions if any(sp in perm for sp in suspicious_perms))
        network_count = sum(1 for perm in permissions if any(np in perm for np in network_perms))
        admin_count = sum(1 for perm in permissions if any(ap in perm for ap in admin_perms))
        
        # Extract numerical features
        file_size_mb = float(apk_analysis.get('File Size', '0 MB').replace(' MB', ''))
        target_sdk = int(apk_analysis.get('Target SDK', 0) or 0)
        min_sdk = int(apk_analysis.get('Min SDK', 0) or 0)
        version_code = int(apk_analysis.get('Version Code', 1) or 1)
        has_certificate = 1 if apk_analysis.get('Certificate') else 0
        
        # Additional features from static analysis
        num_activities = apk_analysis.get('Activities', 0) or 0
        
        features = [
            len(permissions),           # num_permissions
            file_size_mb,              # file_size_mb
            target_sdk,                # target_sdk
            min_sdk,                   # min_sdk
            suspicious_count,          # suspicious_permissions
            has_certificate,           # has_certificate
            version_code,              # version_code
            network_count,             # network_permissions
            admin_count,               # admin_permissions
            num_activities,            # num_activities
        ]
        
        return np.array(features).reshape(1, -1)
    
    def predict_malware(self, features: np.ndarray) -> Tuple[int, float, bool]:
        """Predict if APK is malware using ML models"""
        features_scaled = self.feature_scaler.transform(features)
        
        # Malware classification
        malware_prob = self.malware_classifier.predict_proba(features_scaled)[0]
        is_malware = self.malware_classifier.predict(features_scaled)[0]
        malware_confidence = max(malware_prob)
        
        # Anomaly detection
        anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
        is_anomaly = self.anomaly_detector.predict(features_scaled)[0] == -1
        
        return is_malware, malware_confidence, is_anomaly
    
    def check_threat_intelligence(self, file_hash: str, package_name: str) -> Dict:
        """Check against threat intelligence sources"""
        threats = {
            'hash_reputation': 'clean',
            'package_reputation': 'unknown',
            'threat_score': 0,
            'sources': []
        }
        
        # Simulate VirusTotal-like API check
        known_malware_hashes = {
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': 'trojan.banker.android',
            '2cf24bf4b4ae48c5a54e64ac6ea7e5f7d0ec2a31e3e2d1a5b2b3c4d5e6f7g8h9': 'adware.android.generic'
        }
        
        if file_hash.lower() in known_malware_hashes:
            threats['hash_reputation'] = 'malicious'
            threats['threat_score'] += 8
            threats['sources'].append(f"Hash match: {known_malware_hashes[file_hash.lower()]}")
        
        # Check package reputation
        suspicious_packages = [
            'com.android.debug', 'com.example.', 'com.test.',
            'app.banking.fake', 'com.malware.'
        ]
        
        for suspicious in suspicious_packages:
            if suspicious in package_name.lower():
                threats['package_reputation'] = 'suspicious'
                threats['threat_score'] += 3
                threats['sources'].append(f"Suspicious package pattern: {suspicious}")
                break
        
        return threats
    
    def behavioral_analysis(self, apk_path: str) -> Dict:
        """Perform behavioral analysis on APK"""
        try:
            apk = APK(apk_path)
            
            # Extract DEX files for deeper analysis - Fixed for Androguard 4.1.3
            analysis_results = {
                'api_calls': [],
                'string_analysis': {},
                'crypto_usage': False,
                'obfuscation_detected': False,
                'suspicious_behaviors': []
            }
            
            # Analyze strings in APK using the new API
            strings = []
            try:
                # Get DEX files using the updated method
                for dex_name, dex_raw in apk.get_dex_names():
                    dex = DEX(dex_raw)
                    strings.extend(dex.get_strings())
            except Exception as e:
                # Fallback method if the above doesn't work
                try:
                    # Alternative method for getting strings
                    dex_files = apk.get_all_dex()
                    for dex_raw in dex_files:
                        dex = DEX(dex_raw)
                        strings.extend(dex.get_strings())
                except Exception as e2:
                    analysis_results['error'] = f"Could not extract strings: {str(e2)}"
                    strings = []  # Empty list as fallback
            
            # Look for suspicious strings
            suspicious_strings = [
                'bank', 'credit', 'password', 'pin', 'otp',
                'sms', 'call', 'contact', 'location',
                'root', 'su', 'busybox', 'superuser'
            ]
            
            string_matches = {}
            for s_string in suspicious_strings:
                matches = [s for s in strings if s_string.lower() in s.lower()]
                if matches:
                    string_matches[s_string] = len(matches)
            
            analysis_results['string_analysis'] = string_matches
            
            # Check for obfuscation
            obfuscated_indicators = ['a.a.a', 'o.o.o', 'l.l.l']
            for indicator in obfuscated_indicators:
                if any(indicator in s for s in strings[:100]):  # Check first 100 strings
                    analysis_results['obfuscation_detected'] = True
                    analysis_results['suspicious_behaviors'].append(f"Code obfuscation detected: {indicator}")
                    break
            
            # Check for crypto usage
            crypto_indicators = ['AES', 'DES', 'RSA', 'SHA', 'MD5', 'encrypt', 'decrypt']
            for crypto in crypto_indicators:
                if any(crypto.lower() in s.lower() for s in strings[:200]):
                    analysis_results['crypto_usage'] = True
                    break
            
            return analysis_results
            
        except Exception as e:
            return {'error': str(e)}

def advanced_analyze_apk(file_path: str) -> Dict[str, Any]:
    """Enhanced APK analysis with ML capabilities"""
    try:
        # Initialize ML analyzer
        ml_analyzer = MLSecurityAnalyzer()
        
        # Basic APK analysis
        apk = APK(file_path)
        
        # Extract metadata
        app_name = apk.get_app_name()
        package = apk.get_package()
        permissions = apk.get_permissions()
        activities = apk.get_activities()
        services = apk.get_services()
        receivers = apk.get_receivers()
        certificate = apk.get_signature_names()
        version_name = apk.get_androidversion_name()
        version_code = apk.get_androidversion_code()
        min_sdk = apk.get_min_sdk_version()
        target_sdk = apk.get_target_sdk_version()
        
        # File analysis
        file_size = os.path.getsize(file_path)
        file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
        
        # Basic analysis result
        basic_analysis = {
            "App Name": app_name or "Unknown",
            "Package": package or "Unknown",
            "Version Name": version_name or "Unknown",
            "Version Code": version_code or "Unknown",
            "Min SDK": min_sdk or "Unknown",
            "Target SDK": target_sdk or "Unknown",
            "File Size": f"{file_size / (1024*1024):.2f} MB",
            "SHA256 Hash": file_hash,
            "Permissions": permissions,
            "Activities": len(activities) if activities else 0,
            "Services": len(services) if services else 0,
            "Receivers": len(receivers) if receivers else 0,
            "Certificate": certificate
        }
        
        # ML-based analysis
        ml_features = ml_analyzer.extract_ml_features(basic_analysis)
        is_malware, confidence, is_anomaly = ml_analyzer.predict_malware(ml_features)
        
        # Threat intelligence check
        threat_intel = ml_analyzer.check_threat_intelligence(file_hash, package or "")
        
        # Behavioral analysis
        behavioral_analysis = ml_analyzer.behavioral_analysis(file_path)
        
        # Enhanced rule-based analysis with more realistic scoring
        suspicious_reasons = []
        risk_score = 0
        
        # Apply traditional rules (more balanced)
        legitimate_banks = {
            'sbi': ['com.sbi.SBIFreedomPlus', 'com.sbi.lotusintouch', 'com.onlinesbi'],
            'hdfc': ['com.snapwork.hdfc', 'com.hdfcbank.payzapp', 'com.hdfcbank'],
            'icici': ['com.icicibank.imobile', 'com.icicibank.pocketbanking', 'com.icicibank'],
            'axis': ['com.axis.mobile', 'com.axisbank.mobile', 'com.axis'],
            'kotak': ['com.msf.kbank.mobile', 'com.kotak.mobile', 'com.kotak'],
            'paytm': ['net.one97.paytm'],
            'phonepe': ['com.phonepe.app'],
            'googlepay': ['com.google.android.apps.nbu.paisa.user'],
            'amazon': ['in.amazon.mShop.android.shopping'],
            'flipkart': ['com.flipkart.android'],
            'whatsapp': ['com.whatsapp'],
            'facebook': ['com.facebook.katana'],
            'instagram': ['com.instagram.android'],
            'youtube': ['com.google.android.youtube'],
            'chrome': ['com.android.chrome'],
            'gmail': ['com.google.android.gm']
        }
        
        # More lenient package verification - only flag obvious fakes
        if app_name and package:
            app_lower = app_name.lower()
            package_lower = package.lower()
            
            # Only check banking apps specifically
            banking_keywords = ['bank', 'banking', 'netbanking', 'mobile banking']
            is_banking_app = any(keyword in app_lower for keyword in banking_keywords)
            
            if is_banking_app:
                is_legitimate_bank = False
                for bank, valid_packages in legitimate_banks.items():
                    if bank in app_lower:
                        if any(valid_pkg.lower() in package_lower for valid_pkg in valid_packages):
                            is_legitimate_bank = True
                            break
                
                # Only flag if it claims to be a bank but doesn't match known patterns
                if not is_legitimate_bank and any(bank in app_lower for bank in legitimate_banks.keys()):
                    suspicious_reasons.append(f"Potentially fake banking app: '{app_name}' with package '{package}'")
                    risk_score += 6  # High but not maximum score
        
        # ML predictions integration - more conservative
        if is_malware and confidence > 0.8:  # Only flag if highly confident
            suspicious_reasons.append(f"ML Model Detection: High confidence malware classification ({confidence:.2%})")
            risk_score += int(confidence * 4)  # Reduced impact
        elif is_malware and confidence > 0.6:
            suspicious_reasons.append(f"ML Model Detection: Possible malware (confidence: {confidence:.2%})")
            risk_score += 2
        
        if is_anomaly:
            suspicious_reasons.append("Anomaly Detection: Unusual app characteristics detected")
            risk_score += 2  # Reduced from 3
        
        # Threat intelligence integration
        if threat_intel['hash_reputation'] == 'malicious':
            suspicious_reasons.append("Hash found in malware database")
            risk_score += threat_intel['threat_score']
        
        threat_intel['sources'] = threat_intel.get('sources', [])
        for source in threat_intel['sources']:
            suspicious_reasons.append(f"Threat Intel: {source}")
        
        # Behavioral analysis integration
        if behavioral_analysis.get('obfuscation_detected'):
            suspicious_reasons.append("Code obfuscation detected - possible evasion technique")
            risk_score += 3
        
        if behavioral_analysis.get('string_analysis'):
            sensitive_strings = behavioral_analysis['string_analysis']
            high_risk_strings = ['bank', 'credit', 'password', 'pin', 'otp']
            for string_type, count in sensitive_strings.items():
                if string_type in high_risk_strings and count > 10:  # Increased threshold
                    suspicious_reasons.append(f"High frequency of sensitive strings: {string_type} ({count} occurrences)")
                    risk_score += 2
        
        # Permission analysis (more realistic)
        critical_perms = [
            "SEND_SMS", "WRITE_SMS", "READ_SMS",
            "DEVICE_ADMIN", "SYSTEM_ALERT_WINDOW"
        ]
        
        high_risk_perms = [
            "RECORD_AUDIO", "CAMERA", "CALL_PHONE",
            "READ_CONTACTS", "WRITE_CONTACTS",
            "ACCESS_FINE_LOCATION"
        ]
        
        critical_count = 0
        high_risk_count = 0
        
        for perm in permissions:
            for critical in critical_perms:
                if critical in perm:
                    critical_count += 1
                    break
            for high_risk in high_risk_perms:
                if high_risk in perm:
                    high_risk_count += 1
                    break
        
        if critical_count >= 2:
            suspicious_reasons.append(f"Multiple critical permissions: {critical_count} detected")
            risk_score += critical_count * 2
        
        if high_risk_count >= 4:  # Only flag if many sensitive permissions
            suspicious_reasons.append(f"Many sensitive permissions: {high_risk_count} detected")
            risk_score += 2
        
        # Certificate analysis - more lenient
        if not certificate:
            suspicious_reasons.append("App is not digitally signed")
            risk_score += 3  # Reduced from 4
        
        # File size analysis - more realistic thresholds
        file_size_mb = file_size / (1024 * 1024)
        if file_size_mb < 0.5:  # Very tiny apps are suspicious
            suspicious_reasons.append(f"Extremely small file size: {file_size_mb:.2f}MB")
            risk_score += 3
        elif file_size_mb > 500:  # Very large apps might be suspicious
            suspicious_reasons.append(f"Unusually large file size: {file_size_mb:.2f}MB")
            risk_score += 1
        
        # SDK version analysis - more lenient
        if target_sdk and int(target_sdk) < 19:  # Only flag very old SDKs
            suspicious_reasons.append(f"Very outdated target SDK: {target_sdk} (Android 4.4-)")
            risk_score += 3
        elif target_sdk and int(target_sdk) < 23:
            suspicious_reasons.append(f"Outdated target SDK: {target_sdk} (Android 6.0-)")
            risk_score += 1
        
        # More realistic verdict calculation
        if risk_score == 0:
            verdict = "SAFE ✅"
            risk_level = "LOW"
        elif risk_score <= 3:
            verdict = "LIKELY SAFE ✅"
            risk_level = "LOW"
        elif risk_score <= 6:
            verdict = "CAUTION ⚠️"
            risk_level = "MEDIUM"
        elif risk_score <= 10:
            verdict = "SUSPICIOUS ❌"
            risk_level = "HIGH"
        else:
            verdict = "DANGEROUS 🚨"
            risk_level = "CRITICAL"
        
        # Compile final result
        result = basic_analysis.copy()
        result.update({
            "Verdict": verdict,
            "Risk Level": risk_level,
            "Risk Score": min(risk_score, 10),  # Cap at 10
            "Reasons": suspicious_reasons,
            
            # ML Analysis Results
            "ML Predictions": {
                "Malware Probability": f"{confidence:.2%}" if is_malware else f"{1-confidence:.2%}",
                "Is Anomaly": is_anomaly,
                "Classification": "Malicious" if is_malware else "Legitimate"
            },
            
            # Threat Intelligence
            "Threat Intelligence": threat_intel,
            
            # Behavioral Analysis
            "Behavioral Analysis": behavioral_analysis,
            
            # Additional Metadata
            "Analysis Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Analyzer Version": "v3.0-ML"
        })
        
        return result
        
    except Exception as e:
        return {"Error": str(e), "Details": "Failed to analyze APK file"}

# Example usage and testing
if __name__ == "__main__":
    # Test the ML analyzer
    print("🤖 Initializing Advanced ML APK Security Analyzer...")
    analyzer = MLSecurityAnalyzer()
    print("✅ ML Analyzer ready!")
    
    # You can test with: result = advanced_analyze_apk("path/to/your/test.apk")