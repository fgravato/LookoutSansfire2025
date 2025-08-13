#!/usr/bin/env python3
"""
Lookout Mobile Risk API (MRA) Research Tool

A Python tool for researching mobile devices, threats, and vulnerabilities
using the Lookout MRA API without needing Postman or other tools.

Features:
- Device discovery and analysis
- Threat investigation
- Vulnerability assessment
- Event monitoring
- Interactive command-line interface
- Configuration file support

Author: Security Research Tool
"""

import requests
import json
import time
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlencode
import configparser


@dataclass
class APIConfig:
    """Configuration for Lookout MRA API"""
    base_url: str = "https://api.lookout.com"
    application_key: str = ""
    access_token: str = ""
    token_expires_at: int = 0


class LookoutMRAClient:
    """Client for interacting with Lookout Mobile Risk API"""
    
    def __init__(self, config: APIConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
    
    def authenticate(self) -> bool:
        """Authenticate with the API and get access token"""
        if self._is_token_valid():
            return True
            
        print("Authenticating with Lookout MRA API...")
        
        auth_url = f"{self.config.base_url}/oauth2/token"
        headers = {
            'Authorization': f'Bearer {self.config.application_key}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {'grant_type': 'client_credentials'}
        
        try:
            response = requests.post(auth_url, headers=headers, data=data)
            response.raise_for_status()
            
            token_data = response.json()
            self.config.access_token = token_data['access_token']
            self.config.token_expires_at = token_data['expires_at']
            
            self.session.headers['Authorization'] = f'Bearer {self.config.access_token}'
            print("✓ Authentication successful")
            return True
            
        except requests.exceptions.RequestException as e:
            print(f"✗ Authentication failed: {e}")
            return False
    
    def _is_token_valid(self) -> bool:
        """Check if current token is still valid"""
        if not self.config.access_token:
            return False
        
        current_time = int(time.time() * 1000)
        return current_time < (self.config.token_expires_at - 300000)  # 5 min buffer
    
    def _make_request(self, method: str, endpoint: str, params: Optional[Dict] = None, 
                     data: Optional[Dict] = None) -> Optional[Dict]:
        """Make authenticated API request"""
        if not self.authenticate():
            return None
        
        url = f"{self.config.base_url}{endpoint}"
        
        try:
            response = self.session.request(method, url, params=params, json=data)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            if response.status_code == 401:
                print("Token expired, re-authenticating...")
                self.config.access_token = ""
                return self._make_request(method, endpoint, params, data)
            else:
                print(f"API Error ({response.status_code}): {e}")
                try:
                    error_details = response.json()
                    print(f"Details: {error_details}")
                except:
                    pass
                return None
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None
    
    def get_devices(self, limit: int = 100, filters: Optional[Dict] = None) -> Optional[Dict]:
        """Get list of devices with optional filters"""
        params = {'limit': limit}
        if filters:
            params.update(filters)
        
        return self._make_request('GET', '/mra/api/v2/devices', params=params)
    
    def get_device_by_guid(self, guid: str, show_vulns: bool = True) -> Optional[Dict]:
        """Get specific device by GUID"""
        params = {'guid': guid, 'show_vulns': show_vulns}
        return self._make_request('GET', '/mra/api/v2/device', params=params)
    
    def get_threats(self, limit: int = 100, filters: Optional[Dict] = None) -> Optional[Dict]:
        """Get list of threats with optional filters"""
        params = {'limit': limit}
        if filters:
            params.update(filters)
        
        return self._make_request('GET', '/mra/api/v2/threats', params=params)
    
    def get_threat_by_guid(self, guid: str) -> Optional[Dict]:
        """Get specific threat by GUID"""
        params = {'guid': guid}
        return self._make_request('GET', '/mra/api/v2/threat', params=params)
    
    def get_pcp_threats(self, limit: int = 100, filters: Optional[Dict] = None) -> Optional[Dict]:
        """Get Phishing and Content Protection threats"""
        params = {'limit': limit}
        if filters:
            params.update(filters)
        
        return self._make_request('GET', '/mra/api/v2/pcp-threats', params=params)
    
    def get_android_vulns(self, aspl: str, severity: Optional[int] = None) -> Optional[Dict]:
        """Get Android vulnerabilities for Security Patch Level"""
        params = {'aspl': aspl}
        if severity is not None:
            params['severity'] = severity
        
        return self._make_request('GET', '/mra/api/v2/os-vulns/android', params=params)
    
    def get_ios_vulns(self, version: str, severity: Optional[int] = None) -> Optional[Dict]:
        """Get iOS vulnerabilities for version"""
        params = {'version': version}
        if severity is not None:
            params['severity'] = severity
        
        return self._make_request('GET', '/mra/api/v2/os-vulns/ios', params=params)
    
    def get_cve_info(self, cve_name: str) -> Optional[Dict]:
        """Get CVE information by name"""
        params = {'name': cve_name}
        return self._make_request('GET', '/mra/api/v2/os-vulns/cve', params=params)
    
    def get_devices_by_cve(self, cve_name: str) -> Optional[Dict]:
        """Get devices vulnerable to specific CVE"""
        params = {'name': cve_name}
        return self._make_request('GET', '/mra/api/v2/os-vulns/devices', params=params)
    
    def get_os_versions(self) -> Optional[Dict]:
        """Get distinct OS versions in the fleet"""
        return self._make_request('GET', '/mra/api/v2/os-vulns/os-versions')
    
    def get_events(self, limit: int = 100, filters: Optional[Dict] = None) -> Optional[Dict]:
        """Get events (polling mode)"""
        params = {'limit': limit}
        if filters:
            params.update(filters)
        
        return self._make_request('GET', '/mra/api/v2/events', params=params)
    
    def get_smishing_alerts(self, limit: int = 100, filters: Optional[Dict] = None) -> Optional[Dict]:
        """Get smishing alerts"""
        params = {'limit': limit}
        if filters:
            params.update(filters)
        
        return self._make_request('GET', '/mra/api/v2/smishing-alerts', params=params)


class LookoutMRAResearchTool:
    """Interactive research tool for Lookout MRA"""
    
    def __init__(self):
        self.config = APIConfig()
        self.client = None
        self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        config_file = 'lookout_config.ini'
        
        if os.path.exists(config_file):
            config = configparser.ConfigParser()
            config.read(config_file)
            
            if 'lookout' in config:
                self.config.application_key = config['lookout'].get('application_key', '')
                self.config.base_url = config['lookout'].get('base_url', self.config.base_url)
        else:
            self.create_default_config(config_file)
    
    def create_default_config(self, config_file: str):
        """Create default configuration file"""
        config = configparser.ConfigParser()
        config['lookout'] = {
            'application_key': 'YOUR_APPLICATION_KEY_HERE',
            'base_url': 'https://api.lookout.com'
        }
        
        with open(config_file, 'w') as f:
            config.write(f)
        
        print(f"Created default config file: {config_file}")
        print("Please edit the file and add your Lookout application key.")
    
    def setup_client(self) -> bool:
        """Initialize and authenticate client"""
        if not self.config.application_key or self.config.application_key == 'YOUR_APPLICATION_KEY_HERE':
            print("Please configure your Lookout application key in lookout_config.ini")
            return False
        
        self.client = LookoutMRAClient(self.config)
        return self.client.authenticate()
    
    def print_banner(self):
        """Print tool banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    Lookout MRA Research Tool                 ║
║                                                              ║
║  A Python tool for mobile device security research using    ║
║  the Lookout Mobile Risk API (MRA)                          ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def print_menu(self):
        """Print main menu"""
        menu = """
┌─────────────────────────────────────────────────────────────┐
│                        MAIN MENU                            │
├─────────────────────────────────────────────────────────────┤
│ Device Research:                                            │
│   1. List Devices                                           │
│   2. Device Details by GUID                                 │
│   3. Search Devices by Filters                             │
│                                                             │
│ Threat Research:                                            │
│   4. List Threats                                           │
│   5. Threat Details by GUID                                 │
│   6. PCP (Phishing/Content) Threats                        │
│                                                             │
│ Vulnerability Research:                                     │
│   7. Android Vulnerabilities                               │
│   8. iOS Vulnerabilities                                    │
│   9. CVE Information                                        │
│  10. Devices Affected by CVE                               │
│  11. Fleet OS Versions                                      │
│                                                             │
│ Monitoring:                                                 │
│  12. Recent Events                                          │
│  13. Smishing Alerts                                        │
│                                                             │
│ Utilities:                                                  │
│  14. Export Results to JSON                                 │
│  15. Configuration                                          │
│                                                             │
│   0. Exit                                                   │
└─────────────────────────────────────────────────────────────┘
        """
        print(menu)
    
    def format_device_summary(self, device: Dict) -> str:
        """Format device information for display"""
        return f"""
┌─ Device Summary ─────────────────────────────────────────────┐
│ GUID: {device.get('guid', 'N/A')}
│ Email: {device.get('email', 'N/A')}
│ Platform: {device.get('platform', 'N/A')}
│ Security Status: {device.get('security_status', 'N/A')}
│ Protection Status: {device.get('protection_status', 'N/A')}
│ Last Checkin: {device.get('checkin_time', 'N/A')}
│ OS Version: {device.get('software', {}).get('os_version', 'N/A')}
│ Profile Type: {device.get('profile_type', 'N/A')}
└─────────────────────────────────────────────────────────────┘"""
    
    def format_threat_summary(self, threat: Dict) -> str:
        """Format threat information for display"""
        return f"""
┌─ Threat Summary ─────────────────────────────────────────────┐
│ GUID: {threat.get('guid', 'N/A')}
│ Classification: {threat.get('assessment', {}).get('classification', 'N/A')}
│ Risk: {threat.get('assessment', {}).get('risk', 'N/A')}
│ Status: {threat.get('status', 'N/A')}
│ Device GUID: {threat.get('device', {}).get('guid', 'N/A')}
│ Detected: {threat.get('detected_at', 'N/A')}
│ Threat Type: {threat.get('threat_type', 'N/A')}
└─────────────────────────────────────────────────────────────┘"""
    
    def format_json_pretty(self, data: Any) -> str:
        """Format JSON data for pretty printing"""
        return json.dumps(data, indent=2, sort_keys=True)
    
    def extract_fields(self, data: Dict, fields: List[str]) -> Dict:
        """Extract specific fields from nested dictionary"""
        result = {}
        for field in fields:
            keys = field.split('.')
            value = data
            try:
                for key in keys:
                    value = value[key]
                result[field] = value
            except (KeyError, TypeError):
                result[field] = None
        return result
    
    def list_devices(self):
        """List devices with optional filtering"""
        print("\n=== Device Listing ===")
        
        # Get filter options
        print("\nFiltering Options (press Enter to skip):")
        platform = input("Platform (ANDROID/IOS): ").strip().upper() or None
        security_status = input("Security Status (SECURE/THREATS_LOW/THREATS_MEDIUM/THREATS_HIGH): ").strip().upper() or None
        protection_status = input("Protection Status (PROTECTED/DISCONNECTED): ").strip().upper() or None
        limit = input("Limit (default 50): ").strip() or "50"
        
        filters = {}
        if platform: filters['platform'] = platform
        if security_status: filters['security_status'] = security_status
        if protection_status: filters['protection_status'] = protection_status
        
        print(f"\nFetching devices with filters: {filters}")
        
        result = self.client.get_devices(limit=int(limit), filters=filters)
        if not result:
            print("Failed to retrieve devices")
            return
        
        devices = result.get('devices', [])
        total_count = result.get('count', 0)
        
        print(f"\nFound {len(devices)} devices (Total: {total_count})")
        print("=" * 80)
        
        for i, device in enumerate(devices, 1):
            print(f"{i}. {self.format_device_summary(device)}")
        
        # Option to export or get details
        if devices:
            choice = input(f"\nOptions: (d)etails, (e)xport, (Enter) to continue: ").strip().lower()
            if choice == 'd':
                try:
                    idx = int(input(f"Enter device number (1-{len(devices)}): ")) - 1
                    if 0 <= idx < len(devices):
                        self.show_device_details(devices[idx]['guid'])
                except (ValueError, IndexError):
                    print("Invalid selection")
            elif choice == 'e':
                self.save_to_file(devices, "devices_export")
    
    def device_details(self):
        """Get detailed device information by GUID"""
        print("\n=== Device Details ===")
        guid = input("Enter device GUID: ").strip()
        
        if not guid:
            print("GUID is required")
            return
        
        self.show_device_details(guid)
    
    def show_device_details(self, guid: str):
        """Show detailed device information"""
        print(f"\nFetching details for device: {guid}")
        
        result = self.client.get_device_by_guid(guid, show_vulns=True)
        if not result:
            print("Failed to retrieve device details")
            return
        
        print("\n" + "=" * 80)
        print("DEVICE DETAILED INFORMATION")
        print("=" * 80)
        
        # Basic info
        print(f"GUID: {result.get('guid')}")
        print(f"Email: {result.get('email')}")
        print(f"Platform: {result.get('platform')}")
        print(f"Profile Type: {result.get('profile_type')}")
        print(f"Security Status: {result.get('security_status')}")
        print(f"Protection Status: {result.get('protection_status')}")
        print(f"Activation Status: {result.get('activation_status')}")
        
        # Hardware info
        if 'hardware' in result:
            hw = result['hardware']
            print(f"\nHardware:")
            print(f"  Model: {hw.get('model')}")
            print(f"  Manufacturer: {hw.get('manufacturer')}")
        
        # Software info
        if 'software' in result:
            sw = result['software']
            print(f"\nSoftware:")
            print(f"  OS Version: {sw.get('os_version')}")
            print(f"  Security Patch Level: {sw.get('aspl')}")
        
        # Vulnerabilities
        if 'device_vulns' in result and result['device_vulns']:
            vulns = result['device_vulns'].get('vulnerabilities', [])
            if vulns:
                print(f"\nVulnerabilities ({len(vulns)}):")
                for vuln in vulns[:10]:  # Show first 10
                    print(f"  - {vuln.get('name')} (Severity: {vuln.get('severity')})")
                if len(vulns) > 10:
                    print(f"  ... and {len(vulns) - 10} more")
        
        # Export option
        choice = input("\nExport full details to JSON? (y/N): ").strip().lower()
        if choice == 'y':
            self.save_to_file(result, f"device_{guid}_details")
    
    def search_devices(self):
        """Advanced device search with multiple criteria"""
        print("\n=== Advanced Device Search ===")
        
        print("\nAvailable filters:")
        filters = {}
        
        # Platform
        platform = input("Platform (ANDROID/IOS): ").strip().upper()
        if platform: filters['platform'] = platform
        
        # Security status with negation support
        sec_status = input("Security Status (SECURE/THREATS_LOW/THREATS_MEDIUM/THREATS_HIGH, use ! for NOT): ").strip()
        if sec_status: filters['security_status'] = sec_status
        
        # Email search (partial match)
        email = input("Email (partial match): ").strip()
        if email: filters['email'] = email
        
        # OS version age
        os_age = input("OS Version Age in months (3/6/9/12/18/24): ").strip()
        if os_age and os_age in ['3', '6', '9', '12', '18', '24']:
            filters['os_version_date'] = int(os_age)
        
        # Group
        group_guid = input("Device Group GUID: ").strip()
        if group_guid: filters['group'] = group_guid
        
        # MDM status
        is_mdm = input("MDM Managed (true/false): ").strip().lower()
        if is_mdm in ['true', 'false']:
            filters['is_mdm'] = is_mdm == 'true'
        
        limit = input("Result limit (default 100): ").strip() or "100"
        
        print(f"\nSearching with filters: {filters}")
        
        result = self.client.get_devices(limit=int(limit), filters=filters)
        if not result:
            print("Search failed")
            return
        
        devices = result.get('devices', [])
        
        print(f"\nSearch Results: {len(devices)} devices found")
        print("=" * 80)
        
        for i, device in enumerate(devices, 1):
            print(f"{i}. {self.format_device_summary(device)}")
        
        if devices:
            self.post_search_options(devices, "devices")
    
    def list_threats(self):
        """List threats with filtering"""
        print("\n=== Threat Listing ===")
        
        print("\nFiltering Options (press Enter to skip):")
        risk = input("Risk Level (HIGH/MEDIUM/LOW/ADVISORY/NONE): ").strip().upper() or None
        classification = input("Classification (e.g., MALWARE, RISKWARE): ").strip().upper() or None
        status = input("Status (OPEN/RESOLVED/IGNORED): ").strip().upper() or None
        platform = input("Platform (ANDROID/IOS): ").strip().upper() or None
        device_guid = input("Device GUID: ").strip() or None
        limit = input("Limit (default 50): ").strip() or "50"
        
        filters = {}
        if risk: filters['risk'] = risk
        if classification: filters['classification'] = classification
        if status: filters['status'] = status
        if platform: filters['platform'] = platform
        if device_guid: filters['device_guid'] = device_guid
        
        print(f"\nFetching threats with filters: {filters}")
        
        result = self.client.get_threats(limit=int(limit), filters=filters)
        if not result:
            print("Failed to retrieve threats")
            return
        
        threats = result.get('threats', [])
        total_count = result.get('count', 0)
        
        print(f"\nFound {len(threats)} threats (Total: {total_count})")
        print("=" * 80)
        
        for i, threat in enumerate(threats, 1):
            print(f"{i}. {self.format_threat_summary(threat)}")
        
        if threats:
            self.post_search_options(threats, "threats")
    
    def threat_details(self):
        """Get detailed threat information by GUID"""
        print("\n=== Threat Details ===")
        guid = input("Enter threat GUID: ").strip()
        
        if not guid:
            print("GUID is required")
            return
        
        result = self.client.get_threat_by_guid(guid)
        if not result:
            print("Failed to retrieve threat details")
            return
        
        print("\n" + "=" * 80)
        print("THREAT DETAILED INFORMATION")
        print("=" * 80)
        print(self.format_json_pretty(result))
        
        choice = input("\nExport to JSON? (y/N): ").strip().lower()
        if choice == 'y':
            self.save_to_file(result, f"threat_{guid}_details")
    
    def pcp_threats(self):
        """List Phishing and Content Protection threats"""
        print("\n=== PCP Threats (Phishing & Content Protection) ===")
        
        print("\nFiltering Options (press Enter to skip):")
        classification = input("Classification (MALICIOUS_CONTENT/UNAUTHORIZED_CONTENT/PHISHING_CONTENT/DENYLISTED_CONTENT): ").strip().upper() or None
        risk = input("Risk Level (HIGH/MEDIUM/LOW/ADVISORY/NONE): ").strip().upper() or None
        device_guid = input("Device GUID: ").strip() or None
        limit = input("Limit (default 50): ").strip() or "50"
        
        filters = {}
        if classification: filters['classification'] = classification
        if risk: filters['risk'] = risk
        if device_guid: filters['device_guid'] = device_guid
        
        result = self.client.get_pcp_threats(limit=int(limit), filters=filters)
        if not result:
            print("Failed to retrieve PCP threats")
            return
        
        threats = result.get('threats', [])
        
        print(f"\nFound {len(threats)} PCP threats")
        print("=" * 80)
        
        for i, threat in enumerate(threats, 1):
            print(f"{i}. {self.format_threat_summary(threat)}")
            if 'details' in threat and threat['details'].get('url'):
                print(f"    URL: {threat['details']['url']}")
        
        if threats:
            self.post_search_options(threats, "pcp_threats")
    
    def android_vulnerabilities(self):
        """Get Android vulnerabilities for specific ASPL"""
        print("\n=== Android Vulnerabilities ===")
        
        aspl = input("Enter Android Security Patch Level (e.g., 2023-12-01): ").strip()
        if not aspl:
            print("ASPL is required")
            return
        
        severity = input("Minimum severity (0-10, press Enter for all): ").strip()
        severity = int(severity) if severity.isdigit() else None
        
        result = self.client.get_android_vulns(aspl, severity)
        if not result:
            print("Failed to retrieve vulnerabilities")
            return
        
        vulns = result.get('vulnerabilities', [])
        
        print(f"\nAndroid vulnerabilities for ASPL {aspl}")
        if severity: print(f"Minimum severity: {severity}")
        print(f"Found: {len(vulns)} vulnerabilities")
        print("=" * 80)
        
        for i, vuln in enumerate(vulns, 1):
            print(f"{i}. CVE: {vuln.get('name')} | Severity: {vuln.get('severity')} | CVSS: {vuln.get('cvss_score')}")
            if vuln.get('description'):
                print(f"   Description: {vuln['description'][:100]}...")
        
        if vulns:
            self.post_search_options(vulns, f"android_vulns_{aspl}")
    
    def ios_vulnerabilities(self):
        """Get iOS vulnerabilities for specific version"""
        print("\n=== iOS Vulnerabilities ===")
        
        version = input("Enter iOS version (e.g., 17.0.1): ").strip()
        if not version:
            print("Version is required")
            return
        
        severity = input("Minimum severity (0-10, press Enter for all): ").strip()
        severity = int(severity) if severity.isdigit() else None
        
        result = self.client.get_ios_vulns(version, severity)
        if not result:
            print("Failed to retrieve vulnerabilities")
            return
        
        vulns = result.get('vulnerabilities', [])
        
        print(f"\niOS vulnerabilities for version {version}")
        if severity: print(f"Minimum severity: {severity}")
        print(f"Found: {len(vulns)} vulnerabilities")
        print("=" * 80)
        
        for i, vuln in enumerate(vulns, 1):
            print(f"{i}. CVE: {vuln.get('name')} | Severity: {vuln.get('severity')} | CVSS: {vuln.get('cvss_score')}")
            if vuln.get('description'):
                print(f"   Description: {vuln['description'][:100]}...")
        
        if vulns:
            self.post_search_options(vulns, f"ios_vulns_{version}")
    
    def cve_information(self):
        """Get detailed CVE information"""
        print("\n=== CVE Information Lookup ===")
        
        cve_name = input("Enter CVE name (e.g., CVE-2023-1234): ").strip()
        if not cve_name:
            print("CVE name is required")
            return
        
        result = self.client.get_cve_info(cve_name)
        if not result:
            print("Failed to retrieve CVE information")
            return
        
        print(f"\nCVE Information: {cve_name}")
        print("=" * 80)
        print(self.format_json_pretty(result))
        
        choice = input("\nExport to JSON? (y/N): ").strip().lower()
        if choice == 'y':
            self.save_to_file(result, f"cve_{cve_name.replace('-', '_')}")
    
    def devices_by_cve(self):
        """Find devices affected by specific CVE"""
        print("\n=== Devices Affected by CVE ===")
        
        cve_name = input("Enter CVE name (e.g., CVE-2023-1234): ").strip()
        if not cve_name:
            print("CVE name is required")
            return
        
        result = self.client.get_devices_by_cve(cve_name)
        if not result:
            print("Failed to retrieve affected devices")
            return
        
        devices = result.get('devices', [])
        
        print(f"\nDevices affected by {cve_name}")
        print(f"Found: {len(devices)} devices")
        print("=" * 80)
        
        for i, device in enumerate(devices, 1):
            print(f"{i}. {self.format_device_summary(device)}")
        
        if devices:
            self.post_search_options(devices, f"devices_cve_{cve_name.replace('-', '_')}")
    
    def fleet_os_versions(self):
        """Get OS versions present in fleet"""
        print("\n=== Fleet OS Versions ===")
        
        result = self.client.get_os_versions()
        if not result:
            print("Failed to retrieve OS versions")
            return
        
        android_versions = result.get('android_versions', [])
        ios_versions = result.get('ios_versions', [])
        
        print("\nAndroid Versions in Fleet:")
        print("-" * 40)
        for version in android_versions:
            print(f"  Version: {version.get('version')} | ASPL: {version.get('patch_level')} | Count: {version.get('count', 'N/A')}")
        
        print("\niOS Versions in Fleet:")
        print("-" * 40)
        for version in ios_versions:
            print(f"  Version: {version.get('version')} | Count: {version.get('count', 'N/A')}")
        
        choice = input("\nExport to JSON? (y/N): ").strip().lower()
        if choice == 'y':
            self.save_to_file(result, "fleet_os_versions")
    
    def recent_events(self):
        """Get recent events"""
        print("\n=== Recent Events ===")
        
        print("\nEvent Types (comma-separated or Enter for all):")
        print("DEVICE, THREAT, AUDIT, SMISHING_ALERT")
        event_types = input("Types: ").strip() or None
        
        limit = input("Limit (default 50): ").strip() or "50"
        
        filters = {}
        if event_types: filters['types'] = event_types
        
        result = self.client.get_events(limit=int(limit), filters=filters)
        if not result:
            print("Failed to retrieve events")
            return
        
        events = result.get('events', [])
        last_oid = result.get('last_oid')
        
        print(f"\nRecent Events: {len(events)} events")
        print(f"Last OID: {last_oid}")
        print("=" * 80)
        
        for i, event in enumerate(events, 1):
            event_type = event.get('type', 'UNKNOWN')
            timestamp = event.get('timestamp', 'N/A')
            print(f"{i}. [{event_type}] {timestamp}")
            
            if event_type == 'DEVICE' and 'device_change' in event:
                device = event['device_change']
                print(f"   Device: {device.get('guid')} ({device.get('platform')})")
            elif event_type == 'THREAT' and 'threat' in event:
                threat = event['threat']
                print(f"   Threat: {threat.get('assessment', {}).get('classification')} | Risk: {threat.get('assessment', {}).get('risk')}")
            elif event_type == 'AUDIT' and 'audit' in event:
                audit = event['audit']
                print(f"   Audit: {audit.get('type')}")
        
        if events:
            self.post_search_options(events, "recent_events")
    
    def smishing_alerts(self):
        """Get smishing alerts"""
        print("\n=== Smishing Alerts ===")
        
        print("\nFiltering Options (press Enter to skip):")
        alert_type = input("Alert Type (URL_DETECTION/FRAUD_DETECTION): ").strip().upper() or None
        device_guid = input("Device GUID: ").strip() or None
        limit = input("Limit (default 50): ").strip() or "50"
        
        filters = {}
        if alert_type: filters['alert_type'] = alert_type
        if device_guid: filters['device_guid'] = device_guid
        
        result = self.client.get_smishing_alerts(limit=int(limit), filters=filters)
        if not result:
            print("Failed to retrieve smishing alerts")
            return
        
        alerts = result.get('smishing_alerts', [])
        
        print(f"\nSmishing Alerts: {len(alerts)} alerts")
        print("=" * 80)
        
        for i, alert in enumerate(alerts, 1):
            print(f"{i}. Alert GUID: {alert.get('guid')}")
            print(f"   Type: {alert.get('detection', {}).get('alert_type')}")
            print(f"   Category: {alert.get('detection', {}).get('category')}")
            print(f"   Device: {alert.get('device_guid')}")
            print(f"   Created: {alert.get('created_at')}")
            if alert.get('detection', {}).get('original_url'):
                print(f"   URL: {alert['detection']['original_url']}")
            print()
        
        if alerts:
            self.post_search_options(alerts, "smishing_alerts")
    
    def post_search_options(self, data: List[Dict], data_type: str):
        """Common post-search options"""
        while True:
            print(f"\nPost-Search Options for {len(data)} {data_type}:")
            print("1. Export all to JSON")
            print("2. Export selected fields to CSV")
            print("3. Filter results further")
            print("4. Show detailed view")
            print("0. Back to main menu")
            
            choice = input("Select option: ").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                self.save_to_file(data, f"{data_type}_export")
                break
            elif choice == '2':
                self.export_to_csv(data, data_type)
                break
            elif choice == '3':
                self.filter_results(data, data_type)
            elif choice == '4':
                self.show_detailed_view(data, data_type)
            else:
                print("Invalid option")
    
    def export_to_csv(self, data: List[Dict], data_type: str):
        """Export data to CSV with field selection"""
        if not data:
            print("No data to export")
            return
        
        print("\nAvailable fields (sample from first record):")
        sample_fields = self.get_all_keys(data[0], prefix="")
        for i, field in enumerate(sample_fields[:20], 1):  # Show first 20 fields
            print(f"{i:2d}. {field}")
        if len(sample_fields) > 20:
            print(f"... and {len(sample_fields) - 20} more fields")
        
        print("\nEnter field numbers to export (e.g., 1,2,5-8) or 'all' for all fields:")
        selection = input("Selection: ").strip()
        
        if selection.lower() == 'all':
            selected_fields = sample_fields
        else:
            selected_fields = self.parse_field_selection(selection, sample_fields)
        
        if not selected_fields:
            print("No valid fields selected")
            return
        
        # Extract data for selected fields
        csv_data = []
        for item in data:
            row = {}
            for field in selected_fields:
                row[field] = self.get_nested_value(item, field)
            csv_data.append(row)
        
        filename = f"{data_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        try:
            import csv
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=selected_fields)
                writer.writeheader()
                writer.writerows(csv_data)
            
            print(f"✓ Data exported to {filename}")
        except Exception as e:
            print(f"✗ Export failed: {e}")
    
    def get_all_keys(self, obj, prefix=""):
        """Recursively get all keys from nested dictionary"""
        keys = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_key = f"{prefix}.{key}" if prefix else key
                keys.append(full_key)
                if isinstance(value, dict):
                    keys.extend(self.get_all_keys(value, full_key))
                elif isinstance(value, list) and value and isinstance(value[0], dict):
                    keys.extend(self.get_all_keys(value[0], f"{full_key}[0]"))
        return keys
    
    def get_nested_value(self, obj, key_path):
        """Get value from nested dictionary using dot notation"""
        keys = key_path.split('.')
        value = obj
        try:
            for key in keys:
                if '[' in key and ']' in key:  # Handle array indexing
                    key, index = key.split('[')
                    index = int(index.replace(']', ''))
                    value = value[key][index]
                else:
                    value = value[key]
            return str(value) if value is not None else ""
        except (KeyError, IndexError, TypeError):
            return ""
    
    def parse_field_selection(self, selection: str, available_fields: List[str]) -> List[str]:
        """Parse field selection string"""
        selected = []
        parts = selection.split(',')
        
        for part in parts:
            part = part.strip()
            if '-' in part:  # Range selection
                try:
                    start, end = map(int, part.split('-'))
                    for i in range(start, min(end + 1, len(available_fields) + 1)):
                        if 1 <= i <= len(available_fields):
                            selected.append(available_fields[i - 1])
                except ValueError:
                    continue
            else:  # Single selection
                try:
                    i = int(part)
                    if 1 <= i <= len(available_fields):
                        selected.append(available_fields[i - 1])
                except ValueError:
                    continue
        
        return list(dict.fromkeys(selected))  # Remove duplicates while preserving order
    
    def filter_results(self, data: List[Dict], data_type: str):
        """Interactive result filtering"""
        print(f"\n=== Filter {len(data)} {data_type} ===")
        
        print("Enter filter criteria (field_path operator value):")
        print("Operators: ==, !=, >, <, >=, <=, contains, startswith, endswith")
        print("Examples:")
        print("  platform == ANDROID")
        print("  assessment.risk != LOW")
        print("  software.os_version contains 14")
        print("  email startswith admin")
        print()
        
        filter_expr = input("Filter expression: ").strip()
        if not filter_expr:
            return
        
        try:
            filtered_data = self.apply_filter(data, filter_expr)
            print(f"\nFiltered to {len(filtered_data)} results")
            
            if filtered_data:
                self.post_search_options(filtered_data, f"filtered_{data_type}")
            else:
                print("No results match the filter criteria")
        
        except Exception as e:
            print(f"Filter error: {e}")
    
    def apply_filter(self, data: List[Dict], filter_expr: str) -> List[Dict]:
        """Apply filter expression to data"""
        parts = filter_expr.split()
        if len(parts) != 3:
            raise ValueError("Filter must be: field operator value")
        
        field, operator, value = parts
        
        # Convert value to appropriate type
        if value.lower() in ['true', 'false']:
            value = value.lower() == 'true'
        elif value.isdigit():
            value = int(value)
        elif value.replace('.', '').isdigit():
            value = float(value)
        
        filtered = []
        for item in data:
            item_value = self.get_nested_value(item, field)
            
            # Convert for comparison
            if isinstance(value, (int, float)) and item_value.replace('.', '').isdigit():
                item_value = float(item_value) if '.' in item_value else int(item_value)
            elif isinstance(value, bool):
                item_value = str(item_value).lower() == 'true'
            
            # Apply operator
            try:
                if operator == '==' and item_value == value:
                    filtered.append(item)
                elif operator == '!=' and item_value != value:
                    filtered.append(item)
                elif operator == '>' and item_value > value:
                    filtered.append(item)
                elif operator == '<' and item_value < value:
                    filtered.append(item)
                elif operator == '>=' and item_value >= value:
                    filtered.append(item)
                elif operator == '<=' and item_value <= value:
                    filtered.append(item)
                elif operator == 'contains' and str(value).lower() in str(item_value).lower():
                    filtered.append(item)
                elif operator == 'startswith' and str(item_value).lower().startswith(str(value).lower()):
                    filtered.append(item)
                elif operator == 'endswith' and str(item_value).lower().endswith(str(value).lower()):
                    filtered.append(item)
            except (TypeError, ValueError):
                continue
        
        return filtered
    
    def show_detailed_view(self, data: List[Dict], data_type: str):
        """Show detailed view of selected items"""
        if not data:
            print("No data to show")
            return
        
        print(f"\nDetailed View - Select items to examine:")
        for i, item in enumerate(data[:20], 1):  # Show first 20
            if data_type == 'devices':
                print(f"{i:2d}. {item.get('email', 'N/A')} ({item.get('platform', 'N/A')})")
            elif 'threat' in data_type:
                print(f"{i:2d}. {item.get('assessment', {}).get('classification', 'N/A')} - Risk: {item.get('assessment', {}).get('risk', 'N/A')}")
            else:
                print(f"{i:2d}. {item.get('guid', item.get('name', 'N/A'))}")
        
        if len(data) > 20:
            print(f"... and {len(data) - 20} more items")
        
        selection = input(f"\nSelect item numbers (1-{min(len(data), 20)}): ").strip()
        
        try:
            indices = [int(x.strip()) - 1 for x in selection.split(',')]
            for idx in indices:
                if 0 <= idx < min(len(data), 20):
                    print(f"\n{'='*80}")
                    print(f"DETAILED VIEW - Item {idx + 1}")
                    print('='*80)
                    print(self.format_json_pretty(data[idx]))
        except (ValueError, IndexError):
            print("Invalid selection")
    
    def save_to_file(self, data: Any, filename_prefix: str):
        """Save data to JSON file"""
        filename = f"{filename_prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            
            print(f"✓ Data saved to {filename}")
        except Exception as e:
            print(f"✗ Save failed: {e}")
    
    def export_results(self):
        """Export menu placeholder"""
        print("Export functionality is integrated into each search function")
    
    def configuration_menu(self):
        """Configuration management"""
        print("\n=== Configuration ===")
        print(f"Base URL: {self.config.base_url}")
        print(f"Application Key: {'*' * 20 if self.config.application_key else 'Not configured'}")
        print(f"Token Status: {'Valid' if self._is_token_valid() else 'Invalid/Expired'}")
        
        print("\nOptions:")
        print("1. Update Application Key")
        print("2. Update Base URL")
        print("3. Test Connection")
        print("0. Back")
        
        choice = input("Select option: ").strip()
        
        if choice == '1':
            new_key = input("Enter new application key: ").strip()
            if new_key:
                self.config.application_key = new_key
                self.config.access_token = ""  # Force re-auth
                print("Application key updated")
        elif choice == '2':
            new_url = input(f"Enter new base URL (current: {self.config.base_url}): ").strip()
            if new_url:
                self.config.base_url = new_url
                print("Base URL updated")
        elif choice == '3':
            if self.client.authenticate():
                print("✓ Connection successful")
            else:
                print("✗ Connection failed")
    
    def _is_token_valid(self) -> bool:
        """Check if token is valid (delegate to client)"""
        return self.client._is_token_valid() if self.client else False
    
    def run(self):
        """Run the interactive tool"""
        self.print_banner()
        
        if not self.setup_client():
            print("Failed to initialize. Exiting.")
            return
        
        while True:
            self.print_menu()
            
            try:
                choice = input("\nSelect an option (0-15): ").strip()
                
                if choice == '0':
                    print("Goodbye!")
                    break
                elif choice == '1':
                    self.list_devices()
                elif choice == '2':
                    self.device_details()
                elif choice == '3':
                    self.search_devices()
                elif choice == '4':
                    self.list_threats()
                elif choice == '5':
                    self.threat_details()
                elif choice == '6':
                    self.pcp_threats()
                elif choice == '7':
                    self.android_vulnerabilities()
                elif choice == '8':
                    self.ios_vulnerabilities()
                elif choice == '9':
                    self.cve_information()
                elif choice == '10':
                    self.devices_by_cve()
                elif choice == '11':
                    self.fleet_os_versions()
                elif choice == '12':
                    self.recent_events()
                elif choice == '13':
                    self.smishing_alerts()
                elif choice == '14':
                    self.export_results()
                elif choice == '15':
                    self.configuration_menu()
                else:
                    print("Invalid option. Please try again.")
                
                input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                print("\n\nGoodbye!")
                break
            except Exception as e:
                print(f"Error: {e}")
                input("\nPress Enter to continue...")


if __name__ == "__main__":
    tool = LookoutMRAResearchTool()
    tool.run()