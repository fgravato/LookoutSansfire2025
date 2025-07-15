#!/usr/bin/env python3
"""
Enhanced Lookout Mobile Risk API Device Inspector

A comprehensive command-line tool to retrieve device information, including operating system details,
device type, CVEs, and threats from the Lookout Mobile Risk API. This enhanced version queries both
the device endpoint and the threats API to ensure all threats are properly reported.

Usage:
    python enhanced_device_inspector.py [options]

Examples:
    python enhanced_device_inspector.py --customer-device-id "device123"
    python enhanced_device_inspector.py --guid "550e8400-e29b-41d4-a716-446655440000"
    python enhanced_device_inspector.py --mdm-device-id "mdm123" --format json
    python enhanced_device_inspector.py --customer-device-id "device123" --no-vulns
"""

import argparse
import datetime
import json
import logging
import sys
from typing import Dict, Optional, Any, List
import requests
from urllib.parse import urljoin

# Default application key from file - can be overridden with --api-key flag
DEFAULT_API_KEY = "eyJraWQiOiIxODoxNjo3NzoyMjo2Mzo0YjpmZjoyMzoxOTpmMTpjZjozYTpjYjphZTozODo0NDo5NjpmYTozNDpjMDpjMTo5Zjo2Njo0ZDowZjo2Zjo2ODpjNzpmZDowNDpkOTo0MiIsImN0eSI6IkpXUyIsImVuYyI6IkExMjhHQ00iLCJhbGciOiJSU0EtT0FFUC0yNTYifQ.hYy4pmkMFbg2n92-RUZUS_8z6P2Mm1WmNyNrX71cdnvb7btqQCL8aMKKU3XN6SYWHbfyR_FeEX9Dt1NLiufKqnB_i3FNBfzAUVc0ku-3rRv77Em4kPG6WadGWRwyolZq67GTn6At0T6mPf23MiM0scjSeyBv_HpSHMicX8eABABblraidsAiLszGgMQj6ARSbA0Og4argi7AbYcdQ76Ln7ULOCMrH0DTzuXzLFMa8Vrpct3j9z7_diLHPEoKQ4yc9TIy35jVfmC07QJX2AmnYsTFqsVyrlnbI0-5fYWyuG82BkdcRipND-hCAfiSHfOwPFgE0-luMsWSCKURV-HFobk0zROXZ23NgsqE-lfU-nWFxNMH29o1p0CcpV78h86jI_8eLY5ebfZhBqGckE4mfM0pRIutxHfSpPAdhwN2fh6few557jlCZJ9WD-DIdypDfHJ7KWLfNFKBm0qNliKfoxxH8D-MWLjlHWyJYqrp-gPNIoBREIHQUUGKfHHcG2CCb4uhb94dwOFn-1On40mSKhadPGgZv6ibCK36Gouy1ODFLDH4BwgEtu9SyWfh8UXhB92es5GlAYlsnkENASGVSOCHWENDxvkGD1_EEUJlb29yUMOZH3nddnL3EysKgeixVrU-VbJQsL94RS1XUQl1gZQO4VKn2bDoVAQNUzlTLLI.zLcOpTHESd-KqhGs.stY3rEFPyIU0fVLK_P7KMcXF-R14Q6Av-xcueYIvtaiSrisGbpoQCH2uzIfWVL39QL-wbgzTF7QUMLzt3jqxELgWZlW5_XzykIhHoEdy0aT8LVEj-LXlrJN2dQLYYT-237wkRjWrhNrnE4o9xXIAsB6TeTcxcC9EnpUaRI56dTZRmE21VYwDSW3jasb-s5eLbQPU60bo9-dpPaNat8XULy1w2GdqjnNZclLz2rexhzzRX0dFjG64plS_hvxExRfedT5ocvTKctiSqWCesT-SsymAYAUoMMNPUi4gRD6cD9R5OgnXl7Ky0SeuB7lsPzRbAYK1R-269yo43N3RsOO__-FM-1QgkU8xzOYPcSWsuxi3dDFumrPDjymJ9yg05z70SGlM3Z7ZyHkrrprku02shmINUf81YnmrhcghZ9SExohkvwMmeXxfosLn0_wWMhEb-gJ0HtX5SMMixTkkGegCpWOYZP8u6_xwO8nJlwPWqZejH4tgOKVbIULp6YVVNiIV67xSBWyz2ypdw-SyEHoPmKbhhzUqKKXhTckLLz1WOqe-NOfybzY7Rur5rl2PCI0vRteMGd3MirAy5jpnrTbUUI4RtHE5AWgJbY80DqqmXTkDfB6B65WNwS1B7idc4gGlWbm2YUXhjtyQnWh8kHxUvbXiLP7uqPQ4qsV16VxwV6zIZl2uibIehPpXTOJb4lRNeH1AWZS1b_0LflbA3FWtIbV3dCtY0n-u2k3hyMhMieuIyG2fQHMH0obatgvL9TMmh1-o-lWNQhJQdehfVf9rdPBZ5zxAbPGuDX-S6a6AkbJra-8Djlp6w3w8YLGjrg_SoCB3BpFM7mUic1sC36seshgiyZdFYLMZbnbdTzxPewY5PZcSGV_VamliAP3R_5TCd4syDqZUyesgzWLAh_Y1NNDNJJozO1lXRxIHby8K2DZy0dSdnd3Jm-yD2_e6bnTE0EuNQbBa9bZEUjPok6uvyxOEoUBnvPEY8WTlRwyJFUai3PFcK4ZCrO2dSyJtv86ASGAhws-5jKumrfydEVPkLT9rqRB--L3BoJi2mdLOPUPN1w5C48iWP9elX3ZU_RIimFYb7KTLsLjyYgS9BDbPR_3NsaBFa8DSFcbuPWZTwi-g5Fczf-RSBi4NDKS0Xa3qt0qnJvZy6bDMWy_0TkbwnIFFYdAmlq6q5SJx9KWn7ZzauoOPFjNXqbtPgkgZc411iifQQS1PdXUL7fHSLI_oRUHSBtkhmxSF9NM3c7J3V2nHba2FnjR3ONB4Jr4jPMbpg_vDIc2O7cSY0GxFsflc1mh8IKEHh3q6xT7TibWtEZ_-AdTW57wCjTdbqSIZCGAthxvk2mxuDj9iUvNB-GWG-0VnKYr0m6f4OVnax0NouV8M1EVXN-tAkuL1IOzPhQtFIV0X8fGNBruGKpLqTEjtp9MWtAGiIpv6ac6mliywOgH2NVVCtxPxMsNWfdcyjT24_vaXQtVSaMbKWU9knpYp3cgv3FlSe7L6OfGiGd6vxbwWNEKdOVchmIgveBC0pSgIuzU_RVY92c2t_rxrCoRvpc_XKfjmFILLf1xsUWl1nXwI_xWY9q7DiVvBQuXJqAgfukIRiI2Db2ngMCzXFKZkSs8kifJaCQ6BUtCguhksBiCGUkz56vb9BBB9thh4r4GcsR37FQcEGP5xzLrMXmpHJQ.iqJH8bzPrTeMTUl9m4nOmw"
API_BASE_URL = "https://api.lookout.com"


class LookoutAPIClient:
    """Client for interacting with the Lookout Mobile Risk API."""
    
    def __init__(self, api_key: str, api_domain: str = API_BASE_URL):
        """
        Initialize the Lookout API client.
        
        Args:
            api_key: The application key for OAuth2 authentication
            api_domain: The API domain (default: https://api.lookout.com)
        """
        self.api_key = api_key
        self.api_domain = api_domain
        self.access_token = None
        self.token_expires_at = None
        self.session = requests.Session()
        
    def get_access_token(self) -> str:
        """
        Get an OAuth2 access token using the client credentials flow.
        
        Returns:
            The access token string
            
        Raises:
            requests.RequestException: If the token request fails
        """
        if (self.access_token and self.token_expires_at and 
            datetime.datetime.now().timestamp() * 1000 < self.token_expires_at - 60000):
            return self.access_token
            
        token_url = urljoin(self.api_domain, "/oauth2/token")
        
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        
        data = {'grant_type': 'client_credentials'}
        
        try:
            response = self.session.post(token_url, headers=headers, data=data, timeout=30)
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data['access_token']
            self.token_expires_at = token_data['expires_at']
            
            logging.info("Successfully obtained access token")
            return self.access_token
            
        except requests.RequestException as e:
            logging.error(f"Failed to obtain access token: {e}")
            raise
            
    def get_device(self, 
                  customer_device_id: Optional[str] = None,
                  guid: Optional[str] = None,
                  mdm_connector_id: Optional[int] = None,
                  mdm_connector_uuid: Optional[str] = None,
                  mdm_device_id: Optional[str] = None,
                  show_vulns: bool = True) -> Dict[str, Any]:
        """
        Get device information from the Lookout API.
        
        Args:
            customer_device_id: Customer device identifier
            guid: Device GUID
            mdm_connector_id: MDM connector ID
            mdm_connector_uuid: MDM connector UUID
            mdm_device_id: MDM device ID
            show_vulns: Whether to include vulnerability information
            
        Returns:
            Device information dictionary
            
        Raises:
            requests.RequestException: If the API request fails
            ValueError: If no device identifier is provided
        """
        if not any([customer_device_id, guid, mdm_connector_id, mdm_connector_uuid, mdm_device_id]):
            raise ValueError("At least one device identifier must be provided")
            
        access_token = self.get_access_token()
        
        device_url = urljoin(self.api_domain, "/mra/api/v2/device")
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        params = {}
        if customer_device_id:
            params['customer_device_id'] = customer_device_id
        if guid:
            params['guid'] = guid
        if mdm_connector_id:
            params['mdm_connector_id'] = mdm_connector_id
        if mdm_connector_uuid:
            params['mdm_connector_uuid'] = mdm_connector_uuid
        if mdm_device_id:
            params['mdm_device_id'] = mdm_device_id
        if show_vulns:
            params['show_vulns'] = 'true'
            
        try:
            response = self.session.get(device_url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            device_data = response.json()
            logging.info(f"Successfully retrieved device data")
            return device_data
            
        except requests.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                logging.error(f"API request failed with status {e.response.status_code}: {e.response.text}")
            else:
                logging.error(f"API request failed: {e}")
            raise
    
    def get_threats(self, device_guid: str) -> Dict[str, Any]:
        """
        Get threats for a specific device from the Lookout API.
        
        Args:
            device_guid: Device GUID
            
        Returns:
            Threats information dictionary
            
        Raises:
            requests.RequestException: If the API request fails
        """
        access_token = self.get_access_token()
        
        threats_url = urljoin(self.api_domain, "/mra/api/v2/threats")
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        params = {
            'device_guid': device_guid
        }
            
        try:
            response = self.session.get(threats_url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            threats_data = response.json()
            logging.info(f"Successfully retrieved threats data")
            return threats_data
            
        except requests.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                logging.error(f"Threats API request failed with status {e.response.status_code}: {e.response.text}")
            else:
                logging.error(f"Threats API request failed: {e}")
            raise
    
    def get_pcp_threats(self, device_guid: str) -> Dict[str, Any]:
        """
        Get PCP threats for a specific device from the Lookout API.
        
        Args:
            device_guid: Device GUID
            
        Returns:
            PCP threats information dictionary
            
        Raises:
            requests.RequestException: If the API request fails
        """
        access_token = self.get_access_token()
        
        pcp_threats_url = urljoin(self.api_domain, "/mra/api/v2/pcp-threats")
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        params = {
            'device_guid': device_guid
        }
            
        try:
            response = self.session.get(pcp_threats_url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            pcp_threats_data = response.json()
            logging.info(f"Successfully retrieved PCP threats data")
            return pcp_threats_data
            
        except requests.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                logging.error(f"PCP Threats API request failed with status {e.response.status_code}: {e.response.text}")
            else:
                logging.error(f"PCP Threats API request failed: {e}")
            raise


class EnhancedDeviceInspector:
    """Main class for the enhanced device inspector tool."""
    
    def __init__(self, api_client: LookoutAPIClient):
        """Initialize the device inspector with an API client."""
        self.api_client = api_client
        
    def extract_device_info(self, device_data: Dict[str, Any], threats_data: Optional[Dict[str, Any]] = None, pcp_threats_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Extract relevant device information from the API responses.
        
        Args:
            device_data: Raw device data from the API
            threats_data: Raw threats data from the API (optional)
            pcp_threats_data: Raw PCP threats data from the API (optional)
            
        Returns:
            Structured device information
        """
        info = {
            'device_id': device_data.get('guid'),
            'customer_device_id': device_data.get('customer_device_id'),
            'device_name': device_data.get('device_name'),
            'email': device_data.get('email'),
            'platform': device_data.get('platform'),
            'operating_system': {
                'name': device_data.get('platform'),
                'version': device_data.get('software', {}).get('os_version'),
                'build': device_data.get('software', {}).get('os_build'),
                'patch_level': device_data.get('software', {}).get('security_patch_level'),
                'latest_patch': device_data.get('software', {}).get('latest_security_patch_level')
            },
            'hardware': {
                'manufacturer': device_data.get('hardware', {}).get('manufacturer'),
                'model': device_data.get('hardware', {}).get('model'),
                'device_type': device_data.get('device_type')
            },
            'security_status': {
                'jailbroken_rooted': device_data.get('jailbroken_rooted', False),
                'protection_status': device_data.get('protection_status'),
                'activation_status': device_data.get('activation_status'),
                'compliance_status': device_data.get('compliance_status'),
                'risk_level': device_data.get('risk_level')
            },
            'last_seen': device_data.get('checkin_time'),
            'enrollment_date': device_data.get('enrollment_date'),
            'threats': [],
            'vulnerabilities': []
        }
        
        # Add threats from device_data if present
        if 'threats' in device_data and device_data['threats']:
            for threat in device_data['threats']:
                threat_info = {
                    'id': threat.get('id'),
                    'name': threat.get('name'),
                    'type': threat.get('type'),
                    'severity': threat.get('severity'),
                    'description': threat.get('description'),
                    'detected_at': threat.get('detected_at'),
                    'status': threat.get('status')
                }
                info['threats'].append(threat_info)
        
        # Add threats from threats_data if present
        if threats_data and 'threats' in threats_data and threats_data['threats']:
            for threat in threats_data['threats']:
                # Only add open threats
                if threat.get('status') == 'OPEN':
                    threat_info = {
                        'id': threat.get('guid'),
                        'name': threat.get('description') or threat.get('classification'),
                        'type': threat.get('type'),
                        'severity': threat.get('risk'),
                        'description': threat.get('details', {}).get('application_name') or threat.get('description'),
                        'detected_at': threat.get('detected_at'),
                        'status': threat.get('status'),
                        'classification': threat.get('classification'),
                        'details': threat.get('details')
                    }
                    # Check if this threat is already in the list (avoid duplicates)
                    duplicate = False
                    for existing_threat in info['threats']:
                        if existing_threat.get('id') == threat_info['id']:
                            duplicate = True
                            break
                    if not duplicate:
                        info['threats'].append(threat_info)
        
        # Add PCP threats from pcp_threats_data if present
        if pcp_threats_data and 'threats' in pcp_threats_data and pcp_threats_data['threats']:
            for threat in pcp_threats_data['threats']:
                # Only add open threats
                if threat.get('status') == 'OPEN':
                    threat_info = {
                        'id': threat.get('guid'),
                        'name': threat.get('classification'),
                        'type': threat.get('type'),
                        'severity': threat.get('risk'),
                        'description': threat.get('details', {}).get('url') or threat.get('description'),
                        'detected_at': threat.get('detected_at'),
                        'status': threat.get('status'),
                        'classification': threat.get('classification'),
                        'details': threat.get('details')
                    }
                    # Check if this threat is already in the list (avoid duplicates)
                    duplicate = False
                    for existing_threat in info['threats']:
                        if existing_threat.get('id') == threat_info['id']:
                            duplicate = True
                            break
                    if not duplicate:
                        info['threats'].append(threat_info)
        
        # Add vulnerabilities from device_data if present
        if 'device_vulns' in device_data and device_data['device_vulns'] and 'vulnerabilities' in device_data['device_vulns']:
            for vuln in device_data['device_vulns']['vulnerabilities']:
                if 'info' in vuln:
                    vuln_info = {
                        'cve_id': vuln['info'].get('name'),
                        'severity': vuln['info'].get('severity'),
                        'description': vuln['info'].get('description'),
                        'cvss_score': vuln['info'].get('severity'),
                        'affected_component': vuln['info'].get('classification'),
                        'published_date': None
                    }
                    info['vulnerabilities'].append(vuln_info)
        
        return info
    
    def format_output(self, device_info: Dict[str, Any], output_format: str = 'table') -> str:
        """
        Format device information for display.
        
        Args:
            device_info: Structured device information
            output_format: Output format ('json', 'table', 'compact')
            
        Returns:
            Formatted output string
        """
        if output_format == 'json':
            return json.dumps(device_info, indent=2, default=str)
        
        elif output_format == 'compact':
            lines = []
            lines.append(f"Device: {device_info['device_name'] or device_info['device_id']} ({device_info['device_id']})")
            lines.append(f"Platform: {device_info['platform']}")
            lines.append(f"OS Version: {device_info['operating_system']['version']}")
            lines.append(f"Security Status: {device_info['security_status']['protection_status']}")
            lines.append(f"Threats: {len(device_info['threats'])}")
            lines.append(f"Vulnerabilities: {len(device_info['vulnerabilities'])}")
            return '\n'.join(lines)
        
        else:
            lines = []
            lines.append("=" * 70)
            lines.append("LOOKOUT DEVICE SECURITY REPORT")
            lines.append("=" * 70)
            lines.append(f"Device ID: {device_info['device_id']}")
            lines.append(f"Customer Device ID: {device_info['customer_device_id']}")
            lines.append(f"Device Name: {device_info['device_name']}")
            lines.append(f"User Email: {device_info['email']}")
            lines.append(f"Platform: {device_info['platform']}")
            lines.append("")
            
            lines.append("HARDWARE INFORMATION")
            lines.append("-" * 30)
            hw = device_info['hardware']
            lines.append(f"Manufacturer: {hw['manufacturer']}")
            lines.append(f"Model: {hw['model']}")
            lines.append(f"Device Type: {hw['device_type']}")
            lines.append("")
            
            lines.append("OPERATING SYSTEM")
            lines.append("-" * 30)
            os_info = device_info['operating_system']
            lines.append(f"Platform: {os_info['name']}")
            lines.append(f"OS Version: {os_info['version']}")
            lines.append(f"Build: {os_info['build']}")
            if os_info['patch_level']:
                lines.append(f"Security Patch Level: {os_info['patch_level']}")
                if os_info['latest_patch'] and os_info['patch_level'] != os_info['latest_patch']:
                    lines.append(f"Latest Patch Available: {os_info['latest_patch']}")
                    lines.append("⚠️  SECURITY WARNING: Device is missing latest security patches!")
            lines.append("")
            
            lines.append("SECURITY STATUS")
            lines.append("-" * 30)
            sec = device_info['security_status']
            lines.append(f"Protection Status: {sec['protection_status']}")
            lines.append(f"Activation Status: {sec['activation_status']}")
            lines.append(f"Compliance Status: {sec['compliance_status']}")
            lines.append(f"Risk Level: {sec['risk_level']}")
            
            if sec['jailbroken_rooted']:
                lines.append("🚨 CRITICAL: Device is jailbroken/rooted!")
            else:
                lines.append("✅ Device integrity verified")
            
            lines.append(f"Last Check-in: {device_info['last_seen']}")
            lines.append("")
            
            if device_info['threats']:
                lines.append(f"ACTIVE THREATS ({len(device_info['threats'])})")
                lines.append("-" * 30)
                for threat in device_info['threats']:
                    severity = threat.get('severity', '').upper()
                    severity_icon = "🚨" if severity == "HIGH" else "⚠️" if severity == "MEDIUM" else "ℹ️"
                    lines.append(f"{severity_icon} {threat.get('name')} ({severity})")
                    lines.append(f"   Type: {threat.get('type')}")
                    lines.append(f"   Status: {threat.get('status')}")
                    if threat.get('classification'):
                        lines.append(f"   Classification: {threat.get('classification')}")
                    if threat.get('detected_at'):
                        lines.append(f"   Detected: {threat.get('detected_at')}")
                    if threat.get('description'):
                        lines.append(f"   Description: {threat.get('description')}")
                    lines.append("")
            else:
                lines.append("THREATS")
                lines.append("-" * 30)
                lines.append("✅ No active threats detected")
                lines.append("")
            
            if device_info['vulnerabilities']:
                lines.append(f"VULNERABILITIES ({len(device_info['vulnerabilities'])})")
                lines.append("-" * 30)
                for vuln in device_info['vulnerabilities']:
                    severity = vuln.get('severity', '')
                    if isinstance(severity, str):
                        severity = severity.upper()
                    severity_icon = "🚨" if severity == "CRITICAL" or severity == "HIGH" or int(severity) >= 7 else "⚠️" if severity == "MEDIUM" or int(severity) >= 4 else "ℹ️"
                    lines.append(f"{severity_icon} {vuln.get('cve_id')} (CVSS: {vuln.get('cvss_score')})")
                    lines.append(f"   Severity: {severity}")
                    lines.append(f"   Component: {vuln.get('affected_component')}")
                    if vuln.get('published_date'):
                        lines.append(f"   Published: {vuln.get('published_date')}")
                    if vuln.get('description'):
                        lines.append(f"   Description: {vuln.get('description')}")
                    lines.append("")
            else:
                lines.append("VULNERABILITIES")
                lines.append("-" * 30)
                lines.append("✅ No known vulnerabilities detected")
                lines.append("")
            
            lines.append("=" * 70)
            lines.append("End of Report")
            
            return '\n'.join(lines)


def setup_logging(verbose: bool = False):
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stderr)]
    )


def load_api_key(api_key_input: str) -> str:
    """
    Load API key from input - either direct key or file path.
    
    Args:
        api_key_input: Either the API key directly or a file path containing the key
        
    Returns:
        The API key string
    """
    # Check if it looks like a file path
    if api_key_input.endswith('.txt') or '/' in api_key_input:
        try:
            with open(api_key_input, 'r') as f:
                return f.read().strip()
        except FileNotFoundError:
            print(f"❌ API key file not found: {api_key_input}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error reading API key file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Assume it's the key directly
        return api_key_input


def main():
    """Main function for the CLI tool."""
    parser = argparse.ArgumentParser(
        description='Enhanced Lookout Mobile Risk API Device Inspector - Analyze device security status, threats, and vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --customer-device-id "device123"
  %(prog)s --guid "550e8400-e29b-41d4-a716-446655440000"
  %(prog)s --mdm-device-id "mdm123" --format json
  %(prog)s --api-key sansfire_application_key.txt --guid "device-guid"
        """
    )
    
    parser.add_argument(
        '--api-key',
        default='sansfire_application_key.txt',
        help='Lookout API application key or path to file containing the key (uses default if not provided)'
    )
    
    device_group = parser.add_argument_group('device identifiers', 'At least one device identifier is required')
    device_group.add_argument(
        '--customer-device-id',
        help='Customer device identifier'
    )
    device_group.add_argument(
        '--guid',
        help='Device GUID'
    )
    device_group.add_argument(
        '--mdm-connector-id',
        type=int,
        help='MDM connector ID'
    )
    device_group.add_argument(
        '--mdm-connector-uuid',
        help='MDM connector UUID'
    )
    device_group.add_argument(
        '--mdm-device-id',
        help='MDM device ID'
    )
    
    parser.add_argument(
        '--api-domain',
        default=API_BASE_URL,
        help=f'API domain (default: {API_BASE_URL})'
    )
    parser.add_argument(
        '--format',
        choices=['table', 'json', 'compact'],
        default='table',
        help='Output format (default: table)'
    )
    parser.add_argument(
        '--no-vulns',
        action='store_true',
        help='Do not include vulnerability information'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    device_identifiers = [
        args.customer_device_id,
        args.guid,
        args.mdm_connector_id,
        args.mdm_connector_uuid,
        args.mdm_device_id
    ]
    
    if not any(device_identifiers):
        parser.error("At least one device identifier must be provided")
    
    try:
        # Load the API key (from file if needed)
        api_key = load_api_key(args.api_key)
        
        api_client = LookoutAPIClient(api_key, args.api_domain)
        inspector = EnhancedDeviceInspector(api_client)
        
        print("🔍 Retrieving device information from Lookout API...")
        
        # Get device data
        device_data = api_client.get_device(
            customer_device_id=args.customer_device_id,
            guid=args.guid,
            mdm_connector_id=args.mdm_connector_id,
            mdm_connector_uuid=args.mdm_connector_uuid,
            mdm_device_id=args.mdm_device_id,
            show_vulns=not args.no_vulns
        )
        
        # If we have a GUID, get threats data
        threats_data = None
        pcp_threats_data = None
        
        if args.guid or device_data.get('guid'):
            device_guid = args.guid or device_data.get('guid')
            print(f"🔍 Retrieving threats for device {device_guid}...")
            
            try:
                threats_data = api_client.get_threats(device_guid)
                logging.info(f"Found {len(threats_data.get('threats', []))} threats")
            except requests.RequestException as e:
                logging.warning(f"Failed to retrieve threats: {e}")
                print("⚠️ Failed to retrieve threats data. Continuing with device data only.")
            
            try:
                pcp_threats_data = api_client.get_pcp_threats(device_guid)
                logging.info(f"Found {len(pcp_threats_data.get('threats', []))} PCP threats")
            except requests.RequestException as e:
                logging.warning(f"Failed to retrieve PCP threats: {e}")
                print("⚠️ Failed to retrieve PCP threats data. Continuing without PCP threats.")
        
        # Process the data
        device_info = inspector.extract_device_info(device_data, threats_data, pcp_threats_data)
        output = inspector.format_output(device_info, args.format)
        
        print(output)
        
    except requests.RequestException as e:
        print(f"❌ API request failed: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"❌ Invalid input: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
