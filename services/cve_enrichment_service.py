# services/cve_enrichment_service.py
import aiohttp
import asyncio
import json
import logging
from typing import List, Dict
from datetime import datetime
import requests


class CVEEnrichmentService:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.timeout = 5  # 5 second timeout for API calls
        # Only free sources - no API keys needed!
        self.free_sources = {
            'malwarebazaar': self.enrich_from_malwarebazaar,
            'threatfox': self.enrich_from_threatfox,
        }

    def enrich_alert(self, alert_data: Dict) -> Dict:
        """Main enrichment function - adds CVEs to alert data (synchronous)"""

        # Extract indicators
        indicators = self.extract_indicators(alert_data)
        self.logger.info(f"Extracted indicators: {indicators}")

        # Collect CVEs from all sources
        all_cves = []
        enrichment_sources = []

        # Query MalwareBazaar
        try:
            cves = self.enrich_from_malwarebazaar(indicators)
            if cves:
                all_cves.extend(cves)
                enrichment_sources.append('malwarebazaar')
                self.logger.info(f"Found {len(cves)} CVEs from MalwareBazaar")
        except Exception as e:
            self.logger.error(f"MalwareBazaar error: {e}")

        # Query ThreatFox
        try:
            cves = self.enrich_from_threatfox(indicators)
            if cves:
                all_cves.extend(cves)
                enrichment_sources.append('threatfox')
                self.logger.info(f"Found {len(cves)} CVEs from ThreatFox")
        except Exception as e:
            self.logger.error(f"ThreatFox error: {e}")

        # Remove duplicates
        unique_cves = list(set(all_cves))

        # Add enrichment data to alert
        alert_data['enriched_cves'] = unique_cves
        alert_data['enrichment_sources'] = enrichment_sources
        alert_data['enrichment_timestamp'] = datetime.now().isoformat()

        return alert_data

    def extract_indicators(self, alert_data: Dict) -> Dict:
        """Extract all indicators from alert"""
        indicators = {
            'hashes': [],
            'filenames': [],
            'domains': [],
            'ips': []
        }

        # Extract from VirusTotal data
        vt_data = alert_data.get('data', {}).get('virustotal', {})
        if vt_data:
            for hash_type in ['sha1', 'sha256', 'md5']:
                if hash_type in vt_data:
                    indicators['hashes'].append({
                        'type': hash_type,
                        'value': vt_data[hash_type]
                    })

            source_file = vt_data.get('source', {}).get('file', '')
            if source_file:
                indicators['filenames'].append(source_file)

        # Extract from syscheck data
        syscheck_data = alert_data.get('syscheck', {})
        if syscheck_data:
            for hash_type in ['sha1', 'sha256', 'md5']:
                for field in [f'{hash_type}_after', hash_type]:
                    if field in syscheck_data:
                        indicators['hashes'].append({
                            'type': hash_type,
                            'value': syscheck_data[field]
                        })

        return indicators

    def enrich_from_malwarebazaar(self, indicators: Dict) -> List[str]:
        """Query MalwareBazaar synchronously"""
        cves = []

        for hash_info in indicators.get('hashes', []):
            url = "https://mb-api.abuse.ch/api/v1/"
            data = {
                "query": "get_info",
                "hash": hash_info['value']
            }

            try:
                response = requests.post(url, data=data, timeout=self.timeout)
                if response.status_code == 200:
                    result = response.json()

                    if result.get('query_status') == 'ok':
                        data_entries = result.get('data', [])
                        if data_entries and isinstance(data_entries, list):
                            malware_info = data_entries[0]

                            # Extract CVEs from tags
                            tags = malware_info.get('tags', [])
                            for tag in tags:
                                if isinstance(tag, str) and tag.upper().startswith('CVE-'):
                                    cves.append(tag.upper())

                            # Map malware families to CVEs
                            malware_family = malware_info.get('signature', '').lower()
                            family_cve_map = {
                                'emotet': ['CVE-2017-11882', 'CVE-2018-0802'],
                                'trickbot': ['CVE-2017-0144', 'CVE-2020-0796'],
                                'qakbot': ['CVE-2021-40444'],
                                'cobalt': ['CVE-2021-44228', 'CVE-2021-34527'],
                                'mimikatz': ['CVE-2020-1472']
                            }

                            for family, family_cves in family_cve_map.items():
                                if family in malware_family:
                                    cves.extend(family_cves)
                                    break

            except requests.exceptions.Timeout:
                self.logger.warning(f"MalwareBazaar timeout for hash {hash_info['value']}")
            except Exception as e:
                self.logger.error(f"MalwareBazaar error for {hash_info['value']}: {e}")

        return list(set(cves))

    def enrich_from_threatfox(self, indicators: Dict) -> List[str]:
        """Query ThreatFox synchronously"""
        cves = []

        for hash_info in indicators.get('hashes', []):
            url = "https://threatfox-api.abuse.ch/api/v1/"
            data = json.dumps({
                "query": "search_hash",
                "hash": hash_info['value']
            })
            headers = {'Content-Type': 'application/json'}

            try:
                response = requests.post(url, data=data, headers=headers, timeout=self.timeout)
                if response.status_code == 200:
                    result = response.json()

                    if result.get('query_status') == 'ok':
                        for entry in result.get('data', []):
                            malware = entry.get('malware', '').lower()

                            if 'cobalt' in malware:
                                cves.extend(['CVE-2021-44228', 'CVE-2021-34527'])
                            elif 'metasploit' in malware:
                                cves.extend(['CVE-2017-0143', 'CVE-2017-0144'])
                            elif 'empire' in malware:
                                cves.extend(['CVE-2021-34527', 'CVE-2020-1472'])

                            # Check tags for CVEs
                            tags = entry.get('tags', [])
                            for tag in tags:
                                if isinstance(tag, str) and 'CVE-' in tag.upper():
                                    import re
                                    found_cves = re.findall(r'CVE-\d{4}-\d{4,7}', tag, re.IGNORECASE)
                                    cves.extend([cve.upper() for cve in found_cves])

            except requests.exceptions.Timeout:
                self.logger.warning(f"ThreatFox timeout for hash {hash_info['value']}")
            except Exception as e:
                self.logger.error(f"ThreatFox error for {hash_info['value']}: {e}")

        return list(set(cves))
