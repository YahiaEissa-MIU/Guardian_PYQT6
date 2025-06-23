# models/incident_history_model.py
import re
import sys
import json
import aiohttp
import asyncio
import csv
import logging
import os
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict
from services.cve_enrichment_service import CVEEnrichmentService


@dataclass
class IncidentHistoryModel:
    shuffle_url: str = field(default="")
    shuffle_api_key: str = field(default="")
    workflow_names: List[str] = field(default_factory=list)
    workflow_ids: Dict[str, str] = field(default_factory=dict)
    incidents: List[dict] = field(default_factory=list)
    observers: List[callable] = field(default_factory=list)
    last_modified: datetime = field(default_factory=datetime.now)
    is_configured: bool = field(default=False)
    enrichment_service: CVEEnrichmentService = field(default_factory=CVEEnrichmentService)
    cve_cache: Dict[int, List[str]] = field(default_factory=dict)  # Cache CVEs by incident index

    def __post_init__(self):
        """Post initialization validation"""
        self.is_configured = bool(
            self.shuffle_url and
            self.shuffle_api_key
        )
        self.enrichment_service = CVEEnrichmentService()
        print(f"IncidentHistoryModel initialized with is_configured={self.is_configured}")

    def add_observer(self, observer):
        """Adds an observer to the model"""
        if observer not in self.observers:
            self.observers.append(observer)

    def remove_observer(self, observer):
        """Remove an observer from the model"""
        if observer in self.observers:
            self.observers.remove(observer)

    def notify_observers(self):
        """Notify all registered observers of changes"""
        for observer in list(self.observers):
            try:
                observer()
            except Exception as e:
                print(f"Error notifying observer {observer}: {e}")

    def _get_ssl_context(self):
        """Create SSL context for self-signed certificates"""
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        return ssl_context

    def _ensure_url_protocol(self, url):
        """Ensure URL has proper protocol based on port"""
        if url.startswith(('http://', 'https://')):
            return url

        # Check if port 3443 is specified (HTTPS port)
        if ':3443' in url:
            return f"https://{url}"
        # Default to HTTP for port 3001 or no port
        elif ':3001' in url or ':' not in url:
            # Remove any port and add default HTTP port
            base_url = url.split(':')[0]
            return f"http://{base_url}:3001"
        else:
            # For any other port, default to HTTP
            return f"http://{url}"

    async def get_workflow_ids(self):
        """Fetches workflow IDs for all configured workflow names"""
        try:
            url = self._ensure_url_protocol(self.shuffle_url)

            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self.shuffle_api_key}",
                    "Content-Type": "application/json"
                }
                api_url = f"{url}/api/v1/workflows"
                print(f"Fetching workflows from: {api_url}")

                ssl_context = self._get_ssl_context() if url.startswith('https://') else None

                async with session.get(api_url, headers=headers, ssl=ssl_context) as response:
                    if response.status == 200:
                        workflows = await response.json()
                        self.workflow_ids = {}

                        for workflow in workflows:
                            workflow_name = workflow.get('name')
                            if workflow_name in self.workflow_names:
                                self.workflow_ids[workflow_name] = workflow.get('id')
                                print(f"Found workflow ID for {workflow_name}: {workflow.get('id')}")

                        return self.workflow_ids
                    else:
                        error_text = await response.text()
                        print(f"Failed to fetch workflows: {response.status} - {error_text}")
                        return None
        except Exception as e:
            print(f"Error fetching workflow IDs: {e}")
            return None

    async def validate_connection(self) -> bool:
        """Validates the Shuffle connection and workflow names"""
        if not all([self.shuffle_url, self.shuffle_api_key]):
            print("Missing configuration parameters")
            return False

        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"Authorization": f"Bearer {self.shuffle_api_key}"}

                url = self._ensure_url_protocol(self.shuffle_url)
                api_url = f"{url}/api/v1/workflows"
                print(f"Testing connection to: {api_url}")

                ssl_context = self._get_ssl_context() if url.startswith('https://') else None

                async with session.get(api_url, headers=headers, ssl=ssl_context) as response:
                    print(f"Response status: {response.status}")
                    if response.status == 200:
                        workflows = await response.json()

                        if not self.workflow_names:
                            self.is_configured = True
                            print("Connection validation successful (no workflows selected)")
                            return True

                        available_workflows = {w.get('name') for w in workflows}
                        selected_workflows = set(self.workflow_names)
                        found_workflows = selected_workflows.intersection(available_workflows)

                        if found_workflows:
                            self.is_configured = True
                            print(
                                f"Connection validation successful. Found {len(found_workflows)} of {len(self.workflow_names)} workflows")
                            return True
                        else:
                            print(f"None of the selected workflows found: {self.workflow_names}")
                            return False
                    print(f"Connection failed: {await response.text()}")
                    return False
        except Exception as e:
            print(f"Validation error: {e}")
            return False

    async def fetch_shuffle_incidents(self):
        """Fetches incidents from all configured Shuffle workflows"""
        print("\n=== Fetching Shuffle Incidents ===")

        if not self.workflow_names:
            print("No workflows configured.")
            return []

        if not self.workflow_ids:
            await self.get_workflow_ids()
            if not self.workflow_ids:
                print("Failed to get workflow IDs")
                return []

        url = self._ensure_url_protocol(self.shuffle_url)
        headers = {
            "Authorization": f"Bearer {self.shuffle_api_key}",
            "Content-Type": "application/json"
        }

        all_incidents = []
        self.cve_cache.clear()  # Clear the cache before fetching new incidents

        try:
            timeout = aiohttp.ClientTimeout(total=30)
            ssl_context = self._get_ssl_context() if url.startswith('https://') else None

            async with aiohttp.ClientSession(timeout=timeout) as session:
                for workflow_name, workflow_id in self.workflow_ids.items():
                    api_url = f"{url}/api/v1/workflows/{workflow_id}/executions"
                    print(f"\nFetching from workflow '{workflow_name}'")

                    try:
                        async with session.get(api_url, headers=headers, ssl=ssl_context) as response:
                            if response.status == 200:
                                executions = await response.json()
                                print(f"Found {len(executions)} executions")

                                # Process most recent executions
                                for execution in executions[:50]:
                                    # Only process successful executions
                                    if execution.get('status') not in ['FINISHED', 'SUCCESS']:
                                        continue

                                    # Get the execution argument (the Wazuh alert data)
                                    exec_arg = execution.get('execution_argument')
                                    if not exec_arg:
                                        continue

                                    try:
                                        # Parse the Wazuh alert data
                                        if isinstance(exec_arg, str):
                                            alert_data = json.loads(exec_arg)
                                        else:
                                            alert_data = exec_arg

                                        # Process the Wazuh alert
                                        incident = self._process_wazuh_webhook_alert(alert_data, workflow_name)
                                        if incident:
                                            # Store incident index
                                            incident_index = len(all_incidents)
                                            all_incidents.append(incident)

                                            # Cache CVEs for this incident
                                            if incident.get('CVE'):
                                                cve_list = [cve.strip() for cve in incident['CVE'].split(',') if
                                                            cve.strip()]
                                                self.cve_cache[incident_index] = cve_list

                                    except Exception as e:
                                        print(f"Error processing execution: {e}")
                                        continue

                            else:
                                error_text = await response.text()
                                print(f"Error response for {workflow_name}: {error_text}")

                    except Exception as e:
                        print(f"Error fetching from workflow '{workflow_name}': {e}")

        except Exception as e:
            print(f"Critical error in fetch_shuffle_incidents: {e}")
            import traceback
            traceback.print_exc()
            return []

        print(f"\nTotal incidents collected: {len(all_incidents)}")
        return all_incidents

    def get_cves_for_incident(self, incident_index: int) -> List[str]:
        """Get cached CVEs for a specific incident by index"""
        return self.cve_cache.get(incident_index, [])

    def _process_wazuh_webhook_alert(self, webhook_data, workflow_name):
        """Process Wazuh webhook alert data into incident format"""
        try:
            # Extract main fields from webhook data with defaults
            timestamp = webhook_data.get('timestamp', '')
            rule_id = webhook_data.get('rule_id', '')
            severity = webhook_data.get('severity', 0)
            title = webhook_data.get('title') or webhook_data.get('pretext') or ''
            text = webhook_data.get('text') or ''

            # Get all_fields for detailed information
            all_fields = webhook_data.get('all_fields', {})
            rule_info = all_fields.get('rule', {}) if all_fields else {}
            agent_info = all_fields.get('agent', {}) if all_fields else {}

            # If still no title, try to get from rule description
            if not title and rule_info:
                title = rule_info.get('description', 'Wazuh Alert')

            # Format timestamp
            formatted_time = self._parse_timestamp(timestamp)

            # Determine severity level
            severity_text = self._get_severity_text(severity)

            # Extract CVEs using multiple methods
            unique_cves = self._extract_cves_from_alert(webhook_data, rule_info, title, text, all_fields, rule_id)

            # Build the incident
            incident = {
                "Date": formatted_time,
                "Incident": title or "Wazuh Alert",
                "Action": f"Alert from {agent_info.get('name', 'Unknown Agent')}",
                "Workflow": workflow_name,
                "CVE": ", ".join(unique_cves) if unique_cves else "",
                "Severity": severity_text,
                "Details": json.dumps({
                    "rule_id": rule_id,
                    "rule_level": rule_info.get('level', severity),
                    "agent": agent_info.get('name', 'Unknown'),
                    "agent_id": agent_info.get('id', 'Unknown'),
                    "groups": rule_info.get('groups', []),
                    "mitre": rule_info.get('mitre', {}),
                    "compliance": {
                        "pci_dss": rule_info.get('pci_dss', []),
                        "gdpr": rule_info.get('gdpr', []),
                        "hipaa": rule_info.get('hipaa', []),
                        "nist_800_53": rule_info.get('nist_800_53', [])
                    }
                }, indent=2)
            }

            return incident

        except Exception as e:
            print(f"Error processing Wazuh webhook alert: {e}")
            import traceback
            traceback.print_exc()
            return None

    def _extract_cves_from_alert(self, webhook_data, rule_info, title, text, all_fields, rule_id):
        """Extract CVEs from alert using multiple methods"""
        cve_list = []
        cve_pattern = r'CVE-\d{4}-\d{4,7}'

        # Ensure title and text are strings
        title = title or ""
        text = text or ""

        # 1. Try enrichment service first
        try:
            enriched_alert = self.enrichment_service.enrich_alert(webhook_data.copy())
            enriched_cves = enriched_alert.get('enriched_cves', [])
            if enriched_cves:
                cve_list.extend(enriched_cves)
                print(f"Enrichment found {len(enriched_cves)} CVEs")
        except Exception as e:
            print(f"Enrichment error: {e}")

        # 2. Search for CVEs in text/title/description
        all_text = f"{title} {text} {json.dumps(all_fields)}"
        found_cves = re.findall(cve_pattern, all_text, re.IGNORECASE)
        cve_list.extend([cve.upper() for cve in found_cves])

        # 3. Apply rule-based mappings
        rule_cves = self._get_cves_from_rule_mapping(str(rule_id))
        cve_list.extend(rule_cves)

        # 4. Apply keyword-based mappings
        keywords_to_check = f"{title.lower()} {text.lower()}"
        keyword_cves = self._get_cves_from_keywords(keywords_to_check)
        cve_list.extend(keyword_cves)

        # 5. Check MITRE mappings
        if rule_info.get('mitre'):
            mitre_data = rule_info['mitre']
            techniques = mitre_data.get('technique', [])
            if isinstance(techniques, str):
                techniques = [techniques]
            for technique in techniques:
                technique_cves = self._get_cves_from_mitre_mapping(technique)
                cve_list.extend(technique_cves)

        # Remove duplicates while preserving order
        unique_cves = []
        seen = set()
        for cve in cve_list:
            if cve.upper() not in seen:
                seen.add(cve.upper())
                unique_cves.append(cve.upper())

        return unique_cves

    def _parse_timestamp(self, timestamp_value):
        """Parse various timestamp formats into a consistent string format"""
        try:
            if not timestamp_value:
                return datetime.now().strftime("%Y-%m-%d %H:%M")

            # Handle ISO format with timezone
            if isinstance(timestamp_value, str) and 'T' in timestamp_value:
                # Remove timezone info for parsing
                timestamp_clean = timestamp_value.split('+')[0].split('-')[-1] if '+' in timestamp_value else \
                    timestamp_value.split('Z')[0]
                # Fix: properly handle the timestamp by not splitting on '-' incorrectly
                if '+' in timestamp_value:
                    timestamp_clean = timestamp_value.split('+')[0]
                elif 'Z' in timestamp_value:
                    timestamp_clean = timestamp_value.split('Z')[0]
                else:
                    timestamp_clean = timestamp_value

                dt = datetime.fromisoformat(timestamp_clean)
                return dt.strftime("%Y-%m-%d %H:%M")

            # Handle numeric timestamps
            elif isinstance(timestamp_value, (int, float)):
                if timestamp_value > 1e12:  # Milliseconds
                    return datetime.fromtimestamp(timestamp_value / 1000).strftime("%Y-%m-%d %H:%M")
                else:  # Seconds
                    return datetime.fromtimestamp(timestamp_value).strftime("%Y-%m-%d %H:%M")

                # Handle string timestamps
            elif isinstance(timestamp_value, str):
                # Try parsing as number
                if timestamp_value.isdigit():
                    return self._parse_timestamp(int(timestamp_value))
                # Try common formats
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%d/%m/%Y %H:%M:%S"]:
                    try:
                        dt = datetime.strptime(timestamp_value, fmt)
                        return dt.strftime("%Y-%m-%d %H:%M")
                    except:
                        continue
                return timestamp_value[:16]

            return datetime.now().strftime("%Y-%m-%d %H:%M")

        except Exception as e:
            print(f"Timestamp parsing error for '{timestamp_value}': {e}")
        return datetime.now().strftime("%Y-%m-%d %H:%M")

    def _get_severity_text(self, severity_level):
        """Convert numeric severity to text"""
        severity_map = {
            0: "Info",
            1: "Low",
            2: "Low",
            3: "Low",
            4: "Medium",
            5: "Medium",
            6: "Medium",
            7: "High",
            8: "High",
            9: "High",
            10: "Critical",
            11: "Critical",
            12: "Critical",
            13: "Critical",
            14: "Critical",
            15: "Critical"
        }
        return severity_map.get(severity_level, "Unknown")

    def _get_cves_from_keywords(self, text):
        """Extract CVEs based on keywords in the text"""
        keyword_mappings = {
            # Existing malware families
            'emotet': ['CVE-2017-11882', 'CVE-2018-0802', 'CVE-2018-4878', 'CVE-2021-40444', 'CVE-2022-30190'],
            'trickbot': ['CVE-2017-0144', 'CVE-2020-0796', 'CVE-2021-40444', 'CVE-2020-1472'],
            'qakbot': ['CVE-2021-40444', 'CVE-2021-42287', 'CVE-2021-42278', 'CVE-2022-30190'],
            'qbot': ['CVE-2021-40444', 'CVE-2021-42287', 'CVE-2022-30190'],
            'cobalt': ['CVE-2021-44228', 'CVE-2021-34527', 'CVE-2022-26134', 'CVE-2020-1472'],
            'cobaltstrike': ['CVE-2021-44228', 'CVE-2021-34527', 'CVE-2022-26134'],
            'mimikatz': ['CVE-2020-1472', 'CVE-2021-36942', 'CVE-2021-42287', 'CVE-2021-42278'],
            'lazarus': ['CVE-2021-44228', 'CVE-2017-0144', 'CVE-2021-34527', 'CVE-2022-30190'],
            'darkside': ['CVE-2021-34527', 'CVE-2019-19781', 'CVE-2021-20016', 'CVE-2020-12812'],
            'ryuk': ['CVE-2020-1472', 'CVE-2018-8453', 'CVE-2020-0796', 'CVE-2019-0708'],
            'conti': ['CVE-2020-0796', 'CVE-2021-34527', 'CVE-2022-26134', 'CVE-2021-44228'],
            'wannacry': ['CVE-2017-0144', 'CVE-2017-0145', 'CVE-2017-0146', 'CVE-2017-0147', 'CVE-2017-0148'],

            # Additional malware families
            'revil': ['CVE-2021-30116', 'CVE-2019-2725', 'CVE-2021-34473', 'CVE-2021-34523'],
            'sodinokibi': ['CVE-2019-2725', 'CVE-2019-11510', 'CVE-2018-13379'],
            'maze': ['CVE-2019-11510', 'CVE-2019-19781', 'CVE-2020-5902'],
            'lockbit': ['CVE-2021-34527', 'CVE-2021-44228', 'CVE-2023-0669', 'CVE-2023-20269'],
            'blackcat': ['CVE-2021-44228', 'CVE-2022-26134', 'CVE-2021-34473'],
            'alphv': ['CVE-2021-44228', 'CVE-2022-26134', 'CVE-2023-20269'],
            'hive': ['CVE-2021-34527', 'CVE-2021-34473', 'CVE-2022-26134'],
            'dridex': ['CVE-2017-11882', 'CVE-2017-0199', 'CVE-2021-40444'],
            'icedid': ['CVE-2021-40444', 'CVE-2022-30190', 'CVE-2017-11882'],
            'bazarloader': ['CVE-2021-40444', 'CVE-2022-30190', 'CVE-2020-1472'],

            # Vulnerability names
            'eternalblue': ['CVE-2017-0144', 'CVE-2017-0145'],
            'log4j': ['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-44832', 'CVE-2021-45105'],
            'log4shell': ['CVE-2021-44228', 'CVE-2021-45046'],
            'printnightmare': ['CVE-2021-34527', 'CVE-2021-1675'],
            'zerologon': ['CVE-2020-1472'],
            'proxyshell': ['CVE-2021-34473', 'CVE-2021-34523', 'CVE-2021-31207'],
            'proxylogon': ['CVE-2021-26855', 'CVE-2021-26857', 'CVE-2021-26858', 'CVE-2021-27065'],
            'hafnium': ['CVE-2021-26855', 'CVE-2021-26857', 'CVE-2021-26858', 'CVE-2021-27065'],
            'bluekeep': ['CVE-2019-0708'],
            'sigred': ['CVE-2020-1350'],
            'netlogon': ['CVE-2020-1472'],
            'smbghost': ['CVE-2020-0796'],
            'follina': ['CVE-2022-30190'],
            'petitpotam': ['CVE-2021-36942'],
            'nopetya': ['CVE-2017-0144', 'CVE-2017-0145'],
            'samaccountname': ['CVE-2021-42287', 'CVE-2021-42278'],
            'hivenightmare': ['CVE-2021-36934'],
            'serioussam': ['CVE-2021-36934'],

            # Attack patterns
            'remote code execution': ['CVE-2021-34527', 'CVE-2021-44228', 'CVE-2022-30190', 'CVE-2022-26134'],
            'privilege escalation': ['CVE-2021-1732', 'CVE-2020-0787', 'CVE-2021-33739', 'CVE-2021-36934'],
            'ransomware': ['CVE-2021-34527', 'CVE-2017-0144', 'CVE-2021-44228', 'CVE-2019-19781'],
            'fileless': ['CVE-2017-0199', 'CVE-2017-11882', 'CVE-2018-0802'],
            'powershell': ['CVE-2020-1472', 'CVE-2021-34527', 'CVE-2022-30190'],
            'lateral movement': ['CVE-2020-1472', 'CVE-2017-0144', 'CVE-2019-0708'],
            'kerberos': ['CVE-2020-1472', 'CVE-2021-42287', 'CVE-2021-42278', 'CVE-2022-33679'],
            'active directory': ['CVE-2020-1472', 'CVE-2021-42287', 'CVE-2021-42278', 'CVE-2022-26923'],
            'domain controller': ['CVE-2020-1472', 'CVE-2021-42287', 'CVE-2021-42278'],
            'rdp': ['CVE-2019-0708', 'CVE-2019-1181', 'CVE-2019-1182', 'CVE-2020-0609'],
            'smb': ['CVE-2017-0144', 'CVE-2020-0796', 'CVE-2017-0145', 'CVE-2017-0146'],
            'exchange': ['CVE-2021-26855', 'CVE-2021-34473', 'CVE-2022-41040', 'CVE-2022-41082'],
            'outlook': ['CVE-2023-23397', 'CVE-2023-35384', 'CVE-2024-21413'],
            'office': ['CVE-2017-11882', 'CVE-2017-0199', 'CVE-2021-40444', 'CVE-2022-30190'],
            'macro': ['CVE-2021-40444', 'CVE-2022-30190', 'CVE-2016-7193'],
            'phishing': ['CVE-2021-40444', 'CVE-2017-0199', 'CVE-2017-11882'],
            'spearphishing': ['CVE-2021-40444', 'CVE-2017-0199', 'CVE-2022-30190'],
        }

        cves = []
        text_lower = text.lower()
        for keyword, keyword_cves in keyword_mappings.items():
            if keyword in text_lower:
                cves.extend(keyword_cves)

        return cves

    def _get_cves_from_rule_mapping(self, rule_id):
        """Map Wazuh rule IDs to known CVEs"""
        rule_cve_map = {
            # File integrity monitoring
            "550": ["CVE-2021-44228"],
            "554": ["CVE-2021-45046"],
            "553": ["CVE-2021-36934"],

            # Windows rules
            "60106": ["CVE-2021-34527"],
            "60107": ["CVE-2021-1675"],
            "60108": ["CVE-2021-36934"],
            "60109": ["CVE-2021-42287"],
            "60110": ["CVE-2021-42278"],

            # Authentication failures
            "5710": ["CVE-2020-1472"],
            "5503": ["CVE-2021-42287"],
            "5706": ["CVE-2019-0708"],

            # Web attacks
            "31101": ["CVE-2021-44228", "CVE-2021-45046"],
            "31103": ["CVE-2014-6271"],  # Shellshock
            "31104": ["CVE-2014-7169"],
            "31106": ["CVE-2017-5638"],  # Apache Struts
            "31108": ["CVE-2019-2725"],  # Oracle WebLogic
            "31109": ["CVE-2022-26134"],  # Confluence
            "31110": ["CVE-2022-22965"],  # Spring4Shell

            # SQL injection
            "31107": ["CVE-2019-1821", "CVE-2018-1133"],

            # Known malware patterns
            "87101": ["CVE-2017-0143", "CVE-2017-0144"],  # EternalBlue
            "87102": ["CVE-2017-0145", "CVE-2017-0146"],
            "87105": ["CVE-2017-11882", "CVE-2018-0802"],
            "87106": ["CVE-2021-40444"],
            "87107": ["CVE-2022-30190"],  # Follina

            # Vulnerability scanners
            "100100": ["CVE-2020-1472", "CVE-2019-0708", "CVE-2017-0144"],

            # Brute force
            "5551": ["CVE-2019-0708"],
            "5712": ["CVE-2020-1472"],

            # Process monitoring
            "592": ["CVE-2021-36934"],  # HiveNightmare/SeriousSAM
            "593": ["CVE-2021-34527"],  # PrintNightmare

            # Registry monitoring
            "750": ["CVE-2021-34527"],
            "751": ["CVE-2021-36934"],

            # Rootkit detection
            "510": ["CVE-2021-1732", "CVE-2020-0787"],
            "511": ["CVE-2021-33739"],
        }

        return rule_cve_map.get(rule_id, [])

    def _get_cves_from_mitre_mapping(self, technique):
        """Map MITRE ATT&CK techniques to commonly associated CVEs"""
        technique_cve_map = {
            # Initial Access
            "T1190": ["CVE-2021-44228", "CVE-2021-26855", "CVE-2019-19781", "CVE-2022-26134"],
            "T1133": ["CVE-2019-11510", "CVE-2018-13379", "CVE-2019-19781"],
            "T1078": ["CVE-2021-42287", "CVE-2021-42278"],
            "T1566": ["CVE-2021-40444", "CVE-2017-0199", "CVE-2022-30190"],

            # Execution
            "T1203": ["CVE-2021-40444", "CVE-2021-34527", "CVE-2017-11882", "CVE-2022-30190"],
            "T1059": ["CVE-2020-1472", "CVE-2022-30190"],
            "T1053": ["CVE-2019-1069", "CVE-2020-1472"],
            "T1569": ["CVE-2021-34527"],
            "T1204": ["CVE-2021-40444", "CVE-2017-0199"],

            # Persistence
            "T1547": ["CVE-2021-1732", "CVE-2020-0787"],
            "T1543": ["CVE-2021-1732", "CVE-2021-34527"],
            "T1574": ["CVE-2020-0787", "CVE-2021-33739"],
            "T1546": ["CVE-2021-34527", "CVE-2017-0199"],

            # Privilege Escalation
            "T1055": ["CVE-2020-1380", "CVE-2021-1732"],
            "T1068": ["CVE-2020-0787", "CVE-2021-34527", "CVE-2021-1732", "CVE-2021-33739"],
            "T1078": ["CVE-2021-42287", "CVE-2021-42278"],
            "T1134": ["CVE-2021-36934", "CVE-2020-1472"],

            # Defense Evasion
            "T1036": ["CVE-2020-1464"],
            "T1140": ["CVE-2018-0886"],
            "T1562": ["CVE-2021-34527", "CVE-2021-36934"],
            "T1070": ["CVE-2021-36934"],
            "T1112": ["CVE-2021-34527"],

            # Credential Access
            "T1110": ["CVE-2017-0143", "CVE-2019-0708"],
            "T1003": ["CVE-2020-1472", "CVE-2021-36934", "CVE-2021-42287"],
            "T1558": ["CVE-2021-42287", "CVE-2021-42278", "CVE-2020-1472"],
            "T1552": ["CVE-2021-36934"],
            "T1555": ["CVE-2021-36934"],

            # Discovery
            "T1087": ["CVE-2020-1472"],
            "T1482": ["CVE-2020-1472", "CVE-2021-42287"],
            "T1069": ["CVE-2020-1472"],
            "T1018": ["CVE-2017-0144"],

            # Lateral Movement
            "T1021": ["CVE-2020-1472", "CVE-2019-0708", "CVE-2021-34527"],
            "T1210": ["CVE-2017-0144", "CVE-2019-0708", "CVE-2020-0796"],
            "T1550": ["CVE-2021-42287", "CVE-2021-42278"],
            "T1563": ["CVE-2019-0708"],

            # Collection
            "T1560": ["CVE-2021-36934"],
            "T1005": ["CVE-2021-36934"],
            "T1114": ["CVE-2021-26855", "CVE-2021-34473"],

            # Command and Control
            "T1071": ["CVE-2021-44228"],
            "T1572": ["CVE-2020-1472"],
            "T1090": ["CVE-2021-44228"],
            "T1219": ["CVE-2019-11510", "CVE-2018-13379"],

            # Exfiltration
            "T1048": ["CVE-2021-26855"],
            "T1567": ["CVE-2021-26855", "CVE-2021-34473"],

            # Impact
            "T1486": ["CVE-2017-0144", "CVE-2021-34527", "CVE-2019-0708"],
            "T1490": ["CVE-2021-36934"],
            "T1489": ["CVE-2021-34527"],
            "T1491": ["CVE-2022-26134"],
        }

        return technique_cve_map.get(technique, [])

    def get_incidents(self, filter_type=None, filter_value=None):
        """Returns filtered list of incidents based on criteria"""
        if not filter_type or not filter_value or filter_type == "All":
            return self.incidents

        filtered = []
        for incident in self.incidents:
            if filter_type == "Date" and filter_value in incident["Date"]:
                filtered.append(incident)
            elif filter_type == "Incident" and filter_value.lower() in incident["Incident"].lower():
                filtered.append(incident)
            elif filter_type == "Action" and filter_value.lower() in incident["Action"].lower():
                filtered.append(incident)
            elif filter_type == "Workflow" and filter_value.lower() in incident["Workflow"].lower():
                filtered.append(incident)
            elif filter_type == "CVE" and filter_value.lower() in incident["CVE"].lower():
                filtered.append(incident)
            elif filter_type == "Severity" and filter_value.lower() in incident["Severity"].lower():
                filtered.append(incident)
        return filtered

    def sync_incidents(self):
        """Synchronizes incidents with Shuffle SOAR"""
        try:
            print("\n=== Starting Incident Sync ===")
            print(f"Configuration State:")
            print(f"- URL: {self.shuffle_url}")
            print(f"- API Key: {'Set' if self.shuffle_api_key else 'Not Set'}")
            print(f"- Workflows: {self.workflow_names}")
            print(f"- Configured: {self.is_configured}")

            if not self.is_configured:
                print("Configuration incomplete, attempting to reload...")
                if not self.reload_config():
                    print("Failed to load valid configuration")
                    return False

            # Ensure URL has protocol
            self.shuffle_url = self._ensure_url_protocol(self.shuffle_url)

            # Create new event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                # Validate connection
                connection_valid = loop.run_until_complete(self.validate_connection())
                if not connection_valid:
                    print("Failed to validate Shuffle connection")
                    return False

                # Fetch incidents
                shuffle_incidents = loop.run_until_complete(self.fetch_shuffle_incidents())
                if shuffle_incidents is None:
                    print("Failed to fetch incidents")
                    return False

                print(f"Successfully fetched {len(shuffle_incidents)} incidents")
                self.incidents = shuffle_incidents
                self.notify_observers()
                return True

            finally:
                loop.close()

        except Exception as e:
            print(f"Error in sync_incidents: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    def update_shuffle_config(self, url: str, api_key: str, workflow_names: List[str]) -> bool:
        """Updates Shuffle configuration with multiple workflows"""
        try:
            # Don't process the URL here - it should already be processed by the controller
            self.shuffle_url = url.strip()
            self.shuffle_api_key = api_key.strip()
            self.workflow_names = [name.strip() for name in workflow_names if name.strip()]
            self.workflow_ids = {}
            self.last_modified = datetime.now()

            self.is_configured = all([
                self.shuffle_url,
                self.shuffle_api_key
            ])

            print(f"Model configured with Shuffle URL: {self.shuffle_url}")
            return True
        except Exception as e:
            print(f"Error updating Shuffle config: {e}")
            return False

    def export_to_csv(self, filename="incident_history.csv"):
        """Exports incidents to a CSV file"""
        try:
            with open(filename, mode="w", newline="", encoding="utf-8") as file:
                fieldnames = ["Date", "Incident", "Action", "Workflow", "CVE", "Severity", "Details"]
                writer = csv.DictWriter(file, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(self.incidents)
            return True, f"Exported successfully to {filename}"
        except Exception as e:
            logging.error(f"Error exporting to CSV: {str(e)}")
            return False, f"Error exporting file: {str(e)}"

    def export_to_json(self, filename="incident_history.json"):
        """Exports incidents to a JSON file"""
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                json.dump(self.incidents, file, indent=2, ensure_ascii=False)
            return True, f"Exported successfully to {filename}"
        except Exception as e:
            logging.error(f"Error exporting to JSON: {str(e)}")
            return False, f"Error exporting file: {str(e)}"

    @classmethod
    def create_empty(cls) -> 'IncidentHistoryModel':
        """Creates a new instance with empty credentials"""
        return cls()

    @classmethod
    def load_from_file(cls, filepath: str) -> 'IncidentHistoryModel':
        """Loads configuration from file"""
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    config_data = json.load(f)

                    # Handle backward compatibility
                    workflow_names = config_data.get('workflow_names', [])
                    if not workflow_names and 'workflow_name' in config_data:
                        workflow_names = [config_data['workflow_name']]

                    instance = cls(
                        shuffle_url=config_data.get('shuffle_url', ''),
                        shuffle_api_key=config_data.get('shuffle_api_key', ''),
                        workflow_names=workflow_names,
                        last_modified=datetime.fromisoformat(
                            config_data.get('last_modified', datetime.now().isoformat())
                        )
                    )

                    instance.is_configured = bool(
                        instance.shuffle_url and
                        instance.shuffle_api_key
                    )

                    return instance

            return cls.create_empty()
        except Exception as e:
            print(f"Error loading Shuffle config: {e}")
            return cls.create_empty()

    def save_to_file(self, filepath: str = None) -> bool:
        """Saves current configuration to file"""
        try:
            if filepath is None:
                if sys.platform == "win32":
                    app_data = os.path.join(os.environ['APPDATA'], 'Guardian')
                else:
                    app_data = os.path.join(os.path.expanduser('~'), '.guardian')
                filepath = os.path.join(app_data, 'shuffle_config.json')

            os.makedirs(os.path.dirname(filepath), exist_ok=True)

            config_dict = {
                "shuffle_url": self.shuffle_url,
                "shuffle_api_key": self.shuffle_api_key,
                "workflow_names": self.workflow_names,
                "last_modified": self.last_modified.isoformat(),
                "is_configured": self.is_configured
            }

            with open(filepath, 'w') as f:
                json.dump(config_dict, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving Shuffle config: {e}")
            return False

    def validate_config(self):
        """Validates the current configuration"""
        if not all([self.shuffle_url, self.shuffle_api_key]):
            print("Missing required configuration parameters")
            return False

        # Ensure URL has protocol
        self.shuffle_url = self._ensure_url_protocol(self.shuffle_url)

        # Basic API key validation
        if len(self.shuffle_api_key) < 32:
            print("API key appears invalid")
            return False

        self.is_configured = True
        return True

    def reload_config(self):
        """Reloads configuration from file"""
        if sys.platform == "win32":
            app_data = os.path.join(os.environ['APPDATA'], 'Guardian')
        else:
            app_data = os.path.join(os.path.expanduser('~'), '.guardian')
        filepath = os.path.join(app_data, 'shuffle_config.json')

        loaded_config = self.load_from_file(filepath)
        if loaded_config and loaded_config.is_configured:
            self.shuffle_url = loaded_config.shuffle_url
            self.shuffle_api_key = loaded_config.shuffle_api_key
            self.workflow_names = loaded_config.workflow_names
            self.workflow_ids = {}
            self.is_configured = True
            return True
        return False

    def get_available_workflows(self):
        """Get list of available workflows from Shuffle"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            async def _fetch_workflows():
                url = self._ensure_url_protocol(self.shuffle_url)
                headers = {
                    "Authorization": f"Bearer {self.shuffle_api_key}",
                    "Content-Type": "application/json"
                }

                ssl_context = self._get_ssl_context() if url.startswith('https://') else None

                async with aiohttp.ClientSession() as session:
                    api_url = f"{url}/api/v1/workflows"
                    async with session.get(api_url, headers=headers, ssl=ssl_context) as response:
                        if response.status == 200:
                            workflows = await response.json()
                            return [w.get('name') for w in workflows if w.get('name')]
                        return []

            workflows = loop.run_until_complete(_fetch_workflows())
            loop.close()
            return workflows

        except Exception as e:
            print(f"Error fetching available workflows: {e}")
            return []

    def clear_incidents(self):
        """Clear all incidents from memory"""
        self.incidents = []
        self.notify_observers()

    def get_incident_count(self):
        """Get total number of incidents"""
        return len(self.incidents)

    def get_incident_stats(self):
        """Get statistics about incidents"""
        if not self.incidents:
            return {
                "total": 0,
                "with_cves": 0,
                "by_severity": {},
                "by_workflow": {}
            }

        stats = {
            "total": len(self.incidents),
            "with_cves": sum(1 for i in self.incidents if i.get("CVE")),
            "by_severity": {},
            "by_workflow": {}
        }

        for incident in self.incidents:
            # Count by severity
            severity = incident.get("Severity", "Unknown")
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

            # Count by workflow
            workflow = incident.get("Workflow", "Unknown")
            stats["by_workflow"][workflow] = stats["by_workflow"].get(workflow, 0) + 1

        return stats

    async def validate_connection(self) -> bool:
        """Validates the Shuffle connection and workflow names"""
        if not all([self.shuffle_url, self.shuffle_api_key]):
            print("Missing configuration parameters")
            return False

        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"Authorization": f"Bearer {self.shuffle_api_key}"}

                # URL should already have protocol
                api_url = f"{self.shuffle_url}/api/v1/workflows"
                print(f"Testing connection to: {api_url}")

                # Only use SSL context for HTTPS URLs
                ssl_context = None
                if self.shuffle_url.startswith('https://'):
                    ssl_context = self._get_ssl_context()

                async with session.get(api_url, headers=headers, ssl=ssl_context) as response:
                    print(f"Response status: {response.status}")
                    if response.status == 200:
                        workflows = await response.json()

                        if not self.workflow_names:
                            self.is_configured = True
                            print("Connection validation successful (no workflows selected)")
                            return True

                        available_workflows = {w.get('name') for w in workflows}
                        selected_workflows = set(self.workflow_names)
                        found_workflows = selected_workflows.intersection(available_workflows)

                        if found_workflows:
                            self.is_configured = True
                            print(
                                f"Connection validation successful. Found {len(found_workflows)} of {len(self.workflow_names)} workflows")
                            return True
                        else:
                            print(f"None of the selected workflows found: {self.workflow_names}")
                            return False
                    print(f"Connection failed: {await response.text()}")
                    return False
        except Exception as e:
            print(f"Validation error: {e}")
            return False
