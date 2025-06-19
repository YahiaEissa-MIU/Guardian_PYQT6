# controllers/incident_history_controller.py
from PyQt6.QtCore import QObject, pyqtSignal, QThread

from services.cve_enrichment_service import CVEEnrichmentService
from utils.config_manager import ConfigManager
from models.incident_history_model import IncidentHistoryModel
import asyncio
import aiohttp
import json
import csv
import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import logging
from pathlib import Path

class CVEFetchWorker(QThread):
    """Worker thread for fetching CVE details from NIST NVD API"""
    cve_fetched = pyqtSignal(str, dict)  # cve_id, cve_data

    def __init__(self, cve_id):
        super().__init__()
        self.cve_id = cve_id
        self.api_key = None  # Optional: Add your NVD API key for higher rate limits

    def run(self):
        """Fetch CVE details from NIST NVD API"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            cve_data = loop.run_until_complete(self.fetch_cve_from_nvd())
            self.cve_fetched.emit(self.cve_id, cve_data)
        except Exception as e:
            logging.error(f"Error fetching CVE {self.cve_id}: {e}")
            self.cve_fetched.emit(self.cve_id, {"error": str(e)})
        finally:
            loop.close()

    async def fetch_cve_from_nvd(self):
        """Fetch CVE details from NIST NVD API"""
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        headers = {
            "User-Agent": "Guardian-SOAR/1.0"
        }

        if self.api_key:
            headers["apiKey"] = self.api_key

        params = {
            "cveId": self.cve_id
        }

        async with aiohttp.ClientSession() as session:
            async with session.get(base_url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self.parse_nvd_response(data)
                else:
                    return {"error": f"API returned status {response.status}"}

    def parse_nvd_response(self, data):
        """Parse NVD API response"""
        try:
            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                return {"error": "No vulnerability data found"}

            cve = vulnerabilities[0].get('cve', {})

            # Extract description
            descriptions = cve.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d['lang'] == 'en'), 'No description available')

            # Extract CVSS scores
            metrics = cve.get('metrics', {})
            cvss_data = {}
            severity = 'Unknown'
            score = 'N/A'

            # Check for CVSS v3
            if 'cvssMetricV31' in metrics:
                cvss_v3 = metrics['cvssMetricV31'][0]
                cvss_data = cvss_v3.get('cvssData', {})
                severity = cvss_data.get('baseSeverity', 'Unknown')
                score = cvss_data.get('baseScore', 'N/A')
            elif 'cvssMetricV30' in metrics:
                cvss_v3 = metrics['cvssMetricV30'][0]
                cvss_data = cvss_v3.get('cvssData', {})
                severity = cvss_data.get('baseSeverity', 'Unknown')
                score = cvss_data.get('baseScore', 'N/A')
            elif 'cvssMetricV2' in metrics:
                cvss_v2 = metrics['cvssMetricV2'][0]
                cvss_data = cvss_v2.get('cvssData', {})
                score = cvss_data.get('baseScore', 'N/A')
                # Map v2 scores to severity
                if isinstance(score, (int, float)):
                    if score >= 7.0:
                        severity = 'HIGH'
                    elif score >= 4.0:
                        severity = 'MEDIUM'
                    else:
                        severity = 'LOW'

            # Extract references
            references = cve.get('references', [])

            # Extract affected products
            configurations = cve.get('configurations', [])
            affected_products = []
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        if cpe_match.get('vulnerable'):
                            affected_products.append(cpe_match.get('criteria', ''))

            return {
                'description': description,
                'severity': severity,
                'score': score,
                'cvss_data': cvss_data,
                'references': references[:5],  # Limit to 5 references
                'affected_products': affected_products[:10],  # Limit to 10 products
                'published': cve.get('published', 'Unknown'),
                'last_modified': cve.get('lastModified', 'Unknown')
            }

        except Exception as e:
            logging.error(f"Error parsing NVD response: {e}")
            return {"error": "Failed to parse response"}


class IncidentHistoryController(QObject):
    # Signals
    incidents_updated = pyqtSignal(list)
    cve_data_updated = pyqtSignal(str, dict)
    export_completed = pyqtSignal(str)  # success message
    export_failed = pyqtSignal(str)  # error message
    report_generated = pyqtSignal(str)  # file path
    status_updated = pyqtSignal(str)  # status message

    def __init__(self):
        super().__init__()
        self.config_manager = ConfigManager()
        self.model = None
        self.cve_workers = []

        try:
            # Get the incident model from config manager
            self.model = self.config_manager.incident_model

            # IMPORTANT: Register as observer to ConfigManager for Shuffle updates
            self.config_manager.add_shuffle_observer(self.on_config_updated)

            # Also register as observer to the model itself
            if self.model and hasattr(self.model, 'add_observer'):
                self.model.add_observer(self.on_model_changed)
                logging.info("IncidentHistoryController registered as observer")
            else:
                logging.warning("Incident history model not available or doesn't support observers")

        except Exception as e:
            logging.error(f"Error initializing incident history controller: {e}")

    def on_model_changed(self):
        """Handle model changes"""
        self.incidents_updated.emit(self.model.incidents)

    def refresh_incidents(self):
        """Refresh incidents from Shuffle"""
        if not self.model:
            self.status_updated.emit("disconnected")
            logging.error("No incident model available")
            return

        if not self.model.is_configured:
            self.status_updated.emit("disconnected")
            logging.error("Shuffle not configured")
            return

        self.status_updated.emit("connecting")

        # Create a worker function
        def worker():
            try:
                # Ensure the model has the latest config
                self.model = self.config_manager.incident_model

                if self.model and self.model.is_configured:
                    success = self.model.sync_incidents()
                    if success:
                        self.status_updated.emit("connected")
                        # Emit the updated incidents
                        self.incidents_updated.emit(self.model.incidents)
                    else:
                        self.status_updated.emit("disconnected")
                else:
                    self.status_updated.emit("disconnected")
            except Exception as e:
                logging.error(f"Error refreshing incidents: {e}")
                self.status_updated.emit("disconnected")

        # Create and start the thread
        self.refresh_thread = QThread()
        self.refresh_thread.run = worker
        self.refresh_thread.finished.connect(self.refresh_thread.deleteLater)
        self.refresh_thread.start()

    def _refresh_incidents_thread(self):
        """Thread function for refreshing incidents"""
        try:
            success = self.model.sync_incidents()
            if success:
                self.status_updated.emit("connected")
            else:
                self.status_updated.emit("disconnected")
        except Exception as e:
            logging.error(f"Error refreshing incidents: {e}")
            self.status_updated.emit("disconnected")

    def fetch_cve_details(self, cve_id):
        """Fetch CVE details from NIST NVD"""
        worker = CVEFetchWorker(cve_id)
        worker.cve_fetched.connect(self.on_cve_fetched)
        worker.finished.connect(lambda: self.cve_workers.remove(worker))
        self.cve_workers.append(worker)
        worker.start()

    def on_cve_fetched(self, cve_id, cve_data):
        """Handle fetched CVE data"""
        self.cve_data_updated.emit(cve_id, cve_data)

    def export_incidents(self, format_type, incidents):
        """Export incidents to specified format"""
        try:
            # Get the user's Downloads folder
            downloads_folder = str(Path.home() / "Downloads")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            if format_type == "csv":
                filename = os.path.join(downloads_folder, f"incident_history_{timestamp}.csv")
                self._export_to_csv(incidents, filename)
            elif format_type == "json":
                filename = os.path.join(downloads_folder, f"incident_history_{timestamp}.json")
                self._export_to_json(incidents, filename)
            else:
                raise ValueError(f"Unsupported format: {format_type}")

            self.export_completed.emit(f"Exported to {filename}")

        except Exception as e:
            logging.error(f"Export failed: {e}")
            self.export_failed.emit(str(e))

    def _export_to_csv(self, incidents, filename):
        """Export incidents to CSV format"""
        fieldnames = ["Date", "Incident", "Action", "Workflow", "CVE", "Severity", "Details"]

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(incidents)

    def _export_to_json(self, incidents, filename):
        """Export incidents to JSON format"""
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(incidents, jsonfile, indent=2, default=str)

    def generate_report(self, incidents):
        """Generate comprehensive PDF report"""
        try:
            # Check if incidents list is empty
            if not incidents:
                self.export_failed.emit("No incidents to generate report from")
                return

            # Get the user's Downloads folder
            downloads_folder = str(Path.home() / "Downloads")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(downloads_folder, f"incident_report_{timestamp}.pdf")

            # Create the PDF with error handling for each section
            doc = SimpleDocTemplate(
                filename,
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18,
            )

            # Container for the 'Flowable' objects
            elements = []

            # Define styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1976D2'),
                spaceAfter=30,
                alignment=1  # Center alignment
            )

            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#424242'),
                spaceAfter=12,
            )

            # Add title
            elements.append(Paragraph("Incident Response Report", title_style))
            elements.append(Spacer(1, 12))

            # Add metadata
            metadata_data = [
                ["Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
                ["Total Incidents:", str(len(incidents))],
                ["Date Range:", f"{min(inc['Date'] for inc in incidents)} to {max(inc['Date'] for inc in incidents)}"],
                ["Workflows:", ", ".join(set(inc.get('Workflow', 'Unknown') for inc in incidents))]
            ]

            metadata_table = Table(metadata_data, colWidths=[2 * inch, 4 * inch])
            metadata_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#666666')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))

            elements.append(metadata_table)
            elements.append(Spacer(1, 20))

            # Executive Summary
            elements.append(Paragraph("Executive Summary", heading_style))
            elements.append(Spacer(1, 12))

            summary_text = self._generate_executive_summary(incidents)
            elements.append(Paragraph(summary_text, styles['Normal']))
            elements.append(Spacer(1, 20))

            # Statistics
            elements.append(Paragraph("Incident Statistics", heading_style))
            elements.append(Spacer(1, 12))

            stats_table = self._generate_statistics_table(incidents)
            elements.append(stats_table)
            elements.append(Spacer(1, 20))

            # CVE Analysis
            cve_incidents = [inc for inc in incidents if inc.get('CVE')]
            if cve_incidents:
                elements.append(Paragraph("CVE Analysis", heading_style))
                elements.append(Spacer(1, 12))

                cve_table = self._generate_cve_table(cve_incidents)
                elements.append(cve_table)
                elements.append(PageBreak())

            # Detailed Incident List
            elements.append(Paragraph("Detailed Incident List", heading_style))
            elements.append(Spacer(1, 12))

            # Group incidents by severity
            critical_incidents = [inc for inc in incidents if inc.get('Severity') == 'CRITICAL']
            high_incidents = [inc for inc in incidents if inc.get('Severity') == 'HIGH']
            other_incidents = [inc for inc in incidents if inc.get('Severity') not in ['CRITICAL', 'HIGH']]

            if critical_incidents:
                elements.append(Paragraph("Critical Severity Incidents", styles['Heading3']))
                elements.append(self._generate_incident_table(critical_incidents, color=colors.red))
                elements.append(Spacer(1, 12))

            if high_incidents:
                elements.append(Paragraph("High Severity Incidents", styles['Heading3']))
                elements.append(self._generate_incident_table(high_incidents, color=colors.orange))
                elements.append(Spacer(1, 12))

            if other_incidents:
                elements.append(Paragraph("Other Incidents", styles['Heading3']))
                elements.append(self._generate_incident_table(other_incidents))
                elements.append(Spacer(1, 12))

            # Build PDF
            try:
                doc.build(elements)
                self.report_generated.emit(filename)
            except Exception as build_error:
                logging.error(f"PDF build failed: {build_error}")
                self.export_failed.emit(f"Failed to build PDF: {str(build_error)}")

        except Exception as e:
            logging.error(f"Report generation failed: {e}")
            self.export_failed.emit(f"Report generation failed: {str(e)}")

    def _generate_executive_summary(self, incidents):
        """Generate executive summary text"""
        total = len(incidents)
        workflows = set(inc.get('Workflow', 'Unknown') for inc in incidents)
        incident_types = {}
        severities = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'Unknown': 0}

        for inc in incidents:
            # Count incident types
            inc_type = inc.get('Incident', 'Unknown')
            incident_types[inc_type] = incident_types.get(inc_type, 0) + 1

            # Count severities
            severity = inc.get('Severity', 'Unknown')
            if severity in severities:
                severities[severity] += 1
            else:
                severities['Unknown'] += 1

        # Find most common incident type
        most_common_type = max(incident_types.items(), key=lambda x: x[1])[0] if incident_types else "Unknown"

        summary = f"""
        This report contains analysis of {total} security incidents processed across {len(workflows)} workflow(s). 
        The most common incident type was "{most_common_type}" accounting for {incident_types.get(most_common_type, 0)} incidents.

        Severity breakdown: {severities['CRITICAL']} Critical, {severities['HIGH']} High, 
        {severities['MEDIUM']} Medium, {severities['LOW']} Low, and {severities['Unknown']} Unknown severity incidents.

        {sum(1 for inc in incidents if inc.get('CVE'))} incidents were associated with known CVE vulnerabilities.
        """

        return summary.strip()

    def _generate_statistics_table(self, incidents):
        """Generate statistics table"""
        # Calculate statistics
        incident_types = {}
        actions = {}
        workflows = {}

        for inc in incidents:
            # Count by type
            inc_type = inc.get('Incident', 'Unknown')
            incident_types[inc_type] = incident_types.get(inc_type, 0) + 1

            # Count by action
            action = inc.get('Action', 'Unknown')
            actions[action] = actions.get(action, 0) + 1

            # Count by workflow
            workflow = inc.get('Workflow', 'Unknown')
            workflows[workflow] = workflows.get(workflow, 0) + 1

        # Create table data
        data = [['Category', 'Item', 'Count', 'Percentage']]

        # Add incident types
        total = len(incidents)
        for inc_type, count in sorted(incident_types.items(), key=lambda x: x[1], reverse=True)[:5]:
            percentage = f"{(count / total * 100):.1f}%"
            data.append(['Incident Type', inc_type, str(count), percentage])

        # Add top actions
        for action, count in sorted(actions.items(), key=lambda x: x[1], reverse=True)[:3]:
            percentage = f"{(count / total * 100):.1f}%"
            data.append(['Action Taken', action, str(count), percentage])

        # Add workflows
        for workflow, count in sorted(workflows.items(), key=lambda x: x[1], reverse=True):
            percentage = f"{(count / total * 100):.1f}%"
            data.append(['Workflow', workflow, str(count), percentage])

        # Create and style table
        table = Table(data, colWidths=[1.5 * inch, 2.5 * inch, 1 * inch, 1 * inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (2, 1), (-1, -1), 'CENTER'),
        ]))

        return table

    def _generate_cve_table(self, incidents):
        """Generate CVE analysis table"""
        cve_counts = {}
        cve_severities = {}

        for inc in incidents:
            cves = inc.get('CVE', '').split(', ')
            for cve in cves:
                if cve:
                    cve_counts[cve] = cve_counts.get(cve, 0) + 1
                    if inc.get('Severity') != 'Unknown':
                        cve_severities[cve] = inc.get('Severity', 'Unknown')

        # Sort by count
        sorted_cves = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        data = [['CVE ID', 'Occurrences', 'Severity']]
        for cve, count in sorted_cves:
            severity = cve_severities.get(cve, 'Unknown')
            data.append([cve, str(count), severity])

        table = Table(data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        # Color code severity cells
        for i, (_, _, severity) in enumerate(data[1:], 1):
            if severity == 'CRITICAL':
                table.setStyle(TableStyle([('BACKGROUND', (2, i), (2, i), colors.red)]))
            elif severity == 'HIGH':
                table.setStyle(TableStyle([('BACKGROUND', (2, i), (2, i), colors.orange)]))
            elif severity == 'MEDIUM':
                table.setStyle(TableStyle([('BACKGROUND', (2, i), (2, i), colors.yellow)]))
            elif severity == 'LOW':
                table.setStyle(TableStyle([('BACKGROUND', (2, i), (2, i), colors.green)]))

        return table

    def _generate_incident_table(self, incidents, color=None):
        """Generate incident detail table"""
        data = [['Date', 'Type', 'Action', 'CVE']]

        for inc in incidents[:20]:  # Limit to 20 per section
            data.append([
                inc.get('Date', '')[:16],  # Truncate time
                inc.get('Incident', '')[:30],  # Truncate long text
                inc.get('Action', '')[:30],
                inc.get('CVE', '')[:20]
            ])

        if len(incidents) > 20:
            data.append(['...', f'({len(incidents) - 20} more incidents)', '...', '...'])

        table = Table(data, colWidths=[1.5 * inch, 2 * inch, 2 * inch, 1.5 * inch])

        base_style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]

        if color:
            base_style.append(('BACKGROUND', (0, 1), (-1, -1), color.clone(alpha=0.1)))
        else:
            base_style.append(('BACKGROUND', (0, 1), (-1, -1), colors.beige))

        table.setStyle(TableStyle(base_style))

        return table

    async def enrich_and_process_alert(self, alert_data):
        enrichment_service = CVEEnrichmentService()
        enriched_alert = await enrichment_service.enrich_alert(alert_data)
        # Process enriched alert

    def cleanup(self):
        """Cleanup resources when controller is being destroyed"""
        try:
            # Stop any running threads
            if hasattr(self, 'refresh_thread') and self.refresh_thread.isRunning():
                self.refresh_thread.quit()
                self.refresh_thread.wait(1000)

            # Stop all CVE workers
            for worker in self.cve_workers:
                if worker.isRunning():
                    worker.quit()
                    worker.wait(1000)

            # Clear the workers list
            self.cve_workers.clear()

            # Remove observer from model
            if self.model:
                self.model.remove_observer(self.on_model_changed)

        except Exception as e:
            logging.error(f"Error during controller cleanup: {e}")

    def on_config_updated(self, new_model):
        """Handle configuration updates from ConfigManager"""
        print("IncidentHistoryController: Config updated, refreshing model")

        # Remove observer from old model if exists
        if self.model and hasattr(self.model, 'remove_observer'):
            self.model.remove_observer(self.on_model_changed)

        # Update the model reference
        self.model = new_model

        # Register as observer to the new model
        if self.model and hasattr(self.model, 'add_observer'):
            self.model.add_observer(self.on_model_changed)

        # Clear and update the view
        self.incidents_updated.emit([])  # Clear existing incidents

        # If the model is configured, you might want to auto-refresh
        if self.model and self.model.is_configured:
            print("New model is configured, consider refreshing incidents")
            self.refresh_incidents()

    def get_filtered_incidents(self, filter_type=None, filter_value=None):
        """Get filtered incidents from the model"""
        if not self.model:
            return []

        return self.model.get_incidents(filter_type, filter_value)

