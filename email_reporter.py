"""
Email reporting module for sending alerts to CERT-In
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime
from typing import List, Dict
import logging
from config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailReporter:
    """Send email reports to CERT-In"""
    
    def __init__(self):
        self.smtp_server = settings.smtp_server
        self.smtp_port = settings.smtp_port
        self.sender_email = settings.smtp_email
        self.sender_password = settings.smtp_password
        self.cert_in_email = settings.cert_in_email
    
    def send_sensitive_data_report(self, scan_results: Dict, detections: List[Dict]) -> bool:
        """
        Send sensitive data exposure report to CERT-In
        
        Args:
            scan_results: Scan metadata
            detections: List of detected leaks
        
        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            # Create email
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.cert_in_email
            msg['Subject'] = f"[URGENT] Sensitive Data Exposure Detected on .gov.in Domain - {datetime.now().strftime('%Y-%m-%d')}"
            
            # Create email body
            body = self._create_sensitive_data_email_body(scan_results, detections)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            logger.info(f"📧 Sending report to {self.cert_in_email}...")
            self._send_email(msg)
            logger.info("✅ Email sent successfully!")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Email sending failed: {str(e)}")
            return False
    
    def _create_sensitive_data_email_body(self, scan_results: Dict, detections: List[Dict]) -> str:
        """Create HTML email body for sensitive data report"""
        
        # Group detections by data type
        grouped = {}
        for detection in detections:
            data_type = detection['data_type']
            if data_type not in grouped:
                grouped[data_type] = []
            grouped[data_type].append(detection)
        
        # Calculate statistics
        total_files = len(set(d['file_url'] for d in detections))
        total_detections = len(detections)
        avg_confidence = sum(d['confidence'] for d in detections) / len(detections) if detections else 0
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .header {{ background-color: #d32f2f; color: white; padding: 20px; }}
                .content {{ padding: 20px; }}
                .alert {{ background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }}
                .stats {{ background-color: #f5f5f5; padding: 15px; margin: 20px 0; }}
                .detection {{ background-color: #ffffff; border: 1px solid #ddd; padding: 10px; margin: 10px 0; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #f5f5f5; font-weight: bold; }}
                .high-confidence {{ color: #d32f2f; font-weight: bold; }}
                .medium-confidence {{ color: #ff9800; }}
                .footer {{ background-color: #f5f5f5; padding: 20px; margin-top: 30px; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 URGENT: Sensitive Data Exposure Detected</h1>
                <p>Automated Security Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="content">
                <div class="alert">
                    <strong>⚠️ CRITICAL SECURITY INCIDENT</strong><br>
                    Our automated scanning system has detected sensitive personal data publicly exposed on Indian government (.gov.in) domains.
                    Immediate action is required to protect citizen privacy and prevent potential misuse.
                </div>
                
                <div class="stats">
                    <h2>📊 Executive Summary</h2>
                    <ul>
                        <li><strong>Total Files Affected:</strong> {total_files}</li>
                        <li><strong>Total Data Instances Detected:</strong> {total_detections}</li>
                        <li><strong>Average Confidence Score:</strong> {avg_confidence:.1f}%</li>
                        <li><strong>Scan Duration:</strong> {scan_results.get('duration', 'N/A')}</li>
                        <li><strong>Detection Method:</strong> Automated Google Dorking + Pattern Matching</li>
                    </ul>
                </div>
                
                <h2>🔍 Detailed Findings</h2>
        """
        
        # Add detections grouped by type
        for data_type, items in grouped.items():
            data_type_name = data_type.replace('_', ' ').title()
            html += f"""
                <h3>📌 {data_type_name} ({len(items)} instances)</h3>
                <table>
                    <tr>
                        <th>File URL</th>
                        <th>Confidence</th>
                        <th>Evidence (Anonymized)</th>
                    </tr>
            """
            
            for item in items[:10]:  # Limit to first 10 per type
                confidence_class = "high-confidence" if item['confidence'] >= 80 else "medium-confidence"
                html += f"""
                    <tr>
                        <td><a href="{item['file_url']}">{item['file_url'][:80]}...</a></td>
                        <td class="{confidence_class}">{item['confidence']:.1f}%</td>
                        <td>{item['evidence'][:100]}...</td>
                    </tr>
                """
            
            if len(items) > 10:
                html += f"<tr><td colspan='3'><em>... and {len(items) - 10} more instances</em></td></tr>"
            
            html += "</table>"
        
        # Add recommendations
        html += """
                <h2>✅ Recommended Actions</h2>
                <ol>
                    <li><strong>Immediate:</strong> Take down or restrict access to affected files</li>
                    <li><strong>Short-term:</strong> Notify affected individuals and organizations</li>
                    <li><strong>Long-term:</strong> Implement automated scanning and data protection policies</li>
                    <li><strong>Prevention:</strong> Conduct security awareness training for content publishers</li>
                </ol>
                
                <div class="alert">
                    <strong>⏰ URGENCY LEVEL: HIGH</strong><br>
                    This data is currently indexed by search engines and publicly accessible. 
                    Immediate remediation is critical to prevent identity theft and fraud.
                </div>
            </div>
            
            <div class="footer">
                <p><strong>Report Generated By:</strong> Automated Sensitive Data & Spoofing Detection Framework</p>
                <p><strong>Detection Methodology:</strong> Google Custom Search API + Multi-stage Pattern Validation</p>
                <p><strong>Compliance:</strong> Responsible Disclosure Guidelines, Indian Cybersecurity Laws</p>
                <p><em>This is an automated report. For questions or clarifications, please contact the system administrator.</em></p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def send_government_impersonation_report(self, scan_id: int, findings: List[Dict]) -> bool:
        """Send government impersonation detection report to CERT-In"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.cert_in_email
            msg['Subject'] = f"[URGENT] Government Impersonation Sites Detected - Scan {scan_id} - {datetime.now().strftime('%Y-%m-%d')}"
            body = self._create_gids_email_body(scan_id, findings)
            msg.attach(MIMEText(body, 'html'))
            logger.info(f"📧 Sending GIDS report to {self.cert_in_email}...")
            self._send_email(msg)
            logger.info("✅ GIDS email sent successfully!")
            return True
        except Exception as e:
            logger.error(f"❌ GIDS email sending failed: {str(e)}")
            return False

    def _create_gids_email_body(self, scan_id: int, findings: List[Dict]) -> str:
        """Create HTML email body for government impersonation report"""
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings:
            rl = f.get('risk_level', 'MEDIUM')
            risk_counts[rl] = risk_counts.get(rl, 0) + 1

        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .header {{ background-color: #1a237e; color: white; padding: 20px; }}
                .content {{ padding: 20px; }}
                .alert {{ background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }}
                .stats {{ background-color: #f5f5f5; padding: 15px; margin: 20px 0; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #f5f5f5; font-weight: bold; }}
                .critical {{ color: #d32f2f; font-weight: bold; }}
                .high {{ color: #e65100; font-weight: bold; }}
                .medium {{ color: #f57f17; }}
                .footer {{ background-color: #f5f5f5; padding: 20px; margin-top: 30px; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 URGENT: Government Impersonation Sites Detected</h1>
                <p>Automated Security Scan Report — Scan #{scan_id} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            <div class="content">
                <div class="alert">
                    <strong>⚠️ CRITICAL SECURITY INCIDENT</strong><br>
                    Our automated scanning system has detected websites impersonating Indian government services.
                    These sites may be phishing portals targeting Indian citizens' personal data.
                </div>
                <div class="stats">
                    <h2>📊 Risk Summary</h2>
                    <ul>
                        <li><strong>Total Threats Reported:</strong> {len(findings)}</li>
                        <li><strong>Critical:</strong> {risk_counts['CRITICAL']}</li>
                        <li><strong>High:</strong> {risk_counts['HIGH']}</li>
                        <li><strong>Medium:</strong> {risk_counts['MEDIUM']}</li>
                        <li><strong>Low:</strong> {risk_counts['LOW']}</li>
                    </ul>
                </div>
                <h2>🔍 Detected Impersonation Sites</h2>
                <table>
                    <tr>
                        <th>Service Impersonated</th>
                        <th>Domain</th>
                        <th>Risk Level</th>
                        <th>Confidence</th>
                        <th>Threat Details</th>
                    </tr>
        """
        for finding in findings:
            risk = finding.get('risk_level', 'MEDIUM')
            risk_class = risk.lower() if risk in ('CRITICAL', 'HIGH', 'MEDIUM') else ''
            conf = finding.get('confidence', 0)
            html += f"""
                    <tr>
                        <td>{finding.get('impersonation_type', '').replace('_', ' ').title()}</td>
                        <td><a href="{finding.get('url', '')}">{finding.get('domain', '')}</a></td>
                        <td class="{risk_class}">{risk}</td>
                        <td>{conf:.1f}%</td>
                        <td>{(finding.get('threat_details', '') or '')[:150]}</td>
                    </tr>
            """
        html += """
                </table>
                <h2>✅ Recommended Actions</h2>
                <ol>
                    <li><strong>Immediate:</strong> Report these domains to ISPs and registrars for takedown</li>
                    <li><strong>Short-term:</strong> Issue a public advisory warning citizens about phishing sites</li>
                    <li><strong>Long-term:</strong> Implement DMARC/DNSBL policies to block impersonating domains</li>
                </ol>
            </div>
            <div class="footer">
                <p><strong>Report Generated By:</strong> Automated Sensitive Data &amp; Spoofing Detection Framework</p>
                <p><em>This is a manually triggered report. For questions, contact the system administrator.</em></p>
            </div>
        </body>
        </html>
        """
        return html

    def _send_email(self, msg: MIMEMultipart):
        """Send email via SMTP"""
        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            server.send_message(msg)
    
    def send_test_email(self) -> bool:
        """Send a test email to verify configuration"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.sender_email  # Send to self
            msg['Subject'] = "Test Email - Cybersecurity Detection Framework"
            
            body = """
            <html>
            <body>
                <h2>✅ Email Configuration Test</h2>
                <p>This is a test email from the Automated Sensitive Data & Spoofing Detection Framework.</p>
                <p>If you received this email, your SMTP configuration is working correctly.</p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            self._send_email(msg)
            
            logger.info("✅ Test email sent successfully!")
            return True
            
        except Exception as e:
            logger.error(f"❌ Test email failed: {str(e)}")
            return False
