"""
Advanced Memory Analysis Widget
Provides comprehensive memory forensics analysis with progress tracking and detailed reporting
"""

import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


class AnalysisWorker(QThread):
    """Worker thread for running memory analysis"""

    progress_signal = pyqtSignal(str, int, int)  # message, current, total
    result_signal = pyqtSignal(dict)  # analysis results
    error_signal = pyqtSignal(str)  # error message
    ip_check_signal = pyqtSignal(str, int, int)  # ip, current, total

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")
        self.volatility_output_cache = {}

    def run(self):
        try:
            if not self.api_key:
                self.error_signal.emit(
                    "ABUSEIPDB_API_KEY environment variable not set. Please set it in your .env file."
                )
                return

            # Run Volatility plugins
            self.progress_signal.emit("Running Volatility plugins...", 0, 100)
            results = self.run_all_plugins()

            if not results:
                self.error_signal.emit(
                    "Could not retrieve any process data from the memory image."
                )
                return

            # Build PID to name mapping
            pid_to_name = {
                pid: proc_data["windows.pslist.PsList"][0].get("ImageFileName", "N/A")
                for pid, proc_data in results.items()
                if "windows.pslist.PsList" in proc_data
            }
            pid_to_name[4] = "System"

            # Initialize suspicious processes tracking
            suspicious_pids = defaultdict(lambda: {"Info": {}, "Reasons": []})

            # Analyze parent processes
            self.progress_signal.emit(
                "Analyzing parent process relationships...", 20, 100
            )
            self.analyze_parent_processes(results, pid_to_name, suspicious_pids)

            # Analyze network connections
            self.progress_signal.emit("Analyzing network connections...", 40, 100)
            self.analyze_network_connections(results, pid_to_name, suspicious_pids)

            # Prepare final results
            self.progress_signal.emit("Generating analysis report...", 90, 100)
            analysis_results = {
                "suspicious_processes": dict(suspicious_pids),
                "pid_to_name": pid_to_name,
                "raw_results": results,
                "total_processes": len(pid_to_name),
                "suspicious_count": len(suspicious_pids),
                "analysis_timestamp": datetime.now().isoformat(),
                "file_path": self.file_path,
            }

            self.progress_signal.emit("Analysis complete!", 100, 100)
            self.result_signal.emit(analysis_results)

        except Exception as e:
            self.error_signal.emit(f"Analysis failed: {str(e)}")

    def run_volatility_plugin(self, plugin_name: str):
        """Run a single Volatility plugin"""
        if plugin_name in self.volatility_output_cache:
            return self.volatility_output_cache[plugin_name]

        try:
            command = ["vol", "-f", self.file_path, "--renderer", "json", plugin_name]
            creationflags = (
                subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                creationflags=creationflags,
            )

            if not result.stdout:
                raise ValueError("Volatility produced no output.")

            parsed_json = json.loads(result.stdout)
            self.volatility_output_cache[plugin_name] = parsed_json
            return parsed_json

        except FileNotFoundError:
            raise Exception(
                "The 'vol' command was not found. Is Volatility 3 installed and in your PATH?"
            )
        except subprocess.CalledProcessError as e:
            raise Exception(
                f"Volatility failed with exit code {e.returncode}. Stderr: {e.stderr}"
            )
        except (json.JSONDecodeError, ValueError) as e:
            raise Exception(f"Failed to parse Volatility output. Error: {e}")

    def run_all_plugins(self):
        """Run all required Volatility plugins"""
        plugin_map = {
            "Process List": "windows.pslist.PsList",
            "Network Connections": "windows.netscan.NetScan",
        }

        results = defaultdict(lambda: defaultdict(list))
        for option, plugin_name in plugin_map.items():
            data = self.run_volatility_plugin(plugin_name)
            if data:
                for row in data:
                    if "PID" in row:
                        results[row["PID"]][plugin_name].append(row)
        return results

    def analyze_parent_processes(self, results, pid_to_name, suspicious_pids):
        """Analyze parent-child process relationships for anomalies"""
        expected_parents = {
            "smss.exe": "System",
            "csrss.exe": "smss.exe",
            "wininit.exe": "smss.exe",
            "services.exe": "wininit.exe",
            "lsass.exe": "wininit.exe",
            "winlogon.exe": "smss.exe",
            "svchost.exe": "services.exe",
            "explorer.exe": "userinit.exe",
        }
        suspicious_parents = {
            "cmd.exe",
            "powershell.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        }

        for pid, proc_data in results.items():
            if "windows.pslist.PsList" in proc_data:
                proc_info = proc_data["windows.pslist.PsList"][0]
                name = proc_info.get("ImageFileName", "N/A")
                ppid = proc_info.get("PPID", "N/A")
                parent_name = pid_to_name.get(ppid)

                if ppid is not None and ppid != 0 and parent_name is None:
                    parent_name_for_report = "Unknown (Parent PID not in list)"
                    reason = f"Orphaned process. Parent with PID {ppid} is not in the process list."
                    suspicious_pids[pid]["Info"] = {
                        "PID": pid,
                        "Name": name,
                        "PPID": ppid,
                        "Parent Name": parent_name_for_report,
                    }
                    suspicious_pids[pid]["Reasons"].append(reason)
                elif parent_name is None:
                    parent_name = "N/A"

                if name in expected_parents and parent_name != expected_parents[name]:
                    reason = f"Unexpected parent. Expected: '{expected_parents[name]}', Found: '{parent_name}'"
                    suspicious_pids[pid]["Info"] = {
                        "PID": pid,
                        "Name": name,
                        "PPID": ppid,
                        "Parent Name": parent_name,
                    }
                    suspicious_pids[pid]["Reasons"].append(reason)

                if parent_name in suspicious_parents:
                    reason = f"Spawned by a suspicious parent: '{parent_name}'"
                    suspicious_pids[pid]["Info"] = {
                        "PID": pid,
                        "Name": name,
                        "PPID": ppid,
                        "Parent Name": parent_name,
                    }
                    suspicious_pids[pid]["Reasons"].append(reason)

    def is_valid_ip(self, ip):
        """Validate if the input is a valid, globally routable IP address"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_global and not ip_obj.is_multicast
        except ValueError:
            return False

    def check_ip_abuseipdb(self, ip, confidence_threshold=90):
        """Check an IP using AbuseIPDB"""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": self.api_key}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}

        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)

            if score >= confidence_threshold:
                total_reports = data.get("totalReports", 0)
                isp = data.get("isp", "N/A")
                return {"score": score, "reports": total_reports, "isp": isp}

            return None
        except requests.RequestException as e:
            print(f"Error querying AbuseIPDB for IP {ip}: {e}")
            return None

    def analyze_network_connections(self, results, pid_to_name, suspicious_pids):
        """Analyze network connections for connections to malicious IPs"""
        unique_foreign_ips = set()
        pid_to_foreign_ips = defaultdict(list)

        # Collect foreign IPs
        for pid, proc_data in results.items():
            if "windows.netscan.NetScan" in proc_data:
                for conn in proc_data["windows.netscan.NetScan"]:
                    foreign_addr = conn.get("ForeignAddr")
                    if not foreign_addr or foreign_addr == "*":
                        continue

                    ip_part = ""
                    if foreign_addr.startswith("["):
                        ip_part = foreign_addr.split("]")[0][1:]
                    else:
                        ip_part = foreign_addr.rsplit(":", 1)[0]

                    if self.is_valid_ip(ip_part):
                        unique_foreign_ips.add(ip_part)
                        pid_to_foreign_ips[pid].append(ip_part)

        if not unique_foreign_ips:
            return

        total_ips = len(unique_foreign_ips)
        malicious_ip_details = {}
        checked_count = 0

        # Check each IP against AbuseIPDB
        for ip in sorted(list(unique_foreign_ips)):
            checked_count += 1
            self.ip_check_signal.emit(ip, checked_count, total_ips)

            details = self.check_ip_abuseipdb(ip)
            if details:
                malicious_ip_details[ip] = details

        # Update suspicious processes with malicious IP connections
        if malicious_ip_details:
            for pid, ips in pid_to_foreign_ips.items():
                for ip in ips:
                    if ip in malicious_ip_details:
                        details = malicious_ip_details[ip]
                        name = pid_to_name.get(pid, "N/A")
                        ppid = results[pid]["windows.pslist.PsList"][0].get(
                            "PPID", "N/A"
                        )
                        parent_name = pid_to_name.get(ppid, "Unknown")
                        reason = (
                            f"Connection to malicious IP: {ip} "
                            f"(Score: {details['score']}, Reports: {details['reports']})"
                        )
                        suspicious_pids[pid]["Info"] = {
                            "PID": pid,
                            "Name": name,
                            "PPID": ppid,
                            "Parent Name": parent_name,
                        }
                        suspicious_pids[pid]["Reasons"].append(reason)


class AnalysisWidget(QWidget):
    """Main analysis widget with progress tracking and detailed reporting"""

    def __init__(self, file_path: str = None):
        super().__init__()
        self.file_path = file_path
        self.analysis_worker = None
        self.analysis_results = None
        self.setup_ui()

    def setup_ui(self):
        """Setup the analysis UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 10)
        layout.setSpacing(3)

        # Title
        title = QLabel("Advanced Memory Analysis")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #1C1C1E; margin: 0px;")
        layout.addWidget(title)


        # Control buttons
        button_layout = QHBoxLayout()

        self.start_analysis_btn = QPushButton("Start Analysis")
        self.start_analysis_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #007AFF;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 13px;
                font-weight: 500;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #0056CC;
            }
            QPushButton:disabled {
                background-color: #8E8E93;
            }
        """
        )
        self.start_analysis_btn.clicked.connect(self.start_analysis)

        self.download_pdf_btn = QPushButton("Download PDF")
        self.download_pdf_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #8E8E93;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 13px;
                font-weight: 500;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #6D6D70;
            }
            QPushButton:disabled {
                background-color: #C7C7CC;
            }
        """
        )
        self.download_pdf_btn.clicked.connect(self.download_pdf_report)
        self.download_pdf_btn.setEnabled(False)

        self.clear_btn = QPushButton("Clear Results")
        self.clear_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #FF3B30;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 13px;
                font-weight: 500;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #D70015;
            }
        """
        )
        self.clear_btn.clicked.connect(self.clear_results)

        button_layout.addWidget(self.start_analysis_btn)
        button_layout.addWidget(self.download_pdf_btn)
        button_layout.addWidget(self.clear_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        # Progress section
        progress_frame = QFrame()
        progress_frame.setStyleSheet(
            """
            QFrame {
                background-color: #F2F2F7;
                border: 1px solid #C7C7CC;
                border-radius: 8px;
                padding: 2px;
            }
        """
        )
        progress_layout = QVBoxLayout(progress_frame)

        self.progress_label = QLabel("Ready to start analysis...")
        self.progress_label.setStyleSheet("font-weight: 500; color: #1C1C1E; font-size: 14px;")

        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet(
            """
            QProgressBar {
                border: 1px solid #C7C7CC;
                border-radius: 4px;
                text-align: center;
                font-weight: 500;
                background-color: #F2F2F7;
            }
            QProgressBar::chunk {
                background-color: #007AFF;
                border-radius: 3px;
            }
        """
        )
        self.progress_bar.setVisible(False)

        self.ip_check_label = QLabel("")
        self.ip_check_label.setStyleSheet("color: #666; font-family: monospace;")
        self.ip_check_label.setVisible(False)

        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.ip_check_label)
        layout.addWidget(progress_frame)

        # Results section
        results_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Summary panel
        summary_frame = QFrame()
        summary_frame.setStyleSheet(
            """
            QFrame {
                background-color: #F2F2F7;
                border: 1px solid #C7C7CC;
                border-radius: 8px;
                padding: 4px;
            }
        """
        )
        summary_layout = QVBoxLayout(summary_frame)

        summary_title = QLabel("Analysis Summary")
        summary_title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        summary_title.setStyleSheet("color: #1C1C1E; margin: 0px;")
        summary_layout.addWidget(summary_title)

        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setStyleSheet(
            """
            QTextEdit {
                background-color: white;
                border: 1px solid #C7C7CC;
                border-radius: 6px;
                padding: 8px;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                font-size: 13px;
                line-height: 1.4;
            }
        """
        )
        summary_layout.addWidget(self.summary_text)

        # Detailed report panel
        report_frame = QFrame()
        report_frame.setStyleSheet(
            """
            QFrame {
                background-color: #F2F2F7;
                border: 1px solid #C7C7CC;
                border-radius: 8px;
                padding: 4px;
            }
        """
        )
        report_layout = QVBoxLayout(report_frame)

        report_title = QLabel("Detailed Analysis Report")
        report_title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        report_title.setStyleSheet("color: #1C1C1E; margin: 0px;")
        report_layout.addWidget(report_title)

        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        self.report_text.setStyleSheet(
            """
            QTextEdit {
                background-color: white;
                border: 1px solid #C7C7CC;
                border-radius: 6px;
                padding: 10px;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                font-size: 14px;
                line-height: 1.5;
            }
        """
        )
        report_layout.addWidget(self.report_text)

        results_splitter.addWidget(summary_frame)
        results_splitter.addWidget(report_frame)
        results_splitter.setSizes([250, 1000])
        self.report_text.setMinimumHeight(600)
        self.setMinimumSize(1000, 850)

        layout.addWidget(results_splitter)

        # Initialize with welcome message
        self.show_welcome_message()


    def show_welcome_message(self):
        """Show welcome message and instructions"""
        welcome_text = """
Advanced Memory Analysis Tool

This tool performs comprehensive analysis of memory dumps including:

• Process relationship analysis
• Network connection monitoring  
• Malicious IP detection via AbuseIPDB
• Suspicious activity identification

Click 'Start Analysis' to begin the analysis process.
        """
        self.summary_text.setPlainText(welcome_text)
        self.report_text.setPlainText(
            "Detailed report will appear here after analysis is complete."
        )

    def start_analysis(self):
        """Start the analysis process"""
        if not self.file_path:
            QMessageBox.warning(
                self, "No File", "Please open a memory image file first."
            )
            return

        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            QMessageBox.warning(
                self,
                "API Key Required",
                "Please set ABUSEIPDB_API_KEY in your .env file.",
            )
            return

        # Disable start button and show progress
        self.start_analysis_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.ip_check_label.setVisible(True)

        # Start analysis worker
        self.analysis_worker = AnalysisWorker(self.file_path)
        self.analysis_worker.progress_signal.connect(self.update_progress)
        self.analysis_worker.ip_check_signal.connect(self.update_ip_check)
        self.analysis_worker.result_signal.connect(self.on_analysis_complete)
        self.analysis_worker.error_signal.connect(self.on_analysis_error)
        self.analysis_worker.start()

    def update_progress(self, message: str, current: int, total: int):
        """Update progress display"""
        self.progress_label.setText(message)
        if total > 0:
            progress = int((current / total) * 100)
            self.progress_bar.setValue(progress)

    def update_ip_check(self, ip: str, current: int, total: int):
        """Update IP checking progress"""
        self.ip_check_label.setText(f"  -> Checking {current}/{total}: {ip.ljust(45)}")
        self.ip_check_label.setVisible(True)

    def on_analysis_complete(self, results: dict):
        """Handle analysis completion"""
        self.analysis_results = results
        self.start_analysis_btn.setEnabled(True)
        self.download_pdf_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.ip_check_label.setVisible(False)

        # Update summary
        self.update_summary(results)

        # Update detailed report
        self.update_detailed_report(results)

        self.progress_label.setText("Analysis complete!")
        self.progress_label.setStyleSheet("font-weight: 500; color: #34C759; font-size: 14px;")

    def on_analysis_error(self, error_message: str):
        """Handle analysis errors"""
        self.start_analysis_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.ip_check_label.setVisible(False)

        self.progress_label.setText(f"Analysis failed: {error_message}")
        self.progress_label.setStyleSheet("font-weight: 500; color: #FF3B30; font-size: 14px;")

        QMessageBox.critical(self, "Analysis Error", error_message)

    def update_summary(self, results: dict):
        """Update analysis summary"""
        suspicious_count = results.get("suspicious_count", 0)
        total_processes = results.get("total_processes", 0)

        summary = f"""
📊 ANALYSIS SUMMARY

Total Processes Analyzed: {total_processes}
Suspicious Processes Found: {suspicious_count}
Analysis Status: {'⚠️ SUSPICIOUS ACTIVITY DETECTED' if suspicious_count > 0 else '✅ No suspicious activity detected'}

"""

        if suspicious_count > 0:
            summary += f"""
🚨 SECURITY ALERTS:
• {suspicious_count} processes flagged as suspicious
• Review detailed results below for specific threats
• Consider immediate investigation of flagged processes

"""
        else:
            summary += """
✅ SECURITY STATUS:
• No suspicious processes detected
• System appears clean based on current analysis
• Continue monitoring for any changes

"""

        self.summary_text.setPlainText(summary)

    def download_pdf_report(self):
        """Download analysis results as a PDF report"""
        if not self.analysis_results:
            QMessageBox.warning(
                self,
                "No Results",
                "Please run analysis first before downloading report.",
            )
            return

        # Get save location
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save PDF Report",
            f"memory_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            "PDF Files (*.pdf)",
        )

        if not file_path:
            return

        try:
            self.generate_pdf_report(file_path, self.analysis_results)
            QMessageBox.information(
                self, "Success", f"PDF report saved to: {file_path}"
            )
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to generate PDF report: {str(e)}"
            )

    def generate_pdf_report(self, file_path: str, results: dict):
        """Generate a well-formatted PDF report"""
        doc = SimpleDocTemplate(file_path, pagesize=A4)
        story = []

        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue,
        )

        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue,
        )

        normal_style = ParagraphStyle(
            "CustomNormal", parent=styles["Normal"], fontSize=12, spaceAfter=6
        )

        # Title
        story.append(Paragraph("Memory Forensics Analysis Report", title_style))
        story.append(Spacer(1, 20))

        # Report metadata
        story.append(Paragraph("Report Information", heading_style))
        metadata_data = [
            ["Analysis Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Memory File:", results.get("file_path", "N/A")],
            ["Total Processes:", str(results.get("total_processes", 0))],
            ["Suspicious Processes:", str(results.get("suspicious_count", 0))],
            ["Analysis Status:", "COMPLETED"],
        ]

        metadata_table = Table(metadata_data, colWidths=[2 * inch, 4 * inch])
        metadata_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                    ("BACKGROUND", (1, 0), (1, -1), colors.beige),
                ]
            )
        )
        story.append(metadata_table)
        story.append(Spacer(1, 20))

        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        suspicious_count = results.get("suspicious_count", 0)
        total_processes = results.get("total_processes", 0)

        if suspicious_count > 0:
            summary_text = f"""
            <b>SECURITY ALERT:</b> {suspicious_count} suspicious processes detected out of {total_processes} total processes analyzed.
            
            This indicates potential malicious activity in the memory dump. Immediate investigation is recommended.
            """
        else:
            summary_text = f"""
            <b>SECURITY STATUS:</b> No suspicious processes detected out of {total_processes} total processes analyzed.
            
            The system appears clean based on the current analysis. Continue monitoring for any changes.
            """

        story.append(Paragraph(summary_text, normal_style))
        story.append(Spacer(1, 20))

        # Detailed Findings
        suspicious_processes = results.get("suspicious_processes", {})
        if suspicious_processes:
            story.append(Paragraph("Detailed Findings", heading_style))

            for pid, data in suspicious_processes.items():
                info = data.get("Info", {})
                reasons = data.get("Reasons", [])

                # Process header
                process_title = f"Process ID: {pid} - {info.get('Name', 'Unknown')}"
                story.append(Paragraph(process_title, heading_style))

                # Process details
                details_data = [
                    ["Process Name:", info.get("Name", "N/A")],
                    ["Parent PID:", str(info.get("PPID", "N/A"))],
                    ["Parent Name:", info.get("Parent Name", "N/A")],
                ]

                details_table = Table(details_data, colWidths=[1.5 * inch, 4 * inch])
                details_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                            ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                            ("FONTSIZE", (0, 0), (-1, -1), 10),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                        ]
                    )
                )
                story.append(details_table)

                # Reasons
                story.append(Paragraph("<b>Security Concerns:</b>", normal_style))
                for i, reason in enumerate(reasons, 1):
                    story.append(Paragraph(f"{i}. {reason}", normal_style))

                story.append(Spacer(1, 15))
        else:
            story.append(Paragraph("No Suspicious Activity Detected", heading_style))
            story.append(
                Paragraph(
                    "The analysis did not identify any suspicious processes or network connections.",
                    normal_style,
                )
            )

        # Recommendations
        story.append(Paragraph("Recommendations", heading_style))
        if suspicious_count > 0:
            recommendations = """
            <b>Immediate Actions:</b>
            <br/>• Investigate flagged processes immediately
            <br/>• Check for persistence mechanisms
            <br/>• Review network connections and firewall logs
            <br/>• Consider system isolation if critical threats are found
            <br/>• Document all findings for incident response
            """
        else:
            recommendations = """
            <b>Ongoing Monitoring:</b>
            <br/>• Continue regular memory analysis
            <br/>• Monitor for new suspicious processes
            <br/>• Review network connection patterns
            <br/>• Maintain security awareness
            """

        story.append(Paragraph(recommendations, normal_style))

        # Footer
        story.append(Spacer(1, 30))
        story.append(
            Paragraph(
                "Generated by AI-Powered Memory Analyzer",
                ParagraphStyle(
                    "Footer",
                    parent=styles["Normal"],
                    fontSize=10,
                    alignment=TA_CENTER,
                    textColor=colors.grey,
                ),
            )
        )

        # Build PDF
        doc.build(story)

    def update_detailed_report(self, results: dict):
        """Update the detailed report"""
        suspicious_processes = results.get("suspicious_processes", {})

        if not suspicious_processes:
            report = "No suspicious processes detected in this analysis."
        else:
            report = "DETAILED ANALYSIS REPORT\n"
            report += "=" * 50 + "\n\n"

            for pid, data in suspicious_processes.items():
                info = data.get("Info", {})
                reasons = data.get("Reasons", [])

                report += f"🚨 SUSPICIOUS PROCESS: PID {pid}\n"
                report += f"   Process Name: {info.get('Name', 'N/A')}\n"
                report += f"   Parent PID: {info.get('PPID', 'N/A')}\n"
                report += f"   Parent Name: {info.get('Parent Name', 'N/A')}\n"
                report += f"   Reasons:\n"

                for i, reason in enumerate(reasons, 1):
                    report += f"     {i}. {reason}\n"

                report += "\n" + "-" * 40 + "\n\n"

        self.report_text.setPlainText(report)

    def clear_results(self):
        """Clear all results and reset the interface"""
        self.analysis_results = None
        self.download_pdf_btn.setEnabled(False)
        self.show_welcome_message()
        self.progress_label.setText("Ready to start analysis...")
        self.progress_label.setStyleSheet("font-weight: 500; color: #1C1C1E; font-size: 14px;")
        self.ip_check_label.setVisible(False)

    def set_file_path(self, file_path: str):
        """Set the memory file path for analysis"""
        self.file_path = file_path
