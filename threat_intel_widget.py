"""
Threat Intelligence Widget for Memory Analyzer
Integrates VirusTotal, AlienVault, and IPInfo APIs for comprehensive threat analysis
"""

import os
import re
import hashlib
import subprocess
import tempfile
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QLabel,
    QLineEdit, QPushButton, QTextEdit, QComboBox, QGroupBox,
    QFormLayout, QMessageBox, QProgressBar, QScrollArea, QApplication,
    QSizePolicy
)
from dotenv import load_dotenv

# Import the threat intelligence modules
from threat_intel.virustotal_module import VirusTotalExtractor
from threat_intel.alienvault_module import AlienVaultExtractor
from threat_intel.ipinfo_module import IPInfoExtractor


class ThreatIntelWorker(QThread):
    """Worker thread for API calls to prevent UI blocking"""
    
    result_ready = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    progress_update = pyqtSignal(str)
    
    def __init__(self, api_type, query_type, query_value, api_key):
        super().__init__()
        self.api_type = api_type
        self.query_type = query_type
        self.query_value = query_value
        self.api_key = api_key
        self._is_running = True
    
    def run(self):
        """Execute the API query"""
        try:
            if self.api_type == "virustotal":
                self._run_virustotal()
            elif self.api_type == "alienvault":
                self._run_alienvault()
            elif self.api_type == "ipinfo":
                self._run_ipinfo()
        except Exception as e:
            self.error_occurred.emit(f"Error: {str(e)}")
    
    def _run_virustotal(self):
        """Execute VirusTotal queries"""
        self.progress_update.emit("Querying VirusTotal...")
        vt = VirusTotalExtractor(self.api_key)
        
        # Capture output in string format
        import io
        import sys
        output = io.StringIO()
        sys.stdout = output
        
        try:
            if self.query_type == "hash":
                vt.vthashwork(self.query_value, showreport=1)
            elif self.query_type == "ip":
                vt.vtipwork(self.query_value)
            elif self.query_type == "domain":
                vt.vtdomainwork(self.query_value)
            elif self.query_type == "url":
                vt.vturlwork(self.query_value)
            elif self.query_type == "file":
                vt.filechecking_v3(self.query_value, showreport=1, impexp=0, ovrly=0)
            
            result = output.getvalue()
            self.result_ready.emit(self._format_html_output(result))
        finally:
            sys.stdout = sys.__stdout__
    
    def _run_alienvault(self):
        """Execute AlienVault queries"""
        self.progress_update.emit("Querying AlienVault OTX...")
        av = AlienVaultExtractor(self.api_key)
        
        import io
        import sys
        output = io.StringIO()
        sys.stdout = output
        
        try:
            if self.query_type == "ip":
                av.alien_ipv4(self.query_value)
            elif self.query_type == "domain":
                av.alien_domain(self.query_value)
            elif self.query_type == "hash":
                av.alien_hash(self.query_value)
            elif self.query_type == "url":
                av.alien_url(self.query_value)
            elif self.query_type == "subscribed":
                av.alien_subscribed(self.query_value)
            
            result = output.getvalue()
            self.result_ready.emit(self._format_html_output(result))
        finally:
            sys.stdout = sys.__stdout__
    
    def _run_ipinfo(self):
        """Execute IPInfo queries"""
        self.progress_update.emit("Querying IPInfo.io...")
        ip_info = IPInfoExtractor(self.api_key)
        
        import io
        import sys
        output = io.StringIO()
        sys.stdout = output
        
        try:
            ip_info.get_ip_details(self.query_value)
            result = output.getvalue()
            self.result_ready.emit(self._format_html_output(result))
        finally:
            sys.stdout = sys.__stdout__
    
    def _format_html_output(self, text):
        """Convert ANSI colored text to HTML"""
        # Remove ANSI escape codes
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_text = ansi_escape.sub('', text)
        
        # Convert to HTML with formatting
        html = "<pre style='font-family: monospace; font-size: 12px;'>"
        html += clean_text.replace('\n', '<br>')
        html += "</pre>"
        
        return html
    
    def stop(self):
        """Stop the worker thread"""
        self._is_running = False


class ThreatIntelWidget(QWidget):
    """Main widget for threat intelligence queries"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.memory_data = None  # Store memory analysis data
        self.parent_window = parent
        self.memory_file_path = None  # Store path to memory dump
        self.init_ui()
        self.load_api_keys()
    
    def init_ui(self):
        """Initialize the user interface"""
        # Main layout with fixed size policy
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Create scroll area for the entire content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setFrameShape(QScrollArea.Shape.NoFrame)
        
        # Container widget for scroll area
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(10)
        
        # Title
        title = QLabel("<h2>🔍 Threat Intelligence Analysis</h2>")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        layout.addWidget(title)
        
        # Description
        desc = QLabel(
            "Query threat intelligence from multiple sources: VirusTotal, AlienVault OTX, and IPInfo.io"
        )
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setStyleSheet("color: #666; margin-bottom: 10px;")
        desc.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        layout.addWidget(desc)
        
        # Tab widget for different services
        self.tabs = QTabWidget()
        self.tabs.setMaximumHeight(350)  # Limit tab height
        self.tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: white;
                max-height: 300px;
            }
            QTabBar::tab {
                background-color: #f0f0f0;
                padding: 8px 20px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border: 1px solid #ccc;
                border-bottom: none;
            }
        """)
        
        # Add tabs
        self.tabs.addTab(self.create_virustotal_tab(), "🦠 VirusTotal")
        self.tabs.addTab(self.create_alienvault_tab(), "👽 AlienVault OTX")
        self.tabs.addTab(self.create_ipinfo_tab(), "🌐 IPInfo")
        
        layout.addWidget(self.tabs)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setMaximumHeight(25)
        self.progress_bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.progress_bar)
        
        # Results area
        results_group = QGroupBox("Results")
        results_group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        results_layout = QVBoxLayout()
        results_layout.setContentsMargins(5, 5, 5, 5)
        
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.results_display.setMinimumHeight(200)
        self.results_display.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.results_display.setStyleSheet("""
            QTextEdit {
                background-color: #f9f9f9;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 10px;
                font-family: 'Courier New', monospace;
                font-size: 11px;
            }
        """)
        self.results_display.setPlaceholderText(
            "Results will appear here...\n\n"
            "Enter your query and click 'Analyze' to get started."
        )
        
        results_layout.addWidget(self.results_display)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        clear_btn = QPushButton("Clear Results")
        clear_btn.clicked.connect(self.clear_results)
        clear_btn.setMaximumWidth(150)
        clear_btn.setMaximumHeight(35)
        clear_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
        """)
        
        button_layout.addStretch()
        button_layout.addWidget(clear_btn)
        layout.addLayout(button_layout)
        
        # Set the container widget to scroll area
        scroll_area.setWidget(container)
        main_layout.addWidget(scroll_area)
    
    def create_virustotal_tab(self):
        """Create VirusTotal query tab"""
        widget = QWidget()
        widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        
        # Query type
        query_layout = QFormLayout()
        query_layout.setSpacing(5)
        self.vt_query_type = QComboBox()
        self.vt_query_type.addItems(["Hash (MD5/SHA1/SHA256)", "IP Address", "Domain", "URL", "File Path"])
        self.vt_query_type.currentTextChanged.connect(self.on_vt_query_type_changed)
        self.vt_query_type.setMaximumHeight(30)
        query_layout.addRow("Query Type:", self.vt_query_type)
        
        # Query input (will be swapped between QLineEdit and QComboBox)
        self.vt_query_input = QLineEdit()
        self.vt_query_input.setPlaceholderText("Enter hash, IP, domain, URL, or file path")
        self.vt_query_input.setMaximumHeight(30)
        self.vt_query_combo = QComboBox()
        self.vt_query_combo.setVisible(False)
        self.vt_query_combo.setMaximumHeight(30)
        
        query_layout.addRow("Query:", self.vt_query_input)
        query_layout.addRow("", self.vt_query_combo)
        
        layout.addLayout(query_layout)
        
        # Analyze button
        analyze_btn = QPushButton("🔍 Analyze with VirusTotal")
        analyze_btn.setMaximumHeight(40)
        analyze_btn.setStyleSheet("""
            QPushButton {
                background-color: #007bff;
                color: white;
                padding: 10px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
        """)
        analyze_btn.clicked.connect(self.run_virustotal_query)
        layout.addWidget(analyze_btn)
        
        # Info section
        info_label = QLabel(
            "<b>Supported queries:</b><br>"
            "• <b>Hash:</b> MD5, SHA1, or SHA256 file hash<br>"
            "• <b>IP Address:</b> IPv4 address<br>"
            "• <b>Domain:</b> Domain name (e.g., example.com)<br>"
            "• <b>URL:</b> Full URL (e.g., https://example.com/path)<br>"
            "• <b>File Path:</b> Local file path for scanning"
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #666; font-size: 11px; margin-top: 10px;")
        info_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(info_label)
        
        layout.addStretch()
        return widget
    
    def create_alienvault_tab(self):
        """Create AlienVault OTX query tab"""
        widget = QWidget()
        widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        
        # Query type
        query_layout = QFormLayout()
        query_layout.setSpacing(5)
        self.av_query_type = QComboBox()
        self.av_query_type.addItems(["IP Address", "Domain", "Hash", "URL", "Subscribed Pulses"])
        self.av_query_type.currentTextChanged.connect(self.on_av_query_type_changed)
        self.av_query_type.setMaximumHeight(30)
        query_layout.addRow("Query Type:", self.av_query_type)
        
        # Query input (will be swapped between QLineEdit and QComboBox)
        self.av_query_input = QLineEdit()
        self.av_query_input.setPlaceholderText("Enter IP, domain, hash, or URL")
        self.av_query_input.setMaximumHeight(30)
        self.av_query_combo = QComboBox()
        self.av_query_combo.setVisible(False)
        self.av_query_combo.setMaximumHeight(30)
        
        query_layout.addRow("Query:", self.av_query_input)
        query_layout.addRow("", self.av_query_combo)
        
        layout.addLayout(query_layout)
        
        # Analyze button
        analyze_btn = QPushButton("🔍 Analyze with AlienVault")
        analyze_btn.setMaximumHeight(40)
        analyze_btn.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                padding: 10px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
        """)
        analyze_btn.clicked.connect(self.run_alienvault_query)
        layout.addWidget(analyze_btn)
        
        # Info section
        self.av_info_label = QLabel(
            "<b>Supported queries:</b><br>"
            "• <b>IP Address:</b> IPv4 address analysis<br>"
            "• <b>Domain:</b> Domain reputation and threat data<br>"
            "• <b>Hash:</b> File hash intelligence (MD5/SHA1/SHA256)<br>"
            "• <b>URL:</b> URL reputation analysis<br>"
            "• <b>Subscribed Pulses:</b> Your subscribed threat feeds (enter limit number)"
        )
        self.av_info_label.setWordWrap(True)
        self.av_info_label.setStyleSheet("color: #666; font-size: 11px; margin-top: 10px;")
        self.av_info_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.av_info_label)
        
        layout.addStretch()
        return widget
    
    def create_ipinfo_tab(self):
        """Create IPInfo query tab"""
        widget = QWidget()
        widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        
        # Query input (will be swapped between QLineEdit and QComboBox)
        query_layout = QFormLayout()
        query_layout.setSpacing(5)
        self.ip_query_input = QLineEdit()
        self.ip_query_input.setPlaceholderText("Enter IPv4 address (e.g., 8.8.8.8)")
        self.ip_query_input.setMaximumHeight(30)
        self.ip_query_combo = QComboBox()
        self.ip_query_combo.setVisible(False)
        self.ip_query_combo.setMaximumHeight(30)
        
        query_layout.addRow("IP Address:", self.ip_query_input)
        query_layout.addRow("", self.ip_query_combo)
        layout.addLayout(query_layout)
        
        # Analyze button
        analyze_btn = QPushButton("🔍 Analyze with IPInfo")
        analyze_btn.setMaximumHeight(40)
        analyze_btn.setStyleSheet("""
            QPushButton {
                background-color: #17a2b8;
                color: white;
                padding: 10px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #138496;
            }
        """)
        analyze_btn.clicked.connect(self.run_ipinfo_query)
        layout.addWidget(analyze_btn)
        
        # Info section
        info_label = QLabel(
            "<b>IP Address Geolocation & Info:</b><br>"
            "• <b>Location:</b> City, region, country<br>"
            "• <b>Organization:</b> ISP/hosting provider<br>"
            "• <b>Network:</b> ASN information<br>"
            "• <b>Geolocation:</b> Coordinates and timezone<br><br>"
            "<i>Note: IPInfo.io allows 1,000 requests per day without an API key.</i>"
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #666; font-size: 11px; margin-top: 10px;")
        info_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(info_label)
        
        layout.addStretch()
        return widget
    
    def on_vt_query_type_changed(self, query_type):
        """Update input field based on VirusTotal query type"""
        if query_type == "IP Address":
            # Show dropdown if we have IPs from memory
            if self.memory_data and 'ips' in self.memory_data and self.memory_data['ips']:
                self.vt_query_input.setVisible(False)
                self.vt_query_combo.setVisible(True)
                self.vt_query_combo.clear()
                self.vt_query_combo.addItem("-- Select IP or enter manually below --")
                self.vt_query_combo.addItems(self.memory_data['ips'])
            else:
                self.vt_query_input.setVisible(True)
                self.vt_query_combo.setVisible(False)
                self.vt_query_input.setPlaceholderText("Enter IPv4 address")
        elif query_type == "File Path":
            # Show dropdown if we have files from memory
            if self.memory_data and 'files' in self.memory_data and self.memory_data['files']:
                self.vt_query_input.setVisible(False)
                self.vt_query_combo.setVisible(True)
                self.vt_query_combo.clear()
                self.vt_query_combo.addItem("-- Select file or enter manually below --")
                self.vt_query_combo.addItems(self.memory_data['files'])
            else:
                self.vt_query_input.setVisible(True)
                self.vt_query_combo.setVisible(False)
                self.vt_query_input.setPlaceholderText("Enter file path")
        else:
            # For other types, use text input
            self.vt_query_input.setVisible(True)
            self.vt_query_combo.setVisible(False)
            if query_type == "Hash (MD5/SHA1/SHA256)":
                self.vt_query_input.setPlaceholderText("Enter MD5, SHA1, or SHA256 hash")
            elif query_type == "Domain":
                self.vt_query_input.setPlaceholderText("Enter domain (e.g., example.com)")
            elif query_type == "URL":
                self.vt_query_input.setPlaceholderText("Enter URL (e.g., https://example.com)")
    
    def on_av_query_type_changed(self, query_type):
        """Update input field based on AlienVault query type"""
        if query_type == "IP Address":
            # Show dropdown if we have IPs from memory
            if self.memory_data and 'ips' in self.memory_data and self.memory_data['ips']:
                self.av_query_input.setVisible(False)
                self.av_query_combo.setVisible(True)
                self.av_query_combo.clear()
                self.av_query_combo.addItem("-- Select IP or enter manually below --")
                self.av_query_combo.addItems(self.memory_data['ips'])
            else:
                self.av_query_input.setVisible(True)
                self.av_query_combo.setVisible(False)
                self.av_query_input.setPlaceholderText("Enter IPv4 address")
        elif query_type == "Subscribed Pulses":
            self.av_query_input.setVisible(True)
            self.av_query_combo.setVisible(False)
            self.av_query_input.setPlaceholderText("Enter number of pulses to retrieve (e.g., 10)")
        else:
            # For other types, use text input
            self.av_query_input.setVisible(True)
            self.av_query_combo.setVisible(False)
            if query_type == "Domain":
                self.av_query_input.setPlaceholderText("Enter domain (e.g., example.com)")
            elif query_type == "Hash":
                self.av_query_input.setPlaceholderText("Enter MD5, SHA1, or SHA256 hash")
            elif query_type == "URL":
                self.av_query_input.setPlaceholderText("Enter URL")
    
    def load_api_keys(self):
        """Load API keys from environment variables"""
        load_dotenv()
        
        # Store API keys privately (not displayed)
        self.vt_api_key = os.getenv("VTAPI", "")
        self.av_api_key = os.getenv("ALIENAPI", "")
        self.ip_api_key = os.getenv("IPINFOAPI", "")
    
    def set_memory_data(self, memory_data, memory_file_path=None):
        """Set memory analysis data for populating dropdowns"""
        self.memory_data = memory_data
        self.memory_file_path = memory_file_path
        # Refresh the current query type to update dropdowns
        self.on_vt_query_type_changed(self.vt_query_type.currentText())
        self.on_av_query_type_changed(self.av_query_type.currentText())
        self.update_ipinfo_dropdown()
    
    def run_virustotal_query(self):
        """Execute VirusTotal query"""
        if not self.vt_api_key:
            QMessageBox.warning(self, "API Key Required", 
                              "VirusTotal API key not found in .env file. Please add VTAPI to your .env file.")
            return
        
        # Determine if query comes from dropdown (memory) or manual input (local file)
        from_dropdown = False
        if self.vt_query_combo.isVisible():
            query = self.vt_query_combo.currentText().strip()
            if not query.startswith("--"):
                from_dropdown = True  # User selected from dropdown
            else:
                # User didn't select from dropdown, check manual input
                query = self.vt_query_input.text().strip() if self.vt_query_input.isVisible() else ""
        else:
            query = self.vt_query_input.text().strip()
        
        if not query or query.startswith("--"):
            QMessageBox.warning(self, "Query Required", "Please select or enter a query value.")
            return
        
        query_type_text = self.vt_query_type.currentText()
        query_type_map = {
            "Hash (MD5/SHA1/SHA256)": "hash",
            "IP Address": "ip",
            "Domain": "domain",
            "URL": "url",
            "File Path": "file"  # Default to local file
        }
        query_type = query_type_map.get(query_type_text, "hash")
        
        # Special handling for file paths
        if query_type == "file":
            # Check if this is from memory dropdown or manual input
            if from_dropdown and self.memory_file_path:
                # File path from memory - try to extract and hash
                self.results_display.setHtml(
                    "<pre style='color: #007bff; font-weight: bold;'>"
                    "🔍 Analyzing file from memory dump...\n\n"
                    f"Target: {query}\n\n"
                    "Attempting to:\n"
                    "1. Find existing hash from memory analysis\n"
                    "2. Extract file and calculate hash\n\n"
                    "Please wait..."
                    "</pre>"
                )
                QApplication.processEvents()
                
                # Try to get file hash from memory
                file_hash = self.extract_file_hash_from_memory(query)
                
                if file_hash:
                    # Success - show the hash and proceed
                    self.results_display.setHtml(
                        "<pre style='color: #28a745; font-weight: bold;'>"
                        f"✓ Successfully obtained hash for: {query}\n\n"
                        f"SHA256: {file_hash}\n\n"
                        "Querying VirusTotal..."
                        "</pre>"
                    )
                    QApplication.processEvents()
                    query = file_hash
                    query_type = "hash"
                else:
                    # Failed - offer options to user
                    msg = QMessageBox(self)
                    msg.setIcon(QMessageBox.Icon.Warning)
                    msg.setWindowTitle("File Not Available in Memory")
                    msg.setText(f"Could not extract or find hash for:\n{query}")
                    msg.setInformativeText(
                        "This file may not be fully present in the memory dump.\n\n"
                        "System files like smss.exe, csrss.exe, etc. are often not fully "
                        "resident in memory because they're paged out or protected.\n\n"
                        "Options:\n"
                        "• Try a different file from the dropdown\n"
                        "• Manually enter the file hash if you know it\n"
                        "• Query the filename on VirusTotal (may have existing analysis)\n"
                    )
                    
                    # Add buttons for options
                    try_filename_btn = msg.addButton("Search by Filename", QMessageBox.ButtonRole.ActionRole)
                    enter_hash_btn = msg.addButton("Enter Hash Manually", QMessageBox.ButtonRole.ActionRole)
                    cancel_btn = msg.addButton(QMessageBox.StandardButton.Cancel)
                    
                    msg.exec()
                    
                    if msg.clickedButton() == try_filename_btn:
                        # Query just the filename (not full path)
                        filename = os.path.basename(query)
                        self.vt_query_input.setText(filename)
                        self.vt_query_type.setCurrentText("Hash (MD5/SHA1/SHA256)")
                        QMessageBox.information(
                            self, "Filename Search",
                            f"Set query to filename: {filename}\n\n"
                            "You can now:\n"
                            "1. Try searching VirusTotal for known hashes of this filename\n"
                            "2. Enter a known hash for this file\n"
                            "3. Search online for the authentic hash of this system file"
                        )
                    elif msg.clickedButton() == enter_hash_btn:
                        # Switch to manual input mode
                        self.vt_query_type.setCurrentText("Hash (MD5/SHA1/SHA256)")
                        self.vt_query_input.setVisible(True)
                        self.vt_query_combo.setVisible(False)
                        self.vt_query_input.setFocus()
                        QMessageBox.information(
                            self, "Manual Hash Entry",
                            "Please enter the file hash (MD5, SHA1, or SHA256) in the query field."
                        )
                    
                    return
            else:
                # Local file path - scan the file directly
                # Check if file exists
                if not os.path.isfile(query):
                    QMessageBox.warning(
                        self, "File Not Found",
                        f"Could not find file: {query}\n\n"
                        "Please ensure:\n"
                        "• The file path is correct\n"
                        "• The file exists on your system\n"
                        "• You have permission to read the file"
                    )
                    return
                
                # File exists - proceed with scan
                # Note: query_type stays as "file" for local file scanning
        
        self.execute_query("virustotal", query_type, query, self.vt_api_key)
    
    def run_alienvault_query(self):
        """Execute AlienVault query"""
        if not self.av_api_key:
            QMessageBox.warning(self, "API Key Required", 
                              "AlienVault API key not found in .env file. Please add ALIENAPI to your .env file.")
            return
        
        # Get query from either input or combo box
        if self.av_query_combo.isVisible():
            query = self.av_query_combo.currentText().strip()
            if query.startswith("--"):
                # User didn't select, check if manual input available
                query = self.av_query_input.text().strip() if self.av_query_input.isVisible() else ""
        else:
            query = self.av_query_input.text().strip()
        
        if not query or query.startswith("--"):
            QMessageBox.warning(self, "Query Required", "Please select or enter a query value.")
            return
        
        query_type_text = self.av_query_type.currentText()
        query_type_map = {
            "IP Address": "ip",
            "Domain": "domain",
            "Hash": "hash",
            "URL": "url",
            "Subscribed Pulses": "subscribed"
        }
        query_type = query_type_map.get(query_type_text, "ip")
        
        self.execute_query("alienvault", query_type, query, self.av_api_key)
    
    def run_ipinfo_query(self):
        """Execute IPInfo query"""
        # API key is optional for IPInfo, use from .env if available
        
        # Get query from either input or combo box
        if self.ip_query_combo.isVisible():
            query = self.ip_query_combo.currentText().strip()
            if query.startswith("--"):
                # User didn't select, check if manual input available
                query = self.ip_query_input.text().strip() if self.ip_query_input.isVisible() else ""
        else:
            query = self.ip_query_input.text().strip()
        
        if not query or query.startswith("--"):
            QMessageBox.warning(self, "Query Required", "Please select or enter an IP address.")
            return
        
        # Validate IP address format
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, query):
            QMessageBox.warning(self, "Invalid IP", "Please enter a valid IPv4 address.")
            return
        
        self.execute_query("ipinfo", "ip", query, self.ip_api_key)
    
    def update_ipinfo_dropdown(self):
        """Update IPInfo dropdown based on memory data"""
        if self.memory_data and 'ips' in self.memory_data and self.memory_data['ips']:
            self.ip_query_input.setVisible(False)
            self.ip_query_combo.setVisible(True)
            self.ip_query_combo.clear()
            self.ip_query_combo.addItem("-- Select IP or enter manually below --")
            self.ip_query_combo.addItems(self.memory_data['ips'])
        else:
            self.ip_query_input.setVisible(True)
            self.ip_query_combo.setVisible(False)
    
    def extract_file_hash_from_memory(self, file_path):
        """
        Extract or find hash for a file from memory dump.
        
        Strategy:
        1. Check if hash is already available in memory analysis (filescan, modules)
        2. Try to extract file and calculate hash
        3. Return None if not possible (user can enter manually)
        
        Args:
            file_path: Path to the file as seen in the memory dump
            
        Returns:
            str: SHA256 hash of the file, or None if not available
        """
        if not self.memory_file_path:
            return None
        
        # Strategy 1: Try to find existing hash from memory analysis
        existing_hash = self.find_existing_hash(file_path)
        if existing_hash:
            return existing_hash
        
        # Strategy 2: Try to extract and hash the file
        # Note: This often fails for system files that aren't fully in memory
        try:
            extracted_hash = self.try_extract_and_hash(file_path)
            if extracted_hash:
                return extracted_hash
        except Exception as e:
            print(f"Extraction attempt failed: {e}")
        
        # Strategy 3: Return None - user can manually enter hash or try different file
        return None
    
    def find_existing_hash(self, file_path):
        """
        Look for existing hash information in memory analysis cache.
        
        Some Volatility plugins (like windows.filescan with authenticode)
        might already have hash information.
        """
        if not self.parent_window or not hasattr(self.parent_window, 'volatility_output_cache'):
            return None
        
        cache = self.parent_window.volatility_output_cache
        file_basename = os.path.basename(file_path).lower()
        
        # Check various cache locations for hash info
        # This is extensible - add more sources as needed
        for key in cache:
            if 'hash' in key.lower() or 'authenticode' in key.lower():
                data = cache[key]
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, dict):
                            # Check if this entry matches our file
                            name = entry.get('Name', entry.get('FileName', entry.get('ImageFileName', '')))
                            if name and file_basename in name.lower():
                                # Look for hash fields
                                for hash_field in ['SHA256', 'Hash', 'FileHash', 'SHA256Hash']:
                                    if hash_field in entry:
                                        return entry[hash_field]
        
        return None
    
    def try_extract_and_hash(self, file_path):
        """
        Attempt to extract file from memory and calculate hash.
        
        This often fails for system files, so we make it a best-effort attempt.
        """
        try:
            # Create temporary directory for extraction
            with tempfile.TemporaryDirectory() as temp_dir:
                output_dir = os.path.join(temp_dir, "extracted")
                os.makedirs(output_dir, exist_ok=True)
                
                # Find PID for targeted extraction
                pid = self.find_pid_for_file(file_path)
                
                if pid:
                    cmd = [
                        "python3", "-m", "volatility3",
                        "-f", self.memory_file_path,
                        "-o", output_dir,
                        "windows.dumpfiles",
                        "--pid", str(pid),
                        "--physaddr"  # Try physical address extraction
                    ]
                else:
                    # Without PID, this will be very slow - skip it
                    return None
                
                # Run Volatility extraction with shorter timeout
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60  # 1 minute timeout (reduced from 5 minutes)
                )
                
                # Search for extracted files
                extracted_files = []
                for root, dirs, files in os.walk(output_dir):
                    for file in files:
                        if file.endswith(('.dat', '.img', '.dmp')):
                            file_size = os.path.getsize(os.path.join(root, file))
                            # Only consider files larger than 1KB (to avoid partial/corrupt files)
                            if file_size > 1024:
                                extracted_files.append(os.path.join(root, file))
                
                if not extracted_files:
                    return None
                
                # Try to find best match by name
                target_file = extracted_files[0]
                file_basename = os.path.basename(file_path).lower()
                
                for extracted in extracted_files:
                    if file_basename in extracted.lower():
                        target_file = extracted
                        break
                
                # Calculate SHA256 hash
                sha256_hash = hashlib.sha256()
                with open(target_file, "rb") as f:
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                
                return sha256_hash.hexdigest()
                
        except subprocess.TimeoutExpired:
            print("File extraction timed out (1 minute)")
            return None
        except Exception as e:
            print(f"Extraction error: {e}")
            return None
    
    def find_pid_for_file(self, file_path):
        """
        Find the PID associated with a file path from memory analysis.
        
        Args:
            file_path: Path to search for
            
        Returns:
            int: PID if found, None otherwise
        """
        if not self.parent_window or not hasattr(self.parent_window, 'volatility_output_cache'):
            return None
        
        cache = self.parent_window.volatility_output_cache
        
        # Check PsList for ImageFileName match
        if 'windows.pslist.PsList' in cache:
            for entry in cache['windows.pslist.PsList']:
                if isinstance(entry, dict):
                    image = entry.get('ImageFileName', '')
                    if image and file_path.lower().endswith(image.lower()):
                        return entry.get('PID')
        
        # Check CmdLine for file path in arguments
        if 'windows.cmdline.CmdLine' in cache:
            for entry in cache['windows.cmdline.CmdLine']:
                if isinstance(entry, dict):
                    args = entry.get('Args', '')
                    if args and file_path.lower() in args.lower():
                        return entry.get('PID')
        
        return None
    
    def execute_query(self, api_type, query_type, query_value, api_key):
        """Execute the threat intelligence query in a background thread"""
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Query in Progress", "Please wait for the current query to complete.")
            return
        
        # Clear previous results
        self.results_display.clear()
        
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        # Create and start worker
        self.worker = ThreatIntelWorker(api_type, query_type, query_value, api_key)
        self.worker.result_ready.connect(self.display_results)
        self.worker.error_occurred.connect(self.display_error)
        self.worker.progress_update.connect(self.update_progress)
        self.worker.finished.connect(self.query_finished)
        self.worker.start()
    
    def display_results(self, result):
        """Display query results"""
        self.results_display.setHtml(result)
    
    def display_error(self, error):
        """Display error message"""
        error_html = f"<pre style='color: red; font-weight: bold;'>{error}</pre>"
        self.results_display.setHtml(error_html)
    
    def update_progress(self, message):
        """Update progress bar text"""
        self.progress_bar.setFormat(message)
    
    def query_finished(self):
        """Called when query is complete"""
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
    
    def clear_results(self):
        """Clear the results display"""
        self.results_display.clear()
        self.results_display.setPlaceholderText(
            "Results will appear here...\n\n"
            "Enter your query and click 'Analyze' to get started."
        )
    
    def closeEvent(self, event):
        """Handle widget close event"""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        event.accept()
    
    def showEvent(self, event):
        """Handle widget show event - reset size"""
        super().showEvent(event)
        # Reset to reasonable size when shown
        self.adjustSize()
        self.updateGeometry()
