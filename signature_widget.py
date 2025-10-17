"""
Signature Analysis Widget
Provides file and process signature analysis for memory forensics
"""

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False


class SignatureAnalysisWorker(QThread):
    """Worker thread for signature analysis"""
    
    progress_signal = pyqtSignal(str, int, int)  # message, current, total
    result_signal = pyqtSignal(dict)  # analysis results
    error_signal = pyqtSignal(str)  # error message
    file_check_signal = pyqtSignal(str, int, int)  # filename, current, total
    process_check_signal = pyqtSignal(str, int, int)  # process, current, total

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path
        self.volatility_output_cache = {}
        
        # File signature mappings
        self.EXT_TO_SIGNATURE = {
            '.exe': ['PE32 executable', 'MS-DOS executable'],
            '.dll': ['PE32 executable', 'MS-DOS executable'],
            '.sys': ['PE32 executable', 'MS-DOS executable'],
            '.pdf': 'PDF document',
            '.jpg': 'JPEG image data',
            '.jpeg': 'JPEG image data',
            '.png': 'PNG image data',
            '.gif': 'GIF image data',
            '.zip': 'Zip archive data',
            '.txt': 'ASCII text',
        }

    def run(self):
        try:
            if not MAGIC_AVAILABLE:
                self.error_signal.emit(
                    "python-magic library not installed. Please install it first."
                )
                return

            self.progress_signal.emit("Starting signature analysis...", 0, 100)
            
            # Run signature analysis
            results = self.perform_signature_analysis()
            
            if results is None:
                self.error_signal.emit("Signature analysis failed")
                return
                
            self.progress_signal.emit("Analysis complete!", 100, 100)
            self.result_signal.emit(results)
            
        except Exception as e:
            self.error_signal.emit(f"Analysis failed: {str(e)}")

    def analyze_bytes_for_mismatch(self, file_data: bytes, original_name: str) -> dict | None:
        """Analyze bytes and return mismatch details, or None."""
        extension = os.path.splitext(original_name)[1].lower()
        if not file_data or extension not in self.EXT_TO_SIGNATURE:
            return None

        try:
            actual_type = magic.from_buffer(file_data)
            expected_types = self.EXT_TO_SIGNATURE[extension]
            if not isinstance(expected_types, list):
                expected_types = [expected_types]

            if not any(exp in actual_type for exp in expected_types):
                return {
                    'filename': original_name,
                    'expected': ", ".join(expected_types),
                    'actual': actual_type.split(',')[0]
                }
        except Exception:
            return None
        return None

    def run_volatility_plugin(self, plugin_name: str):
        """Run a single Volatility plugin"""
        if plugin_name in self.volatility_output_cache:
            return self.volatility_output_cache[plugin_name]

        try:
            command = ["vol", "-f", self.file_path, "--renderer", "json", plugin_name]
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
            )

            if not result.stdout:
                return None

            import json
            parsed_json = json.loads(result.stdout)
            self.volatility_output_cache[plugin_name] = parsed_json
            return parsed_json

        except Exception as e:
            print(f"Error running {plugin_name}: {e}")
            return None

    def perform_signature_analysis(self):
        """Perform signature analysis on memory dump"""
        all_mismatches = {"files": [], "processes": []}
        files_checked_count = 0
        procs_checked_count = 0
        total_files_found = 0
        total_procs_found = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            self.progress_signal.emit("Using temporary directory for analysis...", 10, 100)

            # Stage 1: Analyze Open Files
            self.progress_signal.emit("Analyzing open files...", 20, 100)
            filescan_results = self.run_volatility_plugin("windows.filescan.FileScan")
            
            if filescan_results:
                total_files_found = len(filescan_results)
                checkable_files = [
                    f for f in filescan_results 
                    if os.path.splitext(f.get("Name", ""))[1].lower() in self.EXT_TO_SIGNATURE
                ]
                files_checked_count = len(checkable_files)

                for i, file_obj in enumerate(checkable_files):
                    file_name = file_obj.get("Name")
                    virt_addr = file_obj.get("Offset")
                    
                    self.file_check_signal.emit(file_name, i + 1, files_checked_count)

                    try:
                        dump_cmd = [
                            "vol", "-q", "-f", self.file_path, 
                            "windows.dumpfiles", 
                            f"--virtaddr={virt_addr}", 
                            f"--dump-dir={temp_dir}"
                        ]
                        subprocess.run(dump_cmd, check=True, capture_output=True)
                        dumped_file = Path(temp_dir) / f"file.{hex(virt_addr)}.dat"
                        
                        if dumped_file.exists() and dumped_file.stat().st_size > 0:
                            with open(dumped_file, "rb") as f:
                                mismatch = self.analyze_bytes_for_mismatch(f.read(), file_name)
                                if mismatch:
                                    all_mismatches["files"].append(mismatch)
                    except subprocess.CalledProcessError:
                        continue

            # Stage 2: Analyze Running Processes
            self.progress_signal.emit("Analyzing running processes...", 60, 100)
            pslist_results = self.run_volatility_plugin("windows.pslist.PsList")
            
            if pslist_results:
                total_procs_found = len(pslist_results)
                checkable_procs = [
                    p for p in pslist_results 
                    if os.path.splitext(p.get("ImageFileName", ""))[1].lower() in self.EXT_TO_SIGNATURE
                ]
                procs_checked_count = len(checkable_procs)

                for i, process in enumerate(checkable_procs):
                    pid = process.get("PID")
                    proc_name = process.get("ImageFileName")
                    
                    self.process_check_signal.emit(f"{proc_name} (PID: {pid})", i + 1, procs_checked_count)

                    try:
                        dump_cmd = [
                            "vol", "-q", "-f", self.file_path, 
                            "windows.procdump", 
                            f"--pid={pid}", 
                            f"--dump-dir={temp_dir}"
                        ]
                        subprocess.run(dump_cmd, check=True, capture_output=True)
                        dumped_file = Path(temp_dir) / f"executable.{pid}.exe"
                        
                        if dumped_file.exists() and dumped_file.stat().st_size > 0:
                            with open(dumped_file, "rb") as f:
                                mismatch = self.analyze_bytes_for_mismatch(f.read(), proc_name)
                                if mismatch:
                                    mismatch['pid'] = pid
                                    all_mismatches["processes"].append(mismatch)
                    except subprocess.CalledProcessError:
                        continue

        return {
            "mismatches": all_mismatches,
            "files_checked": files_checked_count,
            "processes_checked": procs_checked_count,
            "total_files": total_files_found,
            "total_processes": total_procs_found
        }


class SignatureAnalysisWidget(QWidget):
    """Main signature analysis widget"""

    def __init__(self, file_path: str = None):
        super().__init__()
        self.file_path = file_path
        self.analysis_worker = None
        self.analysis_results = None
        self.setup_ui()

    def setup_ui(self):
        """Setup the signature analysis UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(2)

        # Compact header with title and controls in one row
        header_frame = QFrame()
        header_frame.setStyleSheet(
            """
            QFrame {
                background-color: #F2F2F7;
                border: 1px solid #C7C7CC;
                border-radius: 4px;
                padding: 2px;
            }
        """
        )
        header_frame.setMaximumHeight(32)  # Compact header
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(4, 2, 4, 2)
        header_layout.setSpacing(8)

        # Title
        title = QLabel("🔍 Signature Analysis")
        title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        title.setStyleSheet("color: #2c3e50; min-width: 120px;")
        header_layout.addWidget(title)

        # Control buttons (compact)
        self.start_analysis_btn = QPushButton("Start Analysis")
        self.start_analysis_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #007AFF;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 4px 12px;
                font-weight: bold;
                font-size: 10px;
                min-width: 80px;
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

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #FF3B30;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 4px 12px;
                font-weight: bold;
                font-size: 10px;
                min-width: 50px;
            }
            QPushButton:hover {
                background-color: #D70015;
            }
        """
        )
        self.clear_btn.clicked.connect(self.clear_results)

        header_layout.addWidget(self.start_analysis_btn)
        header_layout.addWidget(self.clear_btn)
        header_layout.addStretch()
        layout.addWidget(header_frame)

        # Minimal progress section
        progress_frame = QFrame()
        progress_frame.setMaximumHeight(20)
        progress_layout = QHBoxLayout(progress_frame)
        progress_layout.setContentsMargins(2, 1, 2, 1)
        progress_layout.setSpacing(4)

        self.progress_label = QLabel("Ready to start signature analysis...")
        self.progress_label.setStyleSheet("font-weight: 500; color: #1C1C1E; font-size: 10px;")

        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet(
            """
            QProgressBar {
                border: 1px solid #C7C7CC;
                border-radius: 3px;
                text-align: center;
                font-weight: 500;
                background-color: #F2F2F7;
                height: 12px;
                font-size: 9px;
            }
            QProgressBar::chunk {
                background-color: #007AFF;
                border-radius: 2px;
            }
        """
        )
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumHeight(12)

        self.check_label = QLabel("")
        self.check_label.setStyleSheet("color: #666; font-family: monospace; font-size: 9px;")
        self.check_label.setVisible(False)
        self.check_label.setMaximumHeight(14)

        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.check_label)
        layout.addWidget(progress_frame)

        # Results section - maximize space
        results_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Summary panel (ultra compact)
        summary_frame = QFrame()
        summary_frame.setStyleSheet(
            """
            QFrame {
                background-color: #F2F2F7;
                border: 1px solid #C7C7CC;
                border-radius: 4px;
                padding: 2px;
            }
        """
        )
        summary_layout = QVBoxLayout(summary_frame)
        summary_layout.setContentsMargins(2, 2, 2, 2)
        summary_layout.setSpacing(1)

        summary_title = QLabel("Summary")
        summary_title.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        summary_title.setStyleSheet("color: #1C1C1E; margin: 0px;")
        summary_layout.addWidget(summary_title)

        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setMaximumHeight(80)  # Ultra compact
        self.summary_text.setStyleSheet(
            """
            QTextEdit {
                background-color: white;
                border: 1px solid #C7C7CC;
                border-radius: 3px;
                padding: 4px;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                font-size: 9px;
                line-height: 1.1;
            }
        """
        )
        summary_layout.addWidget(self.summary_text)

        # Detailed results panel (maximum space)
        results_frame = QFrame()
        results_frame.setStyleSheet(
            """
            QFrame {
                background-color: #F2F2F7;
                border: 1px solid #C7C7CC;
                border-radius: 4px;
                padding: 2px;
            }
        """
        )
        results_layout = QVBoxLayout(results_frame)
        results_layout.setContentsMargins(2, 2, 2, 2)
        results_layout.setSpacing(1)

        results_title = QLabel("Signature Analysis Results")
        results_title.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        results_title.setStyleSheet("color: #1C1C1E; margin: 0px;")
        results_layout.addWidget(results_title)

        # Create compact tabbed interface for files and processes
        self.results_tabs = QWidget()
        self.results_tabs_layout = QVBoxLayout(self.results_tabs)
        self.results_tabs_layout.setContentsMargins(1, 1, 1, 1)
        self.results_tabs_layout.setSpacing(2)
        
        # Files table (compact)
        files_label = QLabel("📁 File Signature Mismatches:")
        files_label.setStyleSheet("font-size: 9px; font-weight: bold; color: #495057; margin: 1px;")
        self.files_table = QTableWidget()
        self.files_table.setColumnCount(3)
        self.files_table.setHorizontalHeaderLabels(["File Name", "Expected", "Actual"])
        self.files_table.setStyleSheet(
            """
            QTableWidget {
                background-color: white;
                border: 1px solid #C7C7CC;
                border-radius: 3px;
                gridline-color: #E0E0E0;
                font-size: 9px;
            }
            QHeaderView::section {
                background-color: #F8F8F8;
                padding: 2px;
                border: 1px solid #DDDDDD;
                font-weight: bold;
                font-size: 8px;
                height: 18px;
            }
            QTableWidget::item {
                padding: 1px;
                font-size: 9px;
            }
            QTableWidget::item:selected {
                background-color: #D0E4F5;
            }
        """
        )
        self.files_table.setAlternatingRowColors(True)
        
        self.results_tabs_layout.addWidget(files_label)
        self.results_tabs_layout.addWidget(self.files_table)

        # Processes table (compact)
        processes_label = QLabel("⚙️ Process Signature Mismatches:")
        processes_label.setStyleSheet("font-size: 9px; font-weight: bold; color: #495057; margin: 1px;")
        self.processes_table = QTableWidget()
        self.processes_table.setColumnCount(4)
        self.processes_table.setHorizontalHeaderLabels(["Process Name", "PID", "Expected", "Actual"])
        self.processes_table.setStyleSheet(
            """
            QTableWidget {
                background-color: white;
                border: 1px solid #C7C7CC;
                border-radius: 3px;
                gridline-color: #E0E0E0;
                font-size: 9px;
            }
            QHeaderView::section {
                background-color: #F8F8F8;
                padding: 2px;
                border: 1px solid #DDDDDD;
                font-weight: bold;
                font-size: 8px;
                height: 18px;
            }
            QTableWidget::item {
                padding: 1px;
                font-size: 9px;
            }
            QTableWidget::item:selected {
                background-color: #D0E4F5;
            }
        """
        )
        self.processes_table.setAlternatingRowColors(True)
        
        self.results_tabs_layout.addWidget(processes_label)
        self.results_tabs_layout.addWidget(self.processes_table)

        results_layout.addWidget(self.results_tabs)
        results_splitter.addWidget(summary_frame)
        results_splitter.addWidget(results_frame)
        # Give much more space to results and minimize summary
        results_splitter.setSizes([100, 1400])

        layout.addWidget(results_splitter)

        # Initialize with welcome message
        self.show_welcome_message()

    def show_welcome_message(self):
        """Show welcome message and instructions"""
        welcome_text = """🔍 Signature Analysis Ready

Detects file/process signature mismatches:
• File signature anomalies
• Process signature errors
• Hidden/obfuscated executables

Click 'Start Analysis' to begin."""
        self.summary_text.setPlainText(welcome_text)

    def show_no_data_message(self):
        """Show message when no analyzable data is found"""
        no_data_text = """📊 SIGNATURE ANALYSIS - NO DATA

❌ NO ANALYZABLE FILES FOUND

The memory dump contains no files or 
processes with recognizable extensions 
for signature analysis.

This could indicate:
• Limited process activity
• Different file types than expected
• Memory dump may need different analysis"""
        
        self.summary_text.setPlainText(no_data_text)
        
        # Clear tables and show appropriate messages
        self.files_table.setRowCount(1)
        no_files_item = QTableWidgetItem("ℹ️ No analyzable files found in memory dump")
        self.files_table.setItem(0, 0, no_files_item)
        self.files_table.setItem(0, 1, QTableWidgetItem("No files with recognizable extensions"))
        self.files_table.setItem(0, 2, QTableWidgetItem("Try different analysis methods"))
        
        self.processes_table.setRowCount(1)
        no_procs_item = QTableWidgetItem("ℹ️ No analyzable processes found in memory dump")
        self.processes_table.setItem(0, 0, no_procs_item)
        self.processes_table.setItem(0, 1, QTableWidgetItem("--"))
        self.processes_table.setItem(0, 2, QTableWidgetItem("No processes with recognizable extensions"))
        self.processes_table.setItem(0, 3, QTableWidgetItem("Try different analysis methods"))
        
        self.files_table.resizeColumnsToContents()
        self.processes_table.resizeColumnsToContents()

    def start_analysis(self):
        """Start the signature analysis process"""
        if not self.file_path:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(
                self, "No File", "Please open a memory image file first."
            )
            return

        if not MAGIC_AVAILABLE:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(
                self, "Missing Dependency", 
                "python-magic library not installed. Please install it first."
            )
            return

        # Disable start button and show progress
        self.start_analysis_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.check_label.setVisible(True)

        # Start analysis worker
        self.analysis_worker = SignatureAnalysisWorker(self.file_path)
        self.analysis_worker.progress_signal.connect(self.update_progress)
        self.analysis_worker.file_check_signal.connect(self.update_file_check)
        self.analysis_worker.process_check_signal.connect(self.update_process_check)
        self.analysis_worker.result_signal.connect(self.on_analysis_complete)
        self.analysis_worker.error_signal.connect(self.on_analysis_error)
        self.analysis_worker.start()

    def update_progress(self, message: str, current: int, total: int):
        """Update progress display"""
        self.progress_label.setText(message)
        if total > 0:
            progress = int((current / total) * 100)
            self.progress_bar.setValue(progress)

    def update_file_check(self, filename: str, current: int, total: int):
        """Update file checking progress"""
        self.check_label.setText(f"  -> Checking file {current}/{total}: {filename}")
        self.check_label.setVisible(True)

    def update_process_check(self, process: str, current: int, total: int):
        """Update process checking progress"""
        self.check_label.setText(f"  -> Checking process {current}/{total}: {process}")
        self.check_label.setVisible(True)

    def on_analysis_complete(self, results: dict):
        """Handle analysis completion"""
        self.analysis_results = results
        self.start_analysis_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.check_label.setVisible(False)

        # Check if we have any results at all
        if not results or results.get("files_checked", 0) == 0 and results.get("processes_checked", 0) == 0:
            self.progress_label.setText("No analyzable files or processes found")
            self.progress_label.setStyleSheet("font-weight: 500; color: #FF9500; font-size: 10px;")
            self.show_no_data_message()
            return

        # Update summary
        self.update_summary(results)

        # Update detailed results
        self.update_detailed_results(results)

        # Determine completion message based on findings
        mismatches = results.get("mismatches", {})
        total_mismatches = len(mismatches.get("files", [])) + len(mismatches.get("processes", []))
        
        if total_mismatches == 0:
            self.progress_label.setText("Analysis complete - No signature mismatches found!")
            self.progress_label.setStyleSheet("font-weight: 500; color: #34C759; font-size: 10px;")
        else:
            self.progress_label.setText(f"Analysis complete - {total_mismatches} signature mismatches detected!")
            self.progress_label.setStyleSheet("font-weight: 500; color: #FF9500; font-size: 10px;")

    def on_analysis_error(self, error_message: str):
        """Handle analysis errors"""
        self.start_analysis_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.check_label.setVisible(False)

        self.progress_label.setText(f"Analysis failed: {error_message}")
        self.progress_label.setStyleSheet("font-weight: 500; color: #FF3B30; font-size: 10px;")

        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.critical(self, "Analysis Error", error_message)

    def update_summary(self, results: dict):
        """Update analysis summary"""
        mismatches = results.get("mismatches", {})
        files_mismatches = len(mismatches.get("files", []))
        processes_mismatches = len(mismatches.get("processes", []))
        files_checked = results.get("files_checked", 0)
        processes_checked = results.get("processes_checked", 0)
        total_files = results.get("total_files", 0)
        total_processes = results.get("total_processes", 0)
        
        total_mismatches = files_mismatches + processes_mismatches

        if total_mismatches == 0:
            summary = f"""📊 SIGNATURE ANALYSIS - COMPLETE

📁 Files: {files_checked}/{total_files} analyzed
⚙️ Processes: {processes_checked}/{total_processes} analyzed

✅ NO SIGNATURE MISMATCHES FOUND

All analyzed files and processes have 
matching signatures. This indicates:
• No obvious file type spoofing
• No signature-based hiding detected
• Clean memory dump analysis

Status: ✅ CLEAN"""
        else:
            summary = f"""📊 SIGNATURE ANALYSIS

📁 Files: {files_checked}/{total_files} analyzed
⚙️ Processes: {processes_checked}/{total_processes} analyzed

🚨 Mismatches Found:
• {files_mismatches} file signature mismatches
• {processes_mismatches} process signature mismatches

Status: ⚠️ SUSPICIOUS"""

        self.summary_text.setPlainText(summary)

    def update_detailed_results(self, results: dict):
        """Update detailed results tables"""
        mismatches = results.get("mismatches", {})
        
        # Update files table
        files_data = mismatches.get("files", [])
        if len(files_data) == 0:
            # Show "No mismatches found" message for files
            self.files_table.setRowCount(1)
            no_match_item = QTableWidgetItem("✅ No file signature mismatches found")
            no_match_item.setBackground(self.files_table.palette().alternateBase())
            self.files_table.setItem(0, 0, no_match_item)
            self.files_table.setItem(0, 1, QTableWidgetItem("All files have valid signatures"))
            self.files_table.setItem(0, 2, QTableWidgetItem("Analysis complete"))
        else:
            self.files_table.setRowCount(len(files_data))
            for i, file_mismatch in enumerate(files_data):
                self.files_table.setItem(i, 0, QTableWidgetItem(file_mismatch.get("filename", "")))
                self.files_table.setItem(i, 1, QTableWidgetItem(file_mismatch.get("expected", "")))
                self.files_table.setItem(i, 2, QTableWidgetItem(file_mismatch.get("actual", "")))
        self.files_table.resizeColumnsToContents()

        # Update processes table
        processes_data = mismatches.get("processes", [])
        if len(processes_data) == 0:
            # Show "No mismatches found" message for processes
            self.processes_table.setRowCount(1)
            no_match_item = QTableWidgetItem("✅ No process signature mismatches found")
            no_match_item.setBackground(self.processes_table.palette().alternateBase())
            self.processes_table.setItem(0, 0, no_match_item)
            self.processes_table.setItem(0, 1, QTableWidgetItem("--"))
            self.processes_table.setItem(0, 2, QTableWidgetItem("All processes have valid signatures"))
            self.processes_table.setItem(0, 3, QTableWidgetItem("Analysis complete"))
        else:
            self.processes_table.setRowCount(len(processes_data))
            for i, process_mismatch in enumerate(processes_data):
                self.processes_table.setItem(i, 0, QTableWidgetItem(process_mismatch.get("filename", "")))
                self.processes_table.setItem(i, 1, QTableWidgetItem(str(process_mismatch.get("pid", ""))))
                self.processes_table.setItem(i, 2, QTableWidgetItem(process_mismatch.get("expected", "")))
                self.processes_table.setItem(i, 3, QTableWidgetItem(process_mismatch.get("actual", "")))
        self.processes_table.resizeColumnsToContents()

    def clear_results(self):
        """Clear all results and reset the interface"""
        self.analysis_results = None
        self.show_welcome_message()
        self.files_table.setRowCount(0)
        self.processes_table.setRowCount(0)
        self.progress_label.setText("Ready to start signature analysis...")
        self.progress_label.setStyleSheet("font-weight: 500; color: #1C1C1E; font-size: 10px;")
        self.check_label.setVisible(False)

    def set_file_path(self, file_path: str):
        """Set the memory file path for analysis"""
        self.file_path = file_path
