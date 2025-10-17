"""
Memory Search Widget
Provides search functionality to find files and processes in memory dumps
"""

import json
import subprocess

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class SearchWorker(QThread):
    """Worker thread for memory search operations"""

    progress_signal = pyqtSignal(str, int, int)  # message, current, total
    result_signal = pyqtSignal(list)  # search results
    error_signal = pyqtSignal(str)  # error message

    def __init__(self, file_path: str, search_term: str, search_type: str):
        super().__init__()
        self.file_path = file_path
        self.search_term = search_term
        self.search_type = search_type
        self.volatility_output_cache = {}

    def run(self):
        try:
            self.progress_signal.emit("Starting memory search...", 0, 100)

            if self.search_type == "files":
                results = self.search_files()
            elif self.search_type == "processes":
                results = self.search_processes()
            else:
                results = self.search_all()

            self.progress_signal.emit("Search complete!", 100, 100)
            self.result_signal.emit(results)

        except Exception as e:
            self.error_signal.emit(f"Search failed: {str(e)}")

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
                return []

            parsed_json = json.loads(result.stdout)
            self.volatility_output_cache[plugin_name] = parsed_json
            return parsed_json

        except Exception as e:
            print(f"Error running {plugin_name}: {e}")
            return []

    def search_files(self):
        """Search for files matching the search term"""
        self.progress_signal.emit("Searching files...", 20, 100)

        filescan_results = self.run_volatility_plugin("windows.filescan.FileScan")
        if not filescan_results:
            return []

        matching_files = []
        search_lower = self.search_term.lower()

        for i, file_obj in enumerate(filescan_results):
            self.progress_signal.emit(
                f"Checking file {i+1}/{len(filescan_results)}",
                20 + (i * 60 // len(filescan_results)),
                100,
            )

            file_name = file_obj.get("Name", "")
            if search_lower in file_name.lower():
                matching_files.append(
                    {
                        "type": "file",
                        "name": file_name,
                        "offset": file_obj.get("Offset", ""),
                        "size": file_obj.get("Size", ""),
                        "inode": file_obj.get("Inode", ""),
                        "info": f"File: {file_name}",
                    }
                )

        return matching_files

    def search_processes(self):
        """Search for processes matching the search term"""
        self.progress_signal.emit("Searching processes...", 20, 100)

        pslist_results = self.run_volatility_plugin("windows.pslist.PsList")
        if not pslist_results:
            return []

        matching_processes = []
        search_lower = self.search_term.lower()

        for i, process in enumerate(pslist_results):
            self.progress_signal.emit(
                f"Checking process {i+1}/{len(pslist_results)}",
                20 + (i * 60 // len(pslist_results)),
                100,
            )

            proc_name = process.get("ImageFileName", "")
            pid = process.get("PID", "")

            if search_lower in proc_name.lower():
                matching_processes.append(
                    {
                        "type": "process",
                        "name": proc_name,
                        "pid": pid,
                        "ppid": process.get("PPID", ""),
                        "create_time": process.get("CreateTime", ""),
                        "info": f"Process: {proc_name} (PID: {pid})",
                    }
                )

        return matching_processes

    def search_all(self):
        """Search both files and processes"""
        self.progress_signal.emit("Searching files and processes...", 10, 100)

        all_results = []

        # Search files
        files = self.search_files()
        all_results.extend(files)

        # Search processes
        processes = self.search_processes()
        all_results.extend(processes)

        return all_results


class MemorySearchWidget(QWidget):
    """Main memory search widget"""

    def __init__(self, file_path: str = None):
        super().__init__()
        self.file_path = file_path
        self.search_worker = None
        self.search_results = None
        self.setup_ui()

    def setup_ui(self):
        """Setup the memory search UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.setSpacing(1)

        # Compact header with title and search in one row
        header_frame = QFrame()
        header_frame.setStyleSheet(
            """
            QFrame {
                background-color: #F2F2F7;
                border: 1px solid #C7C7CC;
                border-radius: 3px;
                padding: 2px;
            }
        """
        )
        header_frame.setMaximumHeight(35)  # Very compact header
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(4, 2, 4, 2)
        header_layout.setSpacing(8)

        # Compact title
        title = QLabel("🔍 Memory Search")
        title.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        title.setStyleSheet("color: #2c3e50; min-width: 100px;")
        header_layout.addWidget(title)

        # Search input (takes most space)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(
            "Search files, processes, or enter search term..."
        )
        self.search_input.setStyleSheet(
            """
            QLineEdit {
                padding: 3px 6px;
                border: 1px solid #ced4da;
                border-radius: 3px;
                background-color: white;
                font-size: 10px;
            }
            QLineEdit:focus {
                border-color: #007AFF;
            }
        """
        )
        self.search_input.returnPressed.connect(self.start_search)
        header_layout.addWidget(self.search_input)

        # Compact type selection
        self.search_type_group = QButtonGroup()

        self.search_files_radio = QRadioButton("Files")
        self.search_files_radio.setStyleSheet(
            "font-size: 8px; margin: 0px; padding: 1px;"
        )
        self.search_processes_radio = QRadioButton("Processes")
        self.search_processes_radio.setStyleSheet(
            "font-size: 8px; margin: 0px; padding: 1px;"
        )
        self.search_all_radio = QRadioButton("All")
        self.search_all_radio.setStyleSheet(
            "font-size: 8px; margin: 0px; padding: 1px;"
        )
        self.search_all_radio.setChecked(True)

        self.search_type_group.addButton(self.search_files_radio, 0)
        self.search_type_group.addButton(self.search_processes_radio, 1)
        self.search_type_group.addButton(self.search_all_radio, 2)

        header_layout.addWidget(self.search_files_radio)
        header_layout.addWidget(self.search_processes_radio)
        header_layout.addWidget(self.search_all_radio)

        # Compact buttons
        self.search_btn = QPushButton("Search")
        self.search_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #007AFF;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 3px 8px;
                font-weight: bold;
                font-size: 9px;
                min-width: 45px;
            }
            QPushButton:hover {
                background-color: #0056CC;
            }
            QPushButton:disabled {
                background-color: #8E8E93;
            }
        """
        )
        self.search_btn.clicked.connect(self.start_search)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #FF3B30;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 3px 8px;
                font-weight: bold;
                font-size: 9px;
                min-width: 40px;
            }
            QPushButton:hover {
                background-color: #D70015;
            }
        """
        )
        self.clear_btn.clicked.connect(self.clear_results)

        header_layout.addWidget(self.search_btn)
        header_layout.addWidget(self.clear_btn)

        layout.addWidget(header_frame)

        # Ultra minimal progress (integrated into header when needed)
        progress_frame = QFrame()
        progress_frame.setMaximumHeight(18)  # Very thin progress area
        progress_layout = QHBoxLayout(progress_frame)
        progress_layout.setContentsMargins(2, 1, 2, 1)
        progress_layout.setSpacing(4)

        self.progress_label = QLabel("Ready to search memory...")
        self.progress_label.setStyleSheet(
            "font-weight: 500; color: #1C1C1E; font-size: 9px;"
        )

        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet(
            """
            QProgressBar {
                border: 1px solid #C7C7CC;
                border-radius: 2px;
                text-align: center;
                font-weight: 500;
                background-color: #F2F2F7;
                height: 10px;
                font-size: 8px;
            }
            QProgressBar::chunk {
                background-color: #007AFF;
                border-radius: 1px;
            }
        """
        )
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumHeight(10)

        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress_bar)
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
                border-radius: 3px;
                padding: 1px;
            }
        """
        )
        summary_layout = QVBoxLayout(summary_frame)
        summary_layout.setContentsMargins(2, 2, 2, 2)
        summary_layout.setSpacing(1)

        summary_title = QLabel("Results")
        summary_title.setFont(QFont("Arial", 9, QFont.Weight.Bold))
        summary_title.setStyleSheet("color: #1C1C1E; margin: 0px;")
        summary_layout.addWidget(summary_title)

        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setMaximumHeight(60)  # Even more compact
        self.summary_text.setStyleSheet(
            """
            QTextEdit {
                background-color: white;
                border: 1px solid #C7C7CC;
                border-radius: 2px;
                padding: 2px;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                font-size: 8px;
                line-height: 1.0;
            }
        """
        )
        summary_layout.addWidget(self.summary_text)

        # Results table (maximum space)
        results_frame = QFrame()
        results_frame.setStyleSheet(
            """
            QFrame {
                background-color: #F2F2F7;
                border: 1px solid #C7C7CC;
                border-radius: 3px;
                padding: 1px;
            }
        """
        )
        results_layout = QVBoxLayout(results_frame)
        results_layout.setContentsMargins(2, 1, 2, 1)
        results_layout.setSpacing(1)

        # Minimal results header
        results_header = QHBoxLayout()
        results_header.setSpacing(4)

        results_title = QLabel("Search Results")
        results_title.setFont(QFont("Arial", 9, QFont.Weight.Bold))
        results_title.setStyleSheet("color: #1C1C1E; margin: 0px;")
        results_header.addWidget(results_title)

        # Add quick filter in header
        self.quick_filter = QLineEdit()
        self.quick_filter.setPlaceholderText("Filter results...")
        self.quick_filter.setStyleSheet(
            """
            QLineEdit {
                padding: 2px 4px;
                border: 1px solid #ced4da;
                border-radius: 2px;
                background-color: white;
                font-size: 8px;
                max-width: 120px;
            }
            QLineEdit:focus {
                border-color: #007AFF;
            }
        """
        )
        self.quick_filter.textChanged.connect(self.filter_results)
        results_header.addWidget(self.quick_filter)
        results_header.addStretch()

        results_layout.addLayout(results_header)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)  # Added one more column for hex viewer button
        self.results_table.setHorizontalHeaderLabels(
            ["Type", "Name/Path", "ID/Offset", "Additional Info", "Actions"]
        )
        self.results_table.setStyleSheet(
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
        self.results_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.results_table.setAlternatingRowColors(True)
        self.results_table.itemDoubleClicked.connect(self.on_item_double_clicked)

        # Set column widths to optimize space
        self.results_table.setColumnWidth(0, 80)   # Type column - compact
        self.results_table.setColumnWidth(1, 250)  # Name - reduced slightly for actions column
        self.results_table.setColumnWidth(2, 100)  # ID/Offset
        self.results_table.setColumnWidth(3, 120)  # Additional info - reduced slightly
        self.results_table.setColumnWidth(4, 80)   # Actions column

        results_layout.addWidget(self.results_table)

        results_splitter.addWidget(summary_frame)
        results_splitter.addWidget(results_frame)
        # Give much more space to results table and minimize summary
        results_splitter.setSizes([80, 1400])

        layout.addWidget(results_splitter)

        # Initialize with welcome message
        self.show_welcome_message()

    def show_welcome_message(self):
        """Show welcome message and instructions"""
        welcome_text = """🔍 Memory Search Ready

Search files & processes in memory dumps.
Enter term → Select type → Click Search

🔥 NEW: Hex Viewer Feature! 
Double-click results OR click 🔍 Hex button 
to view files in hexadecimal format."""
        self.summary_text.setPlainText(welcome_text)

    def start_search(self):
        """Start the search process"""
        if not self.file_path:
            from PyQt6.QtWidgets import QMessageBox

            QMessageBox.warning(
                self, "No File", "Please open a memory image file first."
            )
            return

        search_term = self.search_input.text().strip()
        if not search_term:
            from PyQt6.QtWidgets import QMessageBox

            QMessageBox.warning(self, "No Search Term", "Please enter a search term.")
            return

        # Determine search type
        if self.search_files_radio.isChecked():
            search_type = "files"
        elif self.search_processes_radio.isChecked():
            search_type = "processes"
        else:
            search_type = "all"

        # Disable search button and show progress
        self.search_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        # Start search worker
        self.search_worker = SearchWorker(self.file_path, search_term, search_type)
        self.search_worker.progress_signal.connect(self.update_progress)
        self.search_worker.result_signal.connect(self.on_search_complete)
        self.search_worker.error_signal.connect(self.on_search_error)
        self.search_worker.start()

    def update_progress(self, message: str, current: int, total: int):
        """Update progress display"""
        self.progress_label.setText(message)
        if total > 0:
            progress = int((current / total) * 100)
            self.progress_bar.setValue(progress)

    def on_search_complete(self, results: list):
        """Handle search completion"""
        self.search_results = results
        self.search_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

        # Update summary
        self.update_summary(results)

        # Update results table
        self.update_results_table(results)

        self.progress_label.setText("Search complete!")
        self.progress_label.setStyleSheet(
            "font-weight: 500; color: #34C759; font-size: 9px;"
        )

    def on_search_error(self, error_message: str):
        """Handle search errors"""
        self.search_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

        self.progress_label.setText(f"Search failed: {error_message}")
        self.progress_label.setStyleSheet(
            "font-weight: 500; color: #FF3B30; font-size: 9px;"
        )

        from PyQt6.QtWidgets import QMessageBox

        QMessageBox.critical(self, "Search Error", error_message)

    def update_summary(self, results: list):
        """Update search summary"""
        search_term = self.search_input.text()

        files_found = len([r for r in results if r.get("type") == "file"])
        processes_found = len([r for r in results if r.get("type") == "process"])

        summary = f"""� "{search_term}" → {len(results)} results
📁 {files_found} files  ⚙️ {processes_found} processes

{('✅ Success' if results else '❌ No matches')}"""

        if results and len(results) <= 3:
            summary += f"\n\n📋 Results:\n"
            for result in results:
                name = result.get("name", "Unknown")[:20] + (
                    "..." if len(result.get("name", "")) > 20 else ""
                )
                summary += f"• {name}\n"
            summary += f"\n🔍 Click 'Hex' buttons to view in hex editor"
        elif results:
            summary += f"\n\n� Showing {min(len(results), 100)} results"
            summary += f"\n🔍 Use 'Hex' buttons for hex view"

        self.summary_text.setPlainText(summary)

    def filter_results(self):
        """Filter the results table based on quick filter input"""
        if not self.search_results:
            return

        filter_text = self.quick_filter.text().lower()

        for row in range(self.results_table.rowCount()):
            should_show = True
            if filter_text:
                # Check all columns for the filter text
                row_text = ""
                for col in range(self.results_table.columnCount()):
                    item = self.results_table.item(row, col)
                    if item:
                        row_text += item.text().lower() + " "

                should_show = filter_text in row_text

            self.results_table.setRowHidden(row, not should_show)

    def update_results_table(self, results: list):
        """Update the results table"""
        self.results_table.setRowCount(len(results))

        for i, result in enumerate(results):
            # Type
            type_item = QTableWidgetItem(result.get("type", "").upper())
            if result.get("type") == "file":
                type_item.setBackground(QTableWidgetItem().background())
                type_item.setText("📁 FILE")
            else:
                type_item.setText("⚙️ PROCESS")

            # Name/Path
            name_item = QTableWidgetItem(result.get("name", ""))

            # ID/Offset
            if result.get("type") == "file":
                id_item = QTableWidgetItem(result.get("offset", ""))
            else:
                id_item = QTableWidgetItem(f"PID: {result.get('pid', '')}")

            # Additional Info
            if result.get("type") == "file":
                info_text = f"Size: {result.get('size', 'N/A')}"
            else:
                info_text = f"PPID: {result.get('ppid', 'N/A')}"

            info_item = QTableWidgetItem(info_text)

            # Actions - Hex Viewer Button
            hex_btn = QPushButton("🔍 Hex")
            hex_btn.setStyleSheet("""
                QPushButton {
                    background-color: #28A745;
                    color: white;
                    border: none;
                    border-radius: 3px;
                    padding: 2px 6px;
                    font-size: 8px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #218838;
                }
            """)
            hex_btn.setMaximumWidth(60)
            hex_btn.clicked.connect(lambda checked, r=result: self.show_item_details(r))

            self.results_table.setItem(i, 0, type_item)
            self.results_table.setItem(i, 1, name_item)
            self.results_table.setItem(i, 2, id_item)
            self.results_table.setItem(i, 3, info_item)
            self.results_table.setCellWidget(i, 4, hex_btn)

        self.results_table.resizeColumnsToContents()

    def on_item_double_clicked(self, item):
        """Handle double-click on result item"""
        row = item.row()
        if row < len(self.search_results):
            result = self.search_results[row]
            # This could trigger hex viewer or detailed view
            self.show_item_details(result)

    def show_item_details(self, result: dict):
        """Show detailed information about a selected item and open hex viewer"""
        try:
            # Import hex viewer
            from hex_viewer_widget import HexViewerWidget
            
            # Create and show hex viewer dialog
            hex_viewer = HexViewerWidget(result, self.file_path, self)
            hex_viewer.exec()
            
        except ImportError:
            # Fallback to basic dialog if hex viewer is not available
            from PyQt6.QtWidgets import QMessageBox

            if result.get("type") == "file":
                details = f"""
File Details:
Name: {result.get('name', 'N/A')}
Offset: {result.get('offset', 'N/A')}
Size: {result.get('size', 'N/A')}
Inode: {result.get('inode', 'N/A')}

Hex viewer unavailable - showing basic details only.
                """
            else:
                details = f"""
Process Details:
Name: {result.get('name', 'N/A')}
PID: {result.get('pid', 'N/A')}
PPID: {result.get('ppid', 'N/A')}
Create Time: {result.get('create_time', 'N/A')}

Hex viewer unavailable - showing basic details only.
                """

            QMessageBox.information(self, "Item Details", details)
        except Exception as e:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.critical(
                self, 
                "Hex Viewer Error", 
                f"Failed to open hex viewer:\n{str(e)}\n\nTry selecting a different file or check if the memory dump is accessible."
            )

    def clear_results(self):
        """Clear all results and reset the interface"""
        self.search_results = None
        self.search_input.clear()
        self.quick_filter.clear()
        self.show_welcome_message()
        self.results_table.setRowCount(0)
        self.progress_label.setText("Ready to search memory...")
        self.progress_label.setStyleSheet(
            "font-weight: 500; color: #1C1C1E; font-size: 9px;"
        )

    def set_file_path(self, file_path: str):
        """Set the memory file path for analysis"""
        self.file_path = file_path
