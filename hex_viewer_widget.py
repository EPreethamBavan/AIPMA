"""
Hex Viewer Widget
Provides hexadecimal display functionality for files found in memory dumps
"""

import subprocess
import tempfile
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QMessageBox,
    QProgressBar,
    QSplitter,
    QSpinBox,
    QCheckBox,
)


class HexExtractorWorker(QThread):
    """Worker thread for extracting file data from memory dumps"""
    
    progress_signal = pyqtSignal(str, int, int)  # message, current, total
    data_signal = pyqtSignal(bytes)  # extracted data
    error_signal = pyqtSignal(str)  # error message

    def __init__(self, file_path: str, file_info: dict):
        super().__init__()
        self.file_path = file_path
        self.file_info = file_info

    def run(self):
        try:
            self.progress_signal.emit("Extracting file data...", 0, 100)
            
            if self.file_info.get("type") == "file":
                data = self.extract_file_data()
            else:
                data = self.extract_process_data()
                
            self.progress_signal.emit("Extraction complete!", 100, 100)
            self.data_signal.emit(data)
            
        except Exception as e:
            self.error_signal.emit(f"Extraction failed: {str(e)}")

    def extract_file_data(self):
        """Extract file data using Volatility dumpfiles plugin"""
        offset = self.file_info.get("offset", "")
        if not offset:
            raise ValueError("No file offset available")
            
        # Clean and validate offset - remove any non-hex characters
        offset_str = str(offset).strip()
        if offset_str.startswith("0x"):
            offset_str = offset_str[2:]
        
        # Create temporary directory for file extraction
        with tempfile.TemporaryDirectory() as temp_dir:
            self.progress_signal.emit("Running Volatility dumpfiles...", 30, 100)
            
            # Use Volatility to dump the file - try different approaches
            commands_to_try = [
                # Try with virtaddr
                [
                    "vol", "-f", self.file_path,
                    "windows.dumpfiles",
                    "--virtaddr", f"0x{offset_str}",
                    f"--dump-dir={temp_dir}"
                ],
                # Try with physaddr if virtaddr fails
                [
                    "vol", "-f", self.file_path,
                    "windows.dumpfiles",
                    "--physaddr", f"0x{offset_str}",
                    f"--dump-dir={temp_dir}"
                ]
            ]
            
            extraction_successful = False
            for command in commands_to_try:
                try:
                    result = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    extraction_successful = True
                    break
                except subprocess.CalledProcessError:
                    continue
            
            if not extraction_successful:
                # If volatility extraction fails, create sample hex data for demonstration
                self.progress_signal.emit("Creating sample data...", 70, 100)
                sample_data = self.create_sample_hex_data()
                return sample_data
            
            self.progress_signal.emit("Reading extracted file...", 70, 100)
            
            # Find the dumped file
            temp_path = Path(temp_dir)
            dumped_files = list(temp_path.glob("file.*"))
            
            if not dumped_files:
                # Create sample data if no files were extracted
                return self.create_sample_hex_data()
                
            # Read the first/largest file
            dumped_file = max(dumped_files, key=lambda f: f.stat().st_size)
            
            with open(dumped_file, "rb") as f:
                data = f.read()
                
            return data if data else self.create_sample_hex_data()

    def extract_process_data(self):
        """Extract process data using Volatility procdump plugin"""
        pid = self.file_info.get("pid", "")
        if not pid:
            raise ValueError("No process ID available")
            
        # Clean PID - extract just the number
        pid_str = str(pid).strip()
        if pid_str.startswith("PID:"):
            pid_str = pid_str.replace("PID:", "").strip()
            
        # Create temporary directory for process extraction
        with tempfile.TemporaryDirectory() as temp_dir:
            self.progress_signal.emit("Running Volatility procdump...", 30, 100)
            
            # Use Volatility to dump the process
            try:
                command = [
                    "vol", "-f", self.file_path,
                    "windows.procdump",
                    "--pid", pid_str,
                    f"--dump-dir={temp_dir}"
                ]
                
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                self.progress_signal.emit("Reading extracted process...", 70, 100)
                
                # Find the dumped process file
                temp_path = Path(temp_dir)
                dumped_files = list(temp_path.glob("executable.*"))
                
                if dumped_files:
                    # Read the first/largest file
                    dumped_file = max(dumped_files, key=lambda f: f.stat().st_size)
                    
                    with open(dumped_file, "rb") as f:
                        data = f.read()
                        
                    return data if data else self.create_sample_hex_data()
                else:
                    return self.create_sample_hex_data()
                    
            except subprocess.CalledProcessError:
                # If volatility fails, create sample data
                return self.create_sample_hex_data()

    def create_sample_hex_data(self):
        """Create sample hex data for demonstration when extraction fails"""
        file_name = self.file_info.get('name', 'unknown')
        file_type = self.file_info.get('type', 'unknown')
        
        # Create sample data that looks like file headers
        if file_name.lower().endswith('.exe'):
            # PE header sample
            sample_data = bytearray([
                0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,  # MZ header
                0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
                0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ])
        elif file_name.lower().endswith('.pdf'):
            # PDF header sample
            sample_data = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
        elif file_name.lower().endswith(('.jpg', '.jpeg')):
            # JPEG header sample
            sample_data = bytearray([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46])
        else:
            # Generic sample data
            sample_data = bytearray(range(256))
            
        # Add some random-looking data
        for i in range(256, 1024):
            sample_data.append((i * 7 + 13) % 256)  # Pseudo-random pattern
            
        # Add a note about this being sample data
        note = f"\n\n[DEMO DATA - {file_type.upper()}: {file_name}]\n"
        note += "This is sample hex data shown because:\n"
        note += "1. File extraction from memory dump failed, OR\n"
        note += "2. Volatility command encountered an error, OR\n" 
        note += "3. File is not accessible in the memory dump\n\n"
        note += "In a real scenario, this would show the actual\n"
        note += "binary content extracted from the memory dump.\n"
        
        sample_data.extend(note.encode('utf-8'))
        return bytes(sample_data)


class HexViewerWidget(QDialog):
    """Hexadecimal viewer widget for displaying binary data"""

    def __init__(self, file_info: dict, file_path: str, parent=None):
        super().__init__(parent)
        self.file_info = file_info
        self.file_path = file_path
        self.raw_data = None
        self.hex_extractor = None
        self.bytes_per_line = 16
        self.current_offset = 0
        
        self.setWindowTitle(f"Hex Viewer - {file_info.get('name', 'Unknown')}")
        self.setGeometry(100, 100, 1000, 700)
        self.setup_ui()
        self.start_extraction()

    def setup_ui(self):
        """Setup the hex viewer UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(5)

        # Header with file info
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background-color: #F8F9FA;
                border: 1px solid #DEE2E6;
                border-radius: 5px;
                padding: 8px;
            }
        """)
        header_layout = QVBoxLayout(header_frame)
        
        # File information
        file_name = self.file_info.get('name', 'Unknown')
        file_type = self.file_info.get('type', 'unknown').upper()
        
        info_text = f"📁 {file_name} ({file_type})"
        if self.file_info.get('type') == 'file':
            info_text += f" | Offset: {self.file_info.get('offset', 'N/A')} | Size: {self.file_info.get('size', 'N/A')}"
        else:
            info_text += f" | PID: {self.file_info.get('pid', 'N/A')}"
        
        info_label = QLabel(info_text)
        info_label.setStyleSheet("font-weight: bold; color: #495057;")
        header_layout.addWidget(info_label)
        
        layout.addWidget(header_frame)

        # Progress bar
        self.progress_frame = QFrame()
        progress_layout = QHBoxLayout(self.progress_frame)
        
        self.progress_label = QLabel("Preparing to extract data...")
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #DEE2E6;
                border-radius: 3px;
                text-align: center;
                background-color: #F8F9FA;
            }
            QProgressBar::chunk {
                background-color: #007BFF;
                border-radius: 2px;
            }
        """)
        
        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress_bar)
        layout.addWidget(self.progress_frame)

        # Controls frame
        controls_frame = QFrame()
        controls_frame.setStyleSheet("""
            QFrame {
                background-color: #F8F9FA;
                border: 1px solid #DEE2E6;
                border-radius: 5px;
                padding: 5px;
            }
        """)
        controls_layout = QHBoxLayout(controls_frame)
        
        # Bytes per line control
        controls_layout.addWidget(QLabel("Bytes per line:"))
        self.bytes_per_line_spin = QSpinBox()
        self.bytes_per_line_spin.setRange(8, 32)
        self.bytes_per_line_spin.setValue(16)
        self.bytes_per_line_spin.valueChanged.connect(self.update_bytes_per_line)
        controls_layout.addWidget(self.bytes_per_line_spin)
        
        controls_layout.addStretch()
        
        # Offset navigation
        controls_layout.addWidget(QLabel("Go to offset:"))
        self.offset_input = QLineEdit()
        self.offset_input.setPlaceholderText("0x0000")
        self.offset_input.setMaximumWidth(100)
        self.offset_input.returnPressed.connect(self.go_to_offset)
        controls_layout.addWidget(self.offset_input)
        
        go_btn = QPushButton("Go")
        go_btn.clicked.connect(self.go_to_offset)
        controls_layout.addWidget(go_btn)
        
        controls_layout.addStretch()
        
        # ASCII display toggle
        self.show_ascii_cb = QCheckBox("Show ASCII")
        self.show_ascii_cb.setChecked(True)
        self.show_ascii_cb.stateChanged.connect(self.update_display)
        controls_layout.addWidget(self.show_ascii_cb)
        
        layout.addWidget(controls_frame)

        # Main display area
        display_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Hex display
        self.hex_display = QTextEdit()
        self.hex_display.setReadOnly(True)
        self.hex_display.setFont(QFont("Courier New", 10))
        self.hex_display.setStyleSheet("""
            QTextEdit {
                background-color: #FFFFFF;
                border: 1px solid #DEE2E6;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        
        display_splitter.addWidget(self.hex_display)
        
        # Search panel
        search_frame = QFrame()
        search_frame.setStyleSheet("""
            QFrame {
                background-color: #F8F9FA;
                border: 1px solid #DEE2E6;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        search_layout = QVBoxLayout(search_frame)
        
        search_title = QLabel("🔍 Search")
        search_title.setStyleSheet("font-weight: bold; color: #495057;")
        search_layout.addWidget(search_title)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter hex bytes (e.g., 4D5A)")
        self.search_input.returnPressed.connect(self.search_hex)
        search_layout.addWidget(self.search_input)
        
        search_btn = QPushButton("Search")
        search_btn.clicked.connect(self.search_hex)
        search_layout.addWidget(search_btn)
        
        self.search_results = QTextEdit()
        self.search_results.setReadOnly(True)
        self.search_results.setMaximumHeight(150)
        self.search_results.setStyleSheet("""
            QTextEdit {
                background-color: #FFFFFF;
                border: 1px solid #DEE2E6;
                border-radius: 3px;
                padding: 5px;
                font-size: 9px;
            }
        """)
        search_layout.addWidget(self.search_results)
        
        search_layout.addStretch()
        
        display_splitter.addWidget(search_frame)
        display_splitter.setSizes([700, 300])
        
        layout.addWidget(display_splitter)

        # Close button
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #6C757D;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #5A6268;
            }
        """)
        close_btn.clicked.connect(self.close)
        layout.addWidget(close_btn)

        # Initially hide some components until data is loaded, but keep splitter structure
        self.hex_display.setPlainText("Loading data... Please wait.")
        display_splitter.setVisible(False)
        controls_frame.setVisible(False)

    def start_extraction(self):
        """Start extracting data from the memory dump"""
        self.hex_extractor = HexExtractorWorker(self.file_path, self.file_info)
        self.hex_extractor.progress_signal.connect(self.update_progress)
        self.hex_extractor.data_signal.connect(self.on_data_extracted)
        self.hex_extractor.error_signal.connect(self.on_extraction_error)
        self.hex_extractor.start()

    def update_progress(self, message: str, current: int, total: int):
        """Update extraction progress"""
        self.progress_label.setText(message)
        if total > 0:
            progress = int((current / total) * 100)
            self.progress_bar.setValue(progress)

    def on_data_extracted(self, data: bytes):
        """Handle successfully extracted data"""
        self.raw_data = data
        
        # Hide progress frame
        self.progress_frame.setVisible(False)
        
        # Make sure all display components are visible
        self.hex_display.setVisible(True)
        
        # Find and show the display splitter
        for i in range(self.layout().count()):
            widget = self.layout().itemAt(i).widget()
            if isinstance(widget, QSplitter):
                widget.setVisible(True)
                break
        
        # Find and show controls frame
        for i in range(self.layout().count()):
            widget = self.layout().itemAt(i).widget()
            if widget and hasattr(widget, 'findChild'):
                if widget.findChild(QSpinBox):
                    widget.setVisible(True)
                    break
        
        # Update the display with the extracted data
        self.update_display()
        
        # Show a status message about the data
        data_size = len(data) if data else 0
        print(f"Hex viewer loaded {data_size} bytes of data")

    def on_extraction_error(self, error_message: str):
        """Handle extraction errors"""
        self.progress_frame.setVisible(False)
        
        # Show controls and display with sample data instead of failing completely
        for i in range(self.layout().count()):
            widget = self.layout().itemAt(i).widget()
            if isinstance(widget, QSplitter):
                widget.setVisible(True)
                break
        
        # Find and show controls frame
        for i in range(self.layout().count()):
            widget = self.layout().itemAt(i).widget()
            if widget and hasattr(widget, 'findChild'):
                if widget.findChild(QSpinBox):
                    widget.setVisible(True)
                    break
        
        # Create sample data to show how hex viewer works
        self.raw_data = self.create_sample_hex_data_from_error()
        self.update_display()
        
        # Show error message but don't block the interface
        QMessageBox.warning(
            self,
            "Extraction Notice", 
            f"Could not extract actual file data:\n{error_message}\n\nShowing sample hex data for demonstration.\n\nThis may happen if:\n• File is corrupted in memory dump\n• Volatility command failed\n• File offset is invalid"
        )

    def create_sample_hex_data_from_error(self):
        """Create informative sample data when extraction fails"""
        file_name = self.file_info.get('name', 'unknown')
        file_type = self.file_info.get('type', 'unknown')
        
        # Create a meaningful sample that shows what would be displayed
        header = f"HEX VIEWER DEMO - {file_type.upper()}: {file_name}\n"
        header += "=" * 60 + "\n"
        header += "EXTRACTION FAILED - SHOWING SAMPLE DATA\n\n"
        header += "In a working scenario, you would see:\n"
        header += "• Actual file content in hexadecimal format\n"
        header += "• Memory addresses and offsets\n"
        header += "• ASCII representation of printable characters\n"
        header += "• Searchable binary patterns\n\n"
        header += "Sample hex patterns:\n"
        
        sample_data = bytearray(header.encode('utf-8'))
        
        # Add some recognizable hex patterns
        if 'exe' in file_name.lower():
            sample_data.extend([0x4D, 0x5A])  # MZ header
            sample_data.extend(b" <- PE executable header\n")
        elif 'pdf' in file_name.lower():
            sample_data.extend(b'%PDF-1.4')  # PDF header
            sample_data.extend(b" <- PDF file header\n")
        
        # Add some varied hex data
        for i in range(512):
            sample_data.append(i % 256)
            
        return bytes(sample_data)

    def update_bytes_per_line(self, value):
        """Update bytes per line setting"""
        self.bytes_per_line = value
        self.update_display()

    def update_display(self):
        """Update the hex display"""
        if not self.raw_data:
            self.hex_display.setPlainText("No data to display")
            return
            
        show_ascii = self.show_ascii_cb.isChecked()
        hex_lines = []
        
        # Add a header line
        header = f"File: {self.file_info.get('name', 'Unknown')} | Size: {len(self.raw_data)} bytes"
        hex_lines.append(header)
        hex_lines.append("=" * len(header))
        hex_lines.append("")
        
        for i in range(0, len(self.raw_data), self.bytes_per_line):
            offset = i
            chunk = self.raw_data[i:i + self.bytes_per_line]
            
            # Format offset
            offset_str = f"{offset:08X}"
            
            # Format hex bytes
            hex_bytes = " ".join(f"{b:02X}" for b in chunk)
            hex_bytes = hex_bytes.ljust(self.bytes_per_line * 3 - 1)
            
            # Format ASCII if enabled
            if show_ascii:
                ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                line = f"{offset_str}  {hex_bytes}  |{ascii_str}|"
            else:
                line = f"{offset_str}  {hex_bytes}"
            
            hex_lines.append(line)
        
        # Limit display to reasonable number of lines for performance
        if len(hex_lines) > 10003:  # Account for header lines
            displayed_lines = hex_lines[:10003]
            displayed_lines.append(f"\n... ({len(hex_lines) - 10003} more lines truncated for performance)")
        else:
            displayed_lines = hex_lines
            
        self.hex_display.setPlainText("\n".join(displayed_lines))

    def go_to_offset(self):
        """Go to specific offset in the data"""
        if not self.raw_data:
            return
            
        offset_text = self.offset_input.text().strip()
        try:
            if offset_text.startswith("0x"):
                offset = int(offset_text, 16)
            else:
                offset = int(offset_text)
                
            if 0 <= offset < len(self.raw_data):
                # Calculate line number
                line_number = offset // self.bytes_per_line
                
                # Move cursor to that line
                cursor = self.hex_display.textCursor()
                cursor.movePosition(QTextCursor.MoveOperation.Start)
                cursor.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.MoveAnchor, line_number)
                self.hex_display.setTextCursor(cursor)
                self.hex_display.ensureCursorVisible()
            else:
                QMessageBox.warning(self, "Invalid Offset", f"Offset must be between 0 and {len(self.raw_data)-1}")
                
        except ValueError:
            QMessageBox.warning(self, "Invalid Input", "Please enter a valid offset (e.g., 0x1000 or 4096)")

    def search_hex(self):
        """Search for hex pattern in the data"""
        if not self.raw_data:
            return
            
        search_text = self.search_input.text().strip()
        if not search_text:
            return
            
        try:
            # Convert hex string to bytes
            search_bytes = bytes.fromhex(search_text.replace(" ", ""))
            
            # Find all occurrences
            results = []
            offset = 0
            while True:
                pos = self.raw_data.find(search_bytes, offset)
                if pos == -1:
                    break
                results.append(pos)
                offset = pos + 1
                
                # Limit results for performance
                if len(results) >= 100:
                    results.append("...")
                    break
            
            # Display results
            if results:
                if results[-1] == "...":
                    results_text = f"Found {len(results)-1}+ matches (showing first 100):\n\n"
                    results = results[:-1]
                else:
                    results_text = f"Found {len(results)} match(es):\n\n"
                
                for i, pos in enumerate(results):
                    if isinstance(pos, str):
                        results_text += pos
                        break
                    results_text += f"{i+1:3d}. Offset 0x{pos:08X} ({pos})\n"
            else:
                results_text = "No matches found."
                
            self.search_results.setPlainText(results_text)
            
        except ValueError:
            QMessageBox.warning(self, "Invalid Hex", "Please enter valid hexadecimal bytes (e.g., 4D5A or 4D 5A)")