import sys
import os
import subprocess
import json
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QToolBar, QWidget,
    QVBoxLayout, QListWidget, QListWidgetItem, QDockWidget,
    QTextEdit, QSplitter, QFileDialog, QMessageBox, QLabel, QComboBox, QStyle, QScrollArea
)
from PyQt6.QtGui import QAction, QIcon, QFont, QShortcut, QKeySequence
from PyQt6.QtCore import Qt, QSize

# --- Helper Function to check for Volatility ---
def is_volatility_installed():
    """Checks if volatility3 is accessible."""
    try:
        # Use 'where' on Windows, 'which' on Linux/macOS
        command = "where" if sys.platform == "win32" else "which"
        subprocess.run([command, "vol"], check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

class MemoryAnalyzerWindow(QMainWindow):
    """
    Main window for the AI-Powered Memory Analyzer application.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI-Powered Memory Analyzer")
        self.setGeometry(100, 100, 1200, 800)

        # Cache results to avoid re-running plugins
        self.volatility_output_cache = {}

        # Create a central widget with a layout
        self.central_widget = QWidget()
        self.central_layout = QVBoxLayout(self.central_widget)
        self.central_layout.setContentsMargins(10, 10, 10, 10)

        # Dropdown (initially hidden) placed at the top
        self.view_dropdown = QComboBox()
        self.view_dropdown.addItems(["Process List", "Network Connections", "Commands"])
        self.view_dropdown.setVisible(False)
        self.view_dropdown.currentIndexChanged.connect(self.on_dropdown_selected)
        self.central_layout.addWidget(self.view_dropdown)
        
        # Create a scroll area for results
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_area.setWidget(self.scroll_content)
        self.scroll_area.setStyleSheet("QScrollArea { border: none; }")
        
        # Initialize the content area with a default message
        self.content_label = QTextEdit("Main content area. Open a file to start.")
        self.content_label.setReadOnly(True)
        self.content_label.setStyleSheet("font-size: 16px;")
        self.scroll_layout.addWidget(self.content_label)

        self.central_layout.addWidget(self.scroll_area)
        
        self.setCentralWidget(self.central_widget)

        # --- Create the foldable left panel (Dock Widget) ---
        self.create_left_panel()

        # Use a splitter to allow resizing between the dock and central widget
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.dock_widget)
        splitter.addWidget(self.central_widget)
        splitter.setSizes([250, 950]) # Initial sizes for the panels

        self.setCentralWidget(splitter)

        # --- Create Menus and Toolbar ---
        self.create_actions()
        self.create_menu_bar()
        self.create_toolbar()

        # Enable Ctrl+F for find in QTextEdit
        self.find_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        self.find_shortcut.activated.connect(self.show_find_dialog)

        # Check for Volatility
        if not is_volatility_installed():
            QMessageBox.critical(self, "Dependency Missing",
                                "Volatility 3 not found in your system's PATH.\n"
                                "Please install it using 'pip install volatility3' and ensure it's accessible.")

        self.current_file_path = None

    def show_find_dialog(self):
        """
        Shows the find dialog for the QTextEdit widget when Ctrl+F is pressed.
        """
        self.content_label.setFocus()
        # Trigger the find action to open the dialog
        self.content_label.find("", QTextDocument.FindFlag.FindBackward)  # Use a valid call to initiate search

    def open_memory_file(self):
        """
        Opens a memory image file (.raw), clears the analysis cache, 
        and displays the file's metadata.
        """
        # Open a native file dialog to let the user select a .raw file
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Open Memory Image", 
            "", 
            "Raw Memory Images (*.raw);;All Files (*)"
        )

        # Proceed only if the user selected a file
        if file_path:
            self.current_file_path = file_path
            # Clear the cache of any previous analysis results from another file
            self.volatility_output_cache.clear() 
            
            try:
                # Use the 'os' module to get file statistics
                stat = os.stat(file_path)
                size_mb = stat.st_size / (1024 * 1024)
                creation_time = datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                modification_time = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')

                # Create an HTML string to display the metadata in the main window
                metadata_text = (
                    f"<h2>Memory Image Loaded</h2>"
                    f"<p><b>File Path:</b> {file_path}</p>"
                    f"<p><b>Size:</b> {size_mb:.2f} MB</p>"
                    f"<p><b>Creation Time:</b> {creation_time}</p>"
                    f"<p><b>Last Modified:</b> {modification_time}</p><hr>"
                    f"<p>Select 'View' from the options list on the left to inspect the image.</p>"
                )
                
                # Update the UI with the new information
                self.content_label.setHtml(metadata_text)
                self.options_list.item(0).setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled) # Enable the view item
                self.results_list.clear() # Clear previous results
                self.results_list.setVisible(False) # Hide results list in dock

            except Exception as e:
                # If any error occurs (e.g., file permissions), show a message
                QMessageBox.critical(self, "Error", f"Failed to open or read file metadata: {e}")
                self.current_file_path = None
                self.options_list.item(0).setFlags(Qt.ItemFlag.ItemIsSelectable) # Disable view item

    def on_view_item_clicked(self, item):
        """
        Called when the user clicks the "View" item. Shows the dropdown in the main window.
        """
        if item.text() == "View" and self.current_file_path:
            self.view_dropdown.setVisible(True)
            self.content_label.setHtml(
                f"<h2>Select Analysis View</h2>"
                f"<p>Use the dropdown above to choose a view and display results below.</p>"
            )
            self.results_list.setVisible(False)  # Hide dock results since main window only

    def on_dropdown_selected(self, index):
        """
        Called when a dropdown option is selected. Runs the appropriate Volatility plugin and displays scrollable results.
        """
        selected_option = self.view_dropdown.itemText(index)
        
        # Map the user-friendly names to the actual Volatility plugin names
        plugin_map = {
            "Process List": "windows.pslist.PsList",
            "Network Connections": "windows.netscan.NetScan",
            "Commands": "windows.cmdline.CmdLine"
        }

        if selected_option not in plugin_map:
            return

        plugin_name = plugin_map[selected_option]
        data = self.run_volatility_plugin(plugin_name)

        if data:
            try:
                # Clear previous results
                self.content_label.clear()
                
                # Handle both old (Vol2-like) and new (Vol3) JSON structures
                if 'columns' in data and 'rows' in data:
                    # Old structure: {'columns': [...], 'rows': [[...], ...]}
                    headers = [col if isinstance(col, str) else col['name'] for col in data['columns']]
                    header_text = "\t".join(headers)
                    header_html = f"<p style='font-family: Consolas; font-size: 14px; font-weight: bold;'>{header_text}</p>"
                    self.content_label.append(header_html)
                    
                    for row in data['rows']:
                        if isinstance(row, list):
                            row_text = "\t".join(str(v) for v in row)
                        else:
                            row_text = str(row)
                        row_html = f"<p style='font-family: Consolas; font-size: 14px;'>{row_text}</p>"
                        self.content_label.append(row_html)
                else:
                    # New structure: list of dicts [{'Image': ..., 'PID': ..., ...}, ...]
                    if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                        # Extract headers from first item keys
                        headers = list(data[0].keys())
                        header_text = "\t".join(h for h in headers if h != '__children')
                        header_html = f"<p style='font-family: Consolas; font-size: 14px; font-weight: bold;'>{header_text}</p>"
                        self.content_label.append(header_html)
                        
                        for row_dict in data:
                            row_values = [str(row_dict.get(h, '')) for h in headers if h != '__children']
                            row_text = "\t".join(row_values)
                            row_html = f"<p style='font-family: Consolas; font-size: 14px;'>{row_text}</p>"
                            self.content_label.append(row_html)
                    else:
                        # Fallback: treat as string or simple list
                        self.content_label.append("<p>Unexpected data format. Raw output:</p>")
                        self.content_label.append(f"<pre>{json.dumps(data, indent=2)}</pre>")
                
                self.content_label.append(f"<p><i>Results for {plugin_name} displayed above.</i></p>")

            except (KeyError, IndexError, TypeError, AttributeError) as e:
                error_msg = f"Could not parse the data structure from Volatility.\nError: {e}"
                self.content_label.append(f"<p style='color: red;'>{error_msg}</p>")
                QMessageBox.critical(self, "Data Format Error", error_msg)

    def create_left_panel(self):
        """
        Creates the foldable left panel with options.
        A QDockWidget is inherently foldable/collapsible by the user.
        """
        self.dock_widget = QDockWidget("Tools", self)
        self.dock_widget.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea)

        # Create a container for the dock widget's contents
        dock_content_widget = QWidget()
        dock_layout = QVBoxLayout(dock_content_widget)
        dock_layout.setContentsMargins(5, 10, 5, 10) # Left, Top, Right, Bottom

        # Add a label for "Options"
        label = QLabel("Options")
        label.setStyleSheet("font-weight: bold; font-size: 14px;")
        dock_layout.addWidget(label)

        # Create the list of options (QListWidget)
        self.options_list = QListWidget()
        view_item = QListWidgetItem("View")
        view_item.setFlags(Qt.ItemFlag.ItemIsSelectable)  # Initially disabled
        self.options_list.addItem(view_item)
        self.options_list.addItem(QListWidgetItem("Analyze"))
        self.options_list.itemClicked.connect(self.on_view_item_clicked)
        self.options_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #ccc;
                border-radius: 5px;
                font-size: 14px;
            }
            QListWidget::item {
                padding: 10px;
            }
            QListWidget::item:hover {
                background-color: #eaf5ff; /* Light blue hover */
                color: black; /* Ensure text is visible */
            }
            QListWidget::item:selected {
                background-color: #d0e4f5;
                color: black;
            }
            QListWidget::item:disabled {
                color: #999;
            }
        """)
        dock_layout.addWidget(self.options_list)

        # Create the results list (initially hidden) - kept for compatibility but unused
        self.results_list = QListWidget()
        self.results_list.setVisible(False)
        dock_layout.addWidget(QLabel("Results:"))
        dock_layout.addWidget(self.results_list)

        self.dock_widget.setWidget(dock_content_widget)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self.dock_widget)

    def create_actions(self):
        """
        Create the actions for the menus and toolbar.
        """
        style = self.style()
        self.open_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_DialogOpenButton), "&Open File...", self)
        self.open_action.triggered.connect(self.open_memory_file)
        self.about_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_DialogHelpButton), "&About", self)

    def create_menu_bar(self):
        """
        Create the main menu bar for the application.
        """
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("&File")
        file_menu.addAction(self.open_action)
        file_menu.addSeparator()
        file_menu.addAction("E&xit", self.close)
        edit_menu = menu_bar.addMenu("&Edit")
        find_action = QAction("&Find", self)
        find_action.triggered.connect(self.show_find_dialog)
        edit_menu.addAction(find_action)
        help_menu = menu_bar.addMenu("&Help")
        help_menu.addAction(self.about_action)

    def create_toolbar(self):
        """
        Create the toolbar for quick access to actions.
        """
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)
        toolbar.addAction(self.open_action)
        toolbar.addSeparator()
        toolbar.addAction(self.about_action)

    def run_volatility_plugin(self, plugin_name):
        """
        Runs a Volatility 3 plugin and returns the parsed JSON output.
        """
        if not self.current_file_path:
            QMessageBox.warning(self, "No File", "Please open a memory image file first.")
            return None

        if plugin_name in self.volatility_output_cache:
            return self.volatility_output_cache[plugin_name]

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        self.content_label.append(f"<p>Running Volatility plugin: {plugin_name}...</p>")
        QApplication.processEvents()

        result = None
        try:
            command = [
                "vol",
                "-f", self.current_file_path,
                "--renderer", "json",
                plugin_name
            ]
            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            result = subprocess.run(command, capture_output=True, text=True, check=True, creationflags=creationflags)
            
            if not result.stdout:
                raise ValueError("Volatility produced no output.")

            parsed_json = json.loads(result.stdout)
            self.volatility_output_cache[plugin_name] = parsed_json
            return parsed_json

        except FileNotFoundError:
            QMessageBox.critical(self, "Error", "The 'vol' command was not found. Is Volatility 3 installed and in your PATH?")
            return None
        except subprocess.CalledProcessError as e:
            error_msg = f"Volatility failed with exit code {e.returncode}.\n\nStderr:\n{e.stderr}"
            QMessageBox.critical(self, "Volatility Error", error_msg)
            self.content_label.append(f"<p style='color: red;'>{error_msg}</p>")
            return None
        except (json.JSONDecodeError, ValueError) as e:
            error_msg = f"Failed to parse Volatility output.\nError: {e}\nRaw Output:\n{result.stdout if result else 'No output'}"
            QMessageBox.critical(self, "Parsing Error", error_msg)
            self.content_label.append(f"<p style='color: red;'>{error_msg}</p>")
            return None
        finally:
            QApplication.restoreOverrideCursor()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MemoryAnalyzerWindow()
    window.show()
    sys.exit(app.exec())