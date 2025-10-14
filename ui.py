import os
import re
import sys
from datetime import datetime

from dotenv import load_dotenv
from PyQt6.QtCore import (
    QAbstractTableModel,
    QSize,
    Qt,
    QThread,
    QVariant,
    pyqtSignal,
)
from PyQt6.QtGui import QAction, QIcon, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDockWidget,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from chat_interface import ChatInterface
from core import get_file_metadata, is_volatility_installed, run_volatility_plugin
from analytics import AnalyticsWidget
from analysis_widget import AnalysisWidget


class MemoryDataTableModel(QAbstractTableModel):
    """Custom table model for memory forensics data with filtering"""

    def __init__(self, data=None, headers=None):
        super().__init__()
        self._data = data or []
        self._headers = headers or []
        self._original_data = self._data.copy()

    def rowCount(self, parent=None):
        return len(self._data)

    def columnCount(self, parent=None):
        return len(self._headers)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._data)):
            return QVariant()

        if role == Qt.ItemDataRole.DisplayRole:
            return str(self._data[index.row()][index.column()])
        return QVariant()

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if (
            role == Qt.ItemDataRole.DisplayRole
            and orientation == Qt.Orientation.Horizontal
        ):
            if 0 <= section < len(self._headers):
                return self._headers[section]
        return QVariant()


    def update_data(self, data, headers):
        """Update table data"""
        self.beginResetModel()
        self._data = data
        self._headers = headers
        self._original_data = data.copy()
        self.endResetModel()

    def filter_data(self, search_text="", column_filters=None):
        """Filter data based on search text and column filters"""
        self.beginResetModel()

        filtered_data = self._original_data.copy()

        # Apply search filter
        if search_text:
            search_lower = search_text.lower()
            filtered_data = [
                row
                for row in filtered_data
                if any(search_lower in str(cell).lower() for cell in row)
            ]

        # Apply column filters
        if column_filters:
            for col_idx, filter_value in column_filters.items():
                if filter_value:
                    filter_lower = filter_value.lower()
                    filtered_data = [
                        row
                        for row in filtered_data
                        if filter_lower in str(row[col_idx]).lower()
                    ]

        self._data = filtered_data
        self.endResetModel()


class AgentInitializationWorker(QThread):
    """Worker thread for initializing the memory forensics agent"""

    agent_ready_signal = pyqtSignal(object)
    error_signal = pyqtSignal(str)

    def __init__(self, memory_file_path):
        super().__init__()
        self.memory_file_path = memory_file_path
        self._is_running = True

    def run(self):
        if not self._is_running:
            return

        try:
            from memory_agent import create_memory_forensics_agent

            agent_executor = create_memory_forensics_agent(self.memory_file_path)
            if self._is_running:
                self.agent_ready_signal.emit(agent_executor)

        except Exception as e:
            if self._is_running:
                self.error_signal.emit(f"Failed to initialize agent: {str(e)}")

    def stop(self):
        self._is_running = False
        self.wait()


class MemoryAnalyzerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI-Powered Memory Analyzer")
        self.setGeometry(100, 100, 1200, 800)

        self.volatility_output_cache = {}
        self.current_file_path = None
        self.agent_worker = None
        self.agent_executor = None

        load_dotenv()

        self.stacked_widget = QStackedWidget()

        self.main_view_widget = QWidget()
        self.setup_main_view()

        self.chat_interface = ChatInterface()
        self.analytics_widget = None
        self.analysis_widget = None

        self.stacked_widget.addWidget(self.main_view_widget)
        self.stacked_widget.addWidget(self.chat_interface)

        self.setCentralWidget(self.stacked_widget)

        self.create_left_panel()

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.dock_widget)
        splitter.addWidget(self.stacked_widget)
        splitter.setSizes([250, 950])
        self.setCentralWidget(splitter)

        self.create_actions()
        self.create_menu_bar()
        self.create_toolbar()

        self.find_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        self.find_shortcut.activated.connect(self.show_find_dialog)

        if not is_volatility_installed():
            QMessageBox.critical(
                self,
                "Dependency Missing",
                "Volatility 3 not found. Install with 'pip install volatility3'.",
            )

    def setup_main_view(self):
        """Setup the main analysis view"""
        main_layout = QVBoxLayout(self.main_view_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # Analysis type dropdown
        self.view_dropdown = QComboBox()
        self.view_dropdown.addItems(
            ["--select--", "Process List", "Network Connections", "Commands"]
        )
        self.view_dropdown.setVisible(False)
        self.view_dropdown.currentIndexChanged.connect(self.on_dropdown_selected)
        main_layout.addWidget(self.view_dropdown)

        # Search and filter controls
        self.search_filter_frame = self.create_search_filter_controls()
        self.search_filter_frame.setVisible(False)
        main_layout.addWidget(self.search_filter_frame)

        self.welcome_label = QLabel(
            "<h2>Welcome to the AI-Powered Memory Analyzer</h2><p>Open a memory image file to begin analysis.</p>"
        )
        self.welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.welcome_label.setStyleSheet("font-size: 16px;")
        main_layout.addWidget(self.welcome_label)

        # Enhanced table with model
        self.table_model = MemoryDataTableModel()

        self.results_table = QTableWidget()
        self.results_table.setVisible(False)
        self.results_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        main_layout.addWidget(self.results_table)

        # Store current data for filtering
        self.current_data = []
        self.current_headers = []
        self.column_filters = {}
        self.column_filter_inputs = {}

        # Initialize filter UI state

    def create_search_filter_controls(self):
        """Create search and filter controls"""
        frame = QFrame()
        frame.setStyleSheet(
            """
            QFrame {
                background-color: #F8F9FA;
                border: 1px solid #E0E0E0;
                border-radius: 8px;
                padding: 8px;
                margin: 4px 0px;
            }
        """
        )

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Search controls row
        search_layout = QHBoxLayout()

        # Global search
        search_label = QLabel("🔍 Search:")
        search_label.setStyleSheet("font-weight: bold; color: #495057;")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search across all columns...")
        self.search_input.setStyleSheet(
            """
            QLineEdit {
                padding: 8px 12px;
                border: 2px solid #DEE2E6;
                border-radius: 6px;
                font-size: 13px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #007AFF;
                outline: none;
            }
        """
        )
        self.search_input.textChanged.connect(self.on_search_changed)

        # Clear search button
        self.clear_search_btn = QPushButton("Clear")
        self.clear_search_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #6C757D;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #5A6268;
            }
        """
        )
        self.clear_search_btn.clicked.connect(self.clear_all_filters)

        # Toggle filters button
        self.toggle_filters_btn = QPushButton("Show Column Filters")
        self.toggle_filters_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #007AFF;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #0056CC;
            }
        """
        )
        self.toggle_filters_btn.clicked.connect(self.toggle_column_filters)

        # Results count
        self.results_count_label = QLabel("")
        self.results_count_label.setStyleSheet("color: #6C757D; font-weight: bold;")

        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input, 1)
        search_layout.addWidget(self.clear_search_btn)
        search_layout.addWidget(self.toggle_filters_btn)
        search_layout.addWidget(self.results_count_label)

        layout.addLayout(search_layout)

        # Column filters (initially hidden)
        self.column_filters_frame = QFrame()
        self.column_filters_layout = QVBoxLayout(self.column_filters_frame)
        self.column_filters_frame.setVisible(False)
        layout.addWidget(self.column_filters_frame)

        return frame

    def show_find_dialog(self):
        if self.search_filter_frame.isVisible():
            self.search_input.setFocus()
            self.search_input.selectAll()
        else:
            QMessageBox.information(
                self, "Find", "Please open a memory image and select a view to search."
            )

    def on_search_changed(self):
        """Handle search text changes"""
        self.apply_filters()

    def toggle_column_filters(self):
        """Toggle column filter visibility"""
        is_visible = self.column_filters_frame.isVisible()
        self.column_filters_frame.setVisible(not is_visible)
        self.toggle_filters_btn.setText(
            "Hide Column Filters" if not is_visible else "Show Column Filters"
        )

    def create_column_filters(self, headers):
        """Create filter inputs for each column"""
        # Clear existing filters safely including nested layouts
        while self.column_filters_layout.count():
            child = self.column_filters_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
            elif child.layout():
                # Clear nested layouts properly
                layout = child.layout()
                while layout.count():
                    nested_child = layout.takeAt(0)
                    if nested_child.widget():
                        nested_child.widget().deleteLater()
                # Delete the layout itself
                layout.setParent(None)

        self.column_filter_inputs = {}

        # Create filter for each column
        filters_grid_layout = QHBoxLayout()

        for i, header in enumerate(headers):
            filter_frame = QFrame()
            filter_frame.setStyleSheet(
                """
                QFrame {
                    background-color: white;
                    border: 1px solid #CED4DA;
                    border-radius: 4px;
                    margin: 2px;
                }
            """
            )

            filter_layout = QVBoxLayout(filter_frame)
            filter_layout.setContentsMargins(8, 4, 8, 4)
            filter_layout.setSpacing(2)

            # Column label
            col_label = QLabel(header)
            col_label.setStyleSheet(
                "font-size: 11px; font-weight: bold; color: #495057;"
            )

            # Filter input
            filter_input = QLineEdit()
            filter_input.setPlaceholderText(f"Filter {header}...")
            filter_input.setStyleSheet(
                """
                QLineEdit {
                    padding: 4px 6px;
                    border: 1px solid #CED4DA;
                    border-radius: 3px;
                    font-size: 11px;
                }
                QLineEdit:focus {
                    border-color: #007AFF;
                }
            """
            )
            filter_input.textChanged.connect(
                lambda text, col=i: self.on_column_filter_changed(col, text)
            )

            filter_layout.addWidget(col_label)
            filter_layout.addWidget(filter_input)

            self.column_filter_inputs[i] = filter_input
            filters_grid_layout.addWidget(filter_frame)

        self.column_filters_layout.addLayout(filters_grid_layout)

    def on_column_filter_changed(self, column, text):
        """Handle column filter changes"""
        if text.strip():
            self.column_filters[column] = text
        elif column in self.column_filters:
            del self.column_filters[column]

        self.apply_filters()

    def apply_filters(self):
        """Apply search and column filters"""
        if not self.current_data:
            return

        search_text = self.search_input.text().strip()
        filtered_data = self.current_data.copy()

        # Apply global search
        if search_text:
            search_lower = search_text.lower()
            filtered_data = [
                row
                for row in filtered_data
                if any(search_lower in str(cell).lower() for cell in row)
            ]

        # Apply column filters
        for col_idx, filter_value in self.column_filters.items():
            if filter_value and col_idx < len(self.current_headers):
                filter_lower = filter_value.lower()
                filtered_data = [
                    row
                    for row in filtered_data
                    if col_idx < len(row) and filter_lower in str(row[col_idx]).lower()
                ]

        # Update table
        self.update_table_with_data(filtered_data, self.current_headers)

        # Update results count
        total_count = len(self.current_data)
        filtered_count = len(filtered_data)
        if filtered_count < total_count:
            self.results_count_label.setText(
                f"Showing {filtered_count} of {total_count} results"
            )
        else:
            self.results_count_label.setText(f"Total: {total_count} results")

    def clear_all_filters(self):
        """Clear all search and filter inputs"""
        self.search_input.clear()

        # Clear column filter inputs safely
        if hasattr(self, "column_filter_inputs"):
            for filter_input in self.column_filter_inputs.values():
                filter_input.clear()

        self.column_filters.clear()
        self.apply_filters()

    def reset_filter_ui(self):
        """Reset filter UI to initial state"""
        # Hide column filters
        if hasattr(self, "column_filters_frame"):
            self.column_filters_frame.setVisible(False)

        # Reset toggle button text
        if hasattr(self, "toggle_filters_btn"):
            self.toggle_filters_btn.setText("Show Column Filters")

        # Clear all existing column filters
        if hasattr(self, "column_filters_layout"):
            while self.column_filters_layout.count():
                child = self.column_filters_layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()
                elif child.layout():
                    # Clear nested layouts
                    layout = child.layout()
                    while layout.count():
                        nested_child = layout.takeAt(0)
                        if nested_child.widget():
                            nested_child.widget().deleteLater()

        # Clear search input
        if hasattr(self, "search_input"):
            self.search_input.clear()

        # Clear results count
        if hasattr(self, "results_count_label"):
            self.results_count_label.clear()

        # Reset internal state
        self.column_filters.clear()
        self.column_filter_inputs.clear()
        self.current_data.clear()
        self.current_headers.clear()


    def update_table_with_data(self, data, headers):
        """Update table widget with data"""
        self.results_table.clear()

        if not data or not headers:
            return

        self.results_table.setColumnCount(len(headers))
        self.results_table.setHorizontalHeaderLabels(headers)
        self.results_table.setRowCount(len(data))

        for row_idx, row in enumerate(data):
            for col_idx, cell_value in enumerate(row):
                item = QTableWidgetItem(str(cell_value))
                self.results_table.setItem(row_idx, col_idx, item)

        self.results_table.resizeColumnsToContents()

    def open_memory_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Memory Image", "", "Raw Memory Images (*.raw);;All Files (*)"
        )
        if file_path:
            self.current_file_path = file_path
            self.volatility_output_cache.clear()
            try:
                stat = os.stat(file_path)
                size_mb = stat.st_size / (1024 * 1024)
                creation_time = datetime.fromtimestamp(stat.st_ctime).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                modification_time = datetime.fromtimestamp(stat.st_mtime).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                metadata_html = (
                    f"<h2>Memory Image Loaded</h2>"
                    f"<p><b>File Path:</b> {file_path}</p>"
                    f"<p><b>Size:</b> {size_mb:.2f} MB</p>"
                    f"<p><b>Creation Time:</b> {creation_time}</p>"
                    f"<p><b>Last Modified:</b> {modification_time}</p><hr>"
                    f"<p>Select 'View' from the Options panel on the left to begin analysis.</p>"
                )

                self.welcome_label.setText(metadata_html)
                self.welcome_label.setVisible(True)
                self.results_table.setVisible(False)
                self.view_dropdown.setVisible(False)

                self.options_list.item(0).setFlags(
                    Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled
                )
                self.options_list.item(1).setFlags(
                    Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled
                )
                self.options_list.item(2).setFlags(
                    Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled
                )
                self.options_list.item(3).setFlags(
                    Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled
                )
                self.results_list.clear()
                self.results_list.setVisible(False)

            except Exception as e:
                QMessageBox.critical(
                    self, "Error", f"Failed to open or read file metadata: {e}"
                )
                self.current_file_path = None

    def on_view_item_clicked(self, item):
        if item.text() == "View Memory Data" and self.current_file_path:
            self.stacked_widget.setCurrentIndex(0)
            # Reset filter UI when switching back to view
            self.reset_filter_ui()
            self.view_dropdown.setVisible(True)
            self.search_filter_frame.setVisible(False)
            self.welcome_label.setText(
                "<h2>Select Analysis View</h2><p>Choose a view from the dropdown above.</p>"
            )
            self.welcome_label.setVisible(True)
            self.results_table.setVisible(False)
            self.results_list.setVisible(False)
        elif item.text() == "AI ChatBot":
            if self.current_file_path:
                self.stacked_widget.setCurrentIndex(1)
                if not self.agent_executor:
                    self.initialize_agent()
            else:
                QMessageBox.warning(
                    self,
                    "No Memory File",
                    "Please open a memory image file first before using the chat feature.",
                )
        elif item.text() == "Visualization":
            if self.current_file_path:
                self.show_analytics()
            else:
                QMessageBox.warning(
                    self,
                    "No Memory File",
                    "Please open a memory image file first before viewing analytics.",
                )
        elif item.text() == "Analysis":
            if self.current_file_path:
                self.show_advanced_analysis()
            else:
                QMessageBox.warning(
                    self,
                    "No Memory File",
                    "Please open a memory image file first before running advanced analysis.",
                )

    def initialize_agent(self):
        """Initialize the memory forensics agent in background"""
        if self.agent_worker and self.agent_worker.isRunning():
            return

        self.chat_interface.add_ai_message(
            "🔄 <b>Initializing memory forensics agent...</b><br>"
            "This may take a few moments as I analyze the memory dump."
        )
        self.chat_interface.update_status("Initializing...", "#FFC107")

        self.agent_worker = AgentInitializationWorker(self.current_file_path)
        self.agent_worker.agent_ready_signal.connect(self.on_agent_ready)
        self.agent_worker.error_signal.connect(self.on_agent_error)
        self.agent_worker.start()

    def on_agent_ready(self, agent_executor):
        """Called when agent is successfully initialized"""
        self.agent_executor = agent_executor
        self.chat_interface.set_agent_executor(agent_executor)
        self.chat_interface.update_status("Ready", "#28A745")

    def on_agent_error(self, error_message):
        """Called when agent initialization fails"""
        self.chat_interface.add_ai_message(
            f"❌ <b>Agent Initialization Failed:</b><br>{error_message}"
        )
        self.chat_interface.update_status("Error", "#DC3545")

    def on_dropdown_selected(self, index):
        selected_option = self.view_dropdown.itemText(index)
        plugin_map = {
            "--select--": None,
            "Process List": "windows.pslist.PsList",
            "Network Connections": "windows.netscan.NetScan",
            "Commands": "windows.cmdline.CmdLine",
        }
        plugin_name = plugin_map.get(selected_option)

        # Always reset filter UI when changing views
        self.reset_filter_ui()

        if not plugin_name:
            self.results_table.setVisible(False)
            self.search_filter_frame.setVisible(False)
            self.welcome_label.setText(
                "<h2>Please select an analysis option from the dropdown above.</h2>"
            )
            self.welcome_label.setVisible(True)
            return

        self.welcome_label.setText("<h2>Running Analysis...</h2><p>Please wait.</p>")
        self.welcome_label.setVisible(True)
        self.results_table.setVisible(False)
        QApplication.processEvents()

        data = run_volatility_plugin(
            self.current_file_path,
            plugin_name,
            self.volatility_output_cache,
            lambda x: None,
        )

        if data:
            self.welcome_label.setVisible(False)
            self.results_table.setVisible(True)
            self.populate_table(data, selected_option)
        else:
            self.search_filter_frame.setVisible(False)
            self.welcome_label.setText("<h2>No data returned from analysis.</h2>")

    def populate_table(self, data, selected_option=None):
        headers = []
        rows_data = []

        if isinstance(data, dict) and "columns" in data and "rows" in data:
            headers = [
                col if isinstance(col, str) else col["name"] for col in data["columns"]
            ]
            rows_data = data["rows"]
        elif isinstance(data, list) and data and isinstance(data[0], dict):
            headers = [h for h in data[0].keys() if h != "__children"]
            rows_data = [[row.get(h, "") for h in headers] for row in data]

        if selected_option == "Commands":
            desired_order = ["PID", "Process", "Args"]
            headers = [h for h in desired_order if h in headers]
            if isinstance(data, list):
                rows_data = [[row.get(h, "") for h in headers] for row in data]
            elif isinstance(data, dict):
                rows_data = [
                    [row[headers.index(h)] if h in headers else "" for h in headers]
                    for row in data["rows"]
                ]

        if not headers or not rows_data:
            self.results_table.setVisible(False)
            self.search_filter_frame.setVisible(False)
            self.welcome_label.setText("<h2>No results to display.</h2>")
            self.welcome_label.setVisible(True)
            return

        # Store data for filtering
        self.current_data = rows_data
        self.current_headers = headers

        # Show search/filter controls
        self.search_filter_frame.setVisible(True)

        # Reset filter UI state first
        self.column_filters_frame.setVisible(False)
        self.toggle_filters_btn.setText("Show Column Filters")

        # Create column filters (this will clear existing ones)
        self.create_column_filters(headers)

        # Clear existing filters and reset state
        self.search_input.clear()
        self.column_filters.clear()

        # Update table
        self.update_table_with_data(rows_data, headers)

        # Update results count
        self.results_count_label.setText(f"Total: {len(rows_data)} results")

    def create_left_panel(self):
        self.dock_widget = QDockWidget("Tools", self)
        self.dock_widget.setAllowedAreas(
            Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea
        )

        dock_content_widget = QWidget()
        dock_layout = QVBoxLayout(dock_content_widget)

        label = QLabel("Options")
        label.setStyleSheet("font-weight: bold; font-size: 14px;")
        dock_layout.addWidget(label)

        self.options_list = QListWidget()
        view_item = QListWidgetItem("View Memory Data")
        view_item.setFlags(Qt.ItemFlag.ItemIsSelectable)  # Disabled initially
        self.options_list.addItem(view_item)

        chat_item = QListWidgetItem("AI ChatBot")
        chat_item.setFlags(Qt.ItemFlag.ItemIsSelectable)  # Disabled initially
        self.options_list.addItem(chat_item)
        
        analytics_item = QListWidgetItem("Visualization")
        analytics_item.setFlags(Qt.ItemFlag.ItemIsSelectable)  # Disabled initially
        self.options_list.addItem(analytics_item)
        
        analysis_item = QListWidgetItem("Analysis")
        analysis_item.setFlags(Qt.ItemFlag.ItemIsSelectable)  # Disabled initially
        self.options_list.addItem(analysis_item)

        self.options_list.itemClicked.connect(self.on_view_item_clicked)
        dock_layout.addWidget(self.options_list)

        self.results_list = QListWidget()
        self.results_list.setVisible(False)
        dock_layout.addWidget(QLabel("Results:"))
        dock_layout.addWidget(self.results_list)

        self.dock_widget.setWidget(dock_content_widget)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self.dock_widget)

    def create_actions(self):
        style = self.style()
        self.open_action = QAction(
            style.standardIcon(QStyle.StandardPixmap.SP_DialogOpenButton),
            "&Open File...",
            self,
        )
        self.open_action.triggered.connect(self.open_memory_file)
        
        self.analytics_action = QAction(
            style.standardIcon(QStyle.StandardPixmap.SP_ComputerIcon),
            "&Data Analytics",
            self,
        )
        self.analytics_action.triggered.connect(self.show_analytics)
        
        self.about_action = QAction(
            style.standardIcon(QStyle.StandardPixmap.SP_DialogHelpButton),
            "&About",
            self,
        )

    def create_menu_bar(self):
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("&File")
        file_menu.addAction(self.open_action)
        file_menu.addSeparator()
        file_menu.addAction("E&xit", self.close)

        edit_menu = menu_bar.addMenu("&Edit")
        find_action = QAction("&Find", self)
        find_action.triggered.connect(self.show_find_dialog)
        edit_menu.addAction(find_action)
        
        analysis_menu = menu_bar.addMenu("&Analysis")
        analysis_menu.addAction(self.analytics_action)

        help_menu = menu_bar.addMenu("&Help")
        help_menu.addAction(self.about_action)

    def create_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)
        toolbar.addAction(self.open_action)
        toolbar.addSeparator()
        toolbar.addAction(self.analytics_action)
        toolbar.addSeparator()
        toolbar.addAction(self.about_action)

    def show_analytics(self):
        """Show the data analytics and visualization screen"""
        if not self.current_file_path:
            QMessageBox.warning(
                self,
                "No Memory File",
                "Please open a memory image file first.",
            )
            return
        
        # Check if we have volatility data
        if not self.volatility_output_cache:
            QMessageBox.warning(
                self,
                "No Analysis Data",
                "Please run some Volatility analysis first to generate data for analytics.",
            )
            return
        
        try:
            # Import volatility runner to get the data
            from volatility import VolatilityPluginRunner
            from memory_agent import create_memory_forensics_agent
            from analytics import MemoryDataAnalyzer, AnalyticsVisualizer
            
            # Get the data using the existing cache or run analysis
            volatility_runner = VolatilityPluginRunner()
            volatility_runner.current_file_path = self.current_file_path
            volatility_runner.volatility_output_cache = self.volatility_output_cache
            
            # Run all plugins to get comprehensive data
            results, metadata = volatility_runner.run_all_plugins(self.current_file_path)
            
            # Create analytics widget if it doesn't exist or update it
            if self.analytics_widget is None:
                self.analytics_widget = AnalyticsWidget(metadata, results)
                self.stacked_widget.addWidget(self.analytics_widget)
            else:
                # Update existing widget with new data
                self.analytics_widget.analyzer = MemoryDataAnalyzer(metadata, results)
                self.analytics_widget.visualizer = AnalyticsVisualizer(self.analytics_widget.analyzer)
                self.analytics_widget.generate_analytics()
            
            # Switch to analytics view
            analytics_index = self.stacked_widget.indexOf(self.analytics_widget)
            self.stacked_widget.setCurrentIndex(analytics_index)
            
            # Update left panel to show analytics is active
            for i in range(self.options_list.count()):
                item = self.options_list.item(i)
                if item.text() == "Visualization":
                    item.setSelected(True)
                    break
                    
        except Exception as e:
            QMessageBox.critical(
                self,
                "Analytics Error",
                f"Failed to load analytics: {str(e)}",
            )

    def show_advanced_analysis(self):
        """Show the advanced analysis screen"""
        if not self.current_file_path:
            QMessageBox.warning(
                self,
                "No Memory File",
                "Please open a memory image file first.",
            )
            return
        
        try:
            # Create analysis widget if it doesn't exist or update it
            if self.analysis_widget is None:
                self.analysis_widget = AnalysisWidget(self.current_file_path)
                self.stacked_widget.addWidget(self.analysis_widget)
            else:
                # Update existing widget with new file path
                self.analysis_widget.set_file_path(self.current_file_path)
            
            # Switch to analysis view
            analysis_index = self.stacked_widget.indexOf(self.analysis_widget)
            self.stacked_widget.setCurrentIndex(analysis_index)
            
            # Update left panel to show analysis is active
            for i in range(self.options_list.count()):
                item = self.options_list.item(i)
                if item.text() == "Analysis":
                    item.setSelected(True)
                    break
                    
        except Exception as e:
            QMessageBox.critical(
                self,
                "Analysis Error",
                f"Failed to load advanced analysis: {str(e)}",
            )

    def closeEvent(self, event):
        """Handle application close event"""
        if (
            hasattr(self, "agent_worker")
            and self.agent_worker
            and self.agent_worker.isRunning()
        ):
            self.agent_worker.stop()

        if hasattr(self, "chat_interface") and self.chat_interface:
            self.chat_interface.cleanup()

        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    app.setStyleSheet(
        """
        QMainWindow, QWidget {
            background-color: #FFFFFF;
            color: #000000;
        }
        QWidget {
            font-size: 14px;
        }
        QTableWidget {
            background-color: #FFFFFF;
            color: #000000;
            border: 1px solid #DDDDDD;
            gridline-color: #E0E0E0;
            selection-background-color: #D0E4F5; /* Light blue selection */
            selection-color: #000000;
        }
        QHeaderView::section {
            background-color: #F8F8F8; /* Light gray header */
            padding: 6px;
            border: 1px solid #DDDDDD;
            font-weight: bold;
        }
        QTableWidget::item {
             padding: 6px;
        }
        QTableWidget::item:alternate {
             background-color: #FDFDFD;
        }
        QComboBox {
            background-color: #FFFFFF;
            color: #000000;
            border: 1px solid #CCCCCC;
            padding: 4px;
        }
        QComboBox QAbstractItemView {
            background-color: #FFFFFF;
            selection-background-color: #F2F2F2;
            color: #000000;
        }
        QListWidget {
            background-color: #FAFAFA;
            color: #000000;
            border: 1px solid #E0E0E0;
        }
        QDockWidget {
            background-color: #FAFAFA;
            color: #000000;
            border: 1px solid #E0E0E0;
        }
        QToolBar {
            background-color: #FAFAFA;
            border: 1px solid #E0E0E0;
        }
        QMenuBar {
            background-color: #FFFFFF;
            color: #000000;
        }
        QMenuBar::item:selected {
            background-color: #F2F2F2;
        }
        QMenu {
            background-color: #FFFFFF;
            color: #000000;
        }
        QMenu::item:selected {
            background-color: #F2F2F2;
        }
        QPushButton {
            background-color: #FFFFFF;
            color: #000000;
            border: 1px solid #CCCCCC;
            padding: 6px;
            border-radius: 4px;
        }
        QPushButton:hover {
            background-color: #F9F9F9;
        }
        QLabel {
            color: #000000;
        }
    """
    )

    window = MemoryAnalyzerWindow()
    window.show()
    sys.exit(app.exec())
