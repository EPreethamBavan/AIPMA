import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QToolBar, QWidget,
    QVBoxLayout, QListWidget, QListWidgetItem, QDockWidget,
    QSplitter, QFileDialog, QMessageBox, QLabel, QComboBox, QStyle, 
    QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView, QStackedWidget
)
from PyQt6.QtGui import QAction, QKeySequence, QShortcut
from PyQt6.QtCore import Qt, QSize, QThread, pyqtSignal

from core import is_volatility_installed, get_file_metadata, run_volatility_plugin
from chat_interface import ChatInterface
from datetime import datetime
import os
from dotenv import load_dotenv


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
            QMessageBox.critical(self, "Dependency Missing",
                                 "Volatility 3 not found. Install with 'pip install volatility3'.")
    
    def setup_main_view(self):
        """Setup the main analysis view"""
        main_layout = QVBoxLayout(self.main_view_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)

        self.view_dropdown = QComboBox()
        self.view_dropdown.addItems(["--select--", "Process List", "Network Connections", "Commands"])
        self.view_dropdown.setVisible(False)
        self.view_dropdown.currentIndexChanged.connect(self.on_dropdown_selected)
        main_layout.addWidget(self.view_dropdown)
        
        self.welcome_label = QLabel("<h2>Welcome to the AI-Powered Memory Analyzer</h2><p>Open a memory image file to begin analysis.</p>")
        self.welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.welcome_label.setStyleSheet("font-size: 16px;")
        main_layout.addWidget(self.welcome_label)

        self.results_table = QTableWidget()
        self.results_table.setVisible(False)
        self.results_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        main_layout.addWidget(self.results_table)

    def show_find_dialog(self):
        QMessageBox.information(self, "Find", "Find functionality for tables requires a custom implementation.")

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
                creation_time = datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                modification_time = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')

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

                self.options_list.item(0).setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
                self.options_list.item(1).setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
                self.results_list.clear()
                self.results_list.setVisible(False)

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to open or read file metadata: {e}")
                self.current_file_path = None

    def on_view_item_clicked(self, item):
        if item.text() == "View" and self.current_file_path:
            self.stacked_widget.setCurrentIndex(0)
            self.view_dropdown.setVisible(True)
            self.welcome_label.setText("<h2>Select Analysis View</h2><p>Choose a view from the dropdown above.</p>")
            self.welcome_label.setVisible(True)
            self.results_table.setVisible(False)
            self.results_list.setVisible(False)
        elif item.text() == "Chat":
            if self.current_file_path:
                self.stacked_widget.setCurrentIndex(1)
                if not self.agent_executor:
                    self.initialize_agent()
            else:
                QMessageBox.warning(self, "No Memory File", 
                                  "Please open a memory image file first before using the chat feature.")
    
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
        self.chat_interface.add_ai_message(f"❌ <b>Agent Initialization Failed:</b><br>{error_message}")
        self.chat_interface.update_status("Error", "#DC3545")

    def on_dropdown_selected(self, index):
        selected_option = self.view_dropdown.itemText(index)
        plugin_map = {
            "--select--": None,
            "Process List": "windows.pslist.PsList",
            "Network Connections": "windows.netscan.NetScan",
            "Commands": "windows.cmdline.CmdLine"
        }
        plugin_name = plugin_map.get(selected_option)
        if not plugin_name:
            self.results_table.setVisible(False)
            self.welcome_label.setText("<h2>Please select an analysis option from the dropdown above.</h2>")
            self.welcome_label.setVisible(True)
            return

        self.welcome_label.setText("<h2>Running Analysis...</h2><p>Please wait.</p>")
        self.welcome_label.setVisible(True)
        self.results_table.setVisible(False)
        QApplication.processEvents()
        
        data = run_volatility_plugin(self.current_file_path, plugin_name, self.volatility_output_cache, lambda x: None)
        
        if data:
            self.welcome_label.setVisible(False)
            self.results_table.setVisible(True)
            self.populate_table(data, selected_option)
        else:
            self.welcome_label.setText("<h2>No data returned from analysis.</h2>")

    def populate_table(self, data, selected_option=None):
        self.results_table.clear()
        
        headers = []
        rows_data = []

        if isinstance(data, dict) and 'columns' in data and 'rows' in data:
            headers = [col if isinstance(col, str) else col['name'] for col in data['columns']]
            rows_data = data['rows']
        elif isinstance(data, list) and data and isinstance(data[0], dict):
            headers = [h for h in data[0].keys() if h != '__children']
            rows_data = [[row.get(h, '') for h in headers] for row in data]
        
        if selected_option == "Commands":
            desired_order = ["PID", "Process", "Args"]
            headers = [h for h in desired_order if h in headers]
            if isinstance(data, list):
                rows_data = [[row.get(h, '') for h in headers] for row in data]
            elif isinstance(data, dict):
                rows_data = [[row[headers.index(h)] if h in headers else '' for h in headers] for row in data['rows']]

        if not headers or not rows_data:
            self.results_table.setVisible(False)
            self.welcome_label.setText("<h2>No results to display.</h2>")
            self.welcome_label.setVisible(True)
            return

        self.results_table.setColumnCount(len(headers))
        self.results_table.setHorizontalHeaderLabels(headers)
        self.results_table.setRowCount(len(rows_data))

        for row_idx, row in enumerate(rows_data):
            for col_idx, cell_value in enumerate(row):
                item = QTableWidgetItem(str(cell_value))
                self.results_table.setItem(row_idx, col_idx, item)

        self.results_table.resizeColumnsToContents()

    def create_left_panel(self):
        self.dock_widget = QDockWidget("Tools", self)
        self.dock_widget.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea)

        dock_content_widget = QWidget()
        dock_layout = QVBoxLayout(dock_content_widget)

        label = QLabel("Options")
        label.setStyleSheet("font-weight: bold; font-size: 14px;")
        dock_layout.addWidget(label)

        self.options_list = QListWidget()
        view_item = QListWidgetItem("View")
        view_item.setFlags(Qt.ItemFlag.ItemIsSelectable)  # Disabled initially
        self.options_list.addItem(view_item)
        
        chat_item = QListWidgetItem("Chat")
        chat_item.setFlags(Qt.ItemFlag.ItemIsSelectable)  # Disabled initially
        self.options_list.addItem(chat_item)
        
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
        self.open_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_DialogOpenButton), "&Open File...", self)
        self.open_action.triggered.connect(self.open_memory_file)
        self.about_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_DialogHelpButton), "&About", self)

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

        help_menu = menu_bar.addMenu("&Help")
        help_menu.addAction(self.about_action)

    def create_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)
        toolbar.addAction(self.open_action)
        toolbar.addSeparator()
        toolbar.addAction(self.about_action)
    
    def closeEvent(self, event):
        """Handle application close event"""
        if hasattr(self, 'agent_worker') and self.agent_worker and self.agent_worker.isRunning():
            self.agent_worker.stop()
            
        if hasattr(self, 'chat_interface') and self.chat_interface:
            self.chat_interface.cleanup()
            
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    app.setStyleSheet("""
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
    """)

    window = MemoryAnalyzerWindow()
    window.show()
    sys.exit(app.exec())