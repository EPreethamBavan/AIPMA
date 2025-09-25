import sys
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, 
    QPushButton, QScrollArea, QFrame, QLabel, QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QTextCursor
import time
from datetime import datetime

class TypewriterEffect(QThread):
    """Thread to simulate typewriter effect for AI responses"""
    character_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()
    
    def __init__(self, text, delay=50):
        super().__init__()
        self.text = text
        self.delay = delay
        self.is_running = True
    
    def run(self):
        for char in self.text:
            if not self.is_running:
                break
            self.character_signal.emit(char)
            self.msleep(self.delay)
        self.finished_signal.emit()
    
    def stop(self):
        self.is_running = False
        self.wait()

class ChatBubble(QFrame):
    """Custom widget for chat message bubbles"""
    
    def __init__(self, message, is_user=True, timestamp=None):
        super().__init__()
        self.is_user = is_user
        self.message = message
        self.timestamp = timestamp or datetime.now().strftime("%H:%M")
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        
        self.message_label = QLabel()
        self.message_label.setText(self.message)
        self.message_label.setWordWrap(True)
        self.message_label.setTextFormat(Qt.TextFormat.RichText)
        self.message_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        
        timestamp_label = QLabel(self.timestamp)
        timestamp_label.setStyleSheet("color: #666; font-size: 10px;")
        
        if self.is_user:
            self.setStyleSheet("""
                QFrame {
                    background-color: #007AFF;
                    color: white;
                    border-radius: 18px;
                    margin: 2px 50px 2px 2px;
                }
                QLabel {
                    color: white;
                    font-size: 14px;
                }
            """)
            layout.addWidget(self.message_label)
            layout.addWidget(timestamp_label, alignment=Qt.AlignmentFlag.AlignRight)
        else:
            self.setStyleSheet("""
                QFrame {
                    background-color: #E5E5EA;
                    color: black;
                    border-radius: 18px;
                    margin: 2px 2px 2px 50px;
                }
                QLabel {
                    color: black;
                    font-size: 14px;
                }
            """)
            layout.addWidget(self.message_label)
            layout.addWidget(timestamp_label, alignment=Qt.AlignmentFlag.AlignLeft)

class TypingIndicator(QFrame):
    """Animated typing indicator for AI responses"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.timer = QTimer()
        self.timer.timeout.connect(self.animate)
        self.dot_count = 0
    
    def setup_ui(self):
        self.setStyleSheet("""
            QFrame {
                background-color: #E5E5EA;
                border-radius: 18px;
                margin: 2px 2px 2px 50px;
                padding: 10px;
            }
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(15, 10, 15, 10)
        
        avatar_label = QLabel("🤖")
        avatar_label.setStyleSheet("font-size: 16px;")
        
        self.typing_label = QLabel("AI is thinking")
        self.typing_label.setStyleSheet("color: #666; font-style: italic;")
        
        layout.addWidget(avatar_label)
        layout.addWidget(self.typing_label)
        layout.addStretch()
    
    def start_animation(self):
        self.timer.start(500)
    
    def stop_animation(self):
        self.timer.stop()
    
    def animate(self):
        self.dot_count = (self.dot_count + 1) % 4
        dots = "." * self.dot_count
        self.typing_label.setText(f"AI is thinking{dots}")

class AgentWorker(QThread):
    """Worker thread for handling agent requests"""
    response_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    
    def __init__(self, agent_executor, query):
        super().__init__()
        self.agent_executor = agent_executor
        self.query = query
        self._is_running = True
    
    def run(self):
        if not self._is_running:
            return
            
        try:
            response = self.agent_executor.invoke({"input": self.query})
            if self._is_running:
                self.response_signal.emit(response["output"])
        except Exception as e:
            if self._is_running:
                self.error_signal.emit(f"Error processing query: {str(e)}")
    
    def stop(self):
        self._is_running = False
        self.wait()

class ChatInterface(QWidget):
    """Main chat interface widget"""
    
    def __init__(self, agent_executor=None):
        super().__init__()
        self.agent_executor = agent_executor
        self.typewriter_thread = None
        self.agent_worker = None
        self.current_typing_indicator = None
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        header = self.create_header()
        layout.addWidget(header)
        
        self.chat_scroll = QScrollArea()
        self.chat_scroll.setWidgetResizable(True)
        self.chat_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.chat_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        self.chat_container = QWidget()
        self.chat_layout = QVBoxLayout(self.chat_container)
        self.chat_layout.setContentsMargins(10, 10, 10, 10)
        self.chat_layout.setSpacing(8)
        self.chat_layout.addStretch()
        
        self.chat_scroll.setWidget(self.chat_container)
        layout.addWidget(self.chat_scroll)
        
        input_area = self.create_input_area()
        layout.addWidget(input_area)
        
        self.add_welcome_message()
    
    def create_header(self):
        header = QFrame()
        header.setFixedHeight(60)
        header.setStyleSheet("""
            QFrame {
                background-color: #F8F8F8;
                border-bottom: 1px solid #E0E0E0;
            }
        """)
        
        layout = QHBoxLayout(header)
        layout.setContentsMargins(20, 10, 20, 10)
        
        title_label = QLabel("🤖 Memory Forensics AI Assistant")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #333;")
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("""
            color: #28A745; 
            font-size: 12px; 
            padding: 4px 8px; 
            background-color: #D4EDDA; 
            border-radius: 10px;
        """)
        
        layout.addWidget(title_label)
        layout.addStretch()
        layout.addWidget(self.status_label)
        
        return header
    
    def create_input_area(self):
        input_frame = QFrame()
        input_frame.setFixedHeight(80)
        input_frame.setStyleSheet("""
            QFrame {
                background-color: #FFFFFF;
                border-top: 1px solid #E0E0E0;
            }
        """)
        
        layout = QHBoxLayout(input_frame)
        layout.setContentsMargins(15, 15, 15, 15)
        
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Ask about memory forensics, processes, network connections...")
        self.input_field.setStyleSheet("""
            QLineEdit {
                border: 2px solid #E0E0E0;
                border-radius: 20px;
                padding: 10px 15px;
                font-size: 14px;
                background-color: #F9F9F9;
            }
            QLineEdit:focus {
                border-color: #007AFF;
                background-color: white;
            }
        """)
        self.input_field.returnPressed.connect(self.send_message)
        
        self.send_button = QPushButton("Send")
        self.send_button.setFixedSize(80, 40)
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #007AFF;
                color: white;
                border: none;
                border-radius: 20px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #0056CC;
            }
            QPushButton:pressed {
                background-color: #004499;
            }
            QPushButton:disabled {
                background-color: #CCCCCC;
                color: #666666;
            }
        """)
        self.send_button.clicked.connect(self.send_message)
        
        layout.addWidget(self.input_field)
        layout.addWidget(self.send_button)
        
        return input_frame
    
    def add_welcome_message(self):
        welcome_text = """
        <b>Welcome to the Memory Forensics AI Assistant! 🔍</b><br><br>
        I can help you analyze memory dumps and answer questions about:
        <ul>
        <li>🔍 <b>Process Analysis</b> - Find processes, PIDs, and process details</li>
        <li>🌐 <b>Network Connections</b> - Analyze network activity and connections</li>
        <li>📊 <b>Memory Forensics</b> - General questions about memory analysis techniques</li>
        <li>🛠️ <b>Volatility Framework</b> - Usage and plugin information</li>
        </ul>
        <br><b>Sample questions you can ask:</b>
        <ul>
        <li>"Which process has the most network connections?"</li>
        <li>"Show me details for PID 1234"</li>
        <li>"What applications are running multiple processes?"</li>
        <li>"How does memory forensics work?"</li>
        </ul>
        <br>Feel free to ask me anything! 💬
        """
        
        welcome_bubble = ChatBubble(welcome_text, is_user=False)
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, welcome_bubble)
        self.scroll_to_bottom()
    
    def send_message(self):
        message = self.input_field.text().strip()
        if not message:
            return
        
        if not self.agent_executor:
            self.add_ai_message("❌ Agent not initialized. Please ensure memory data is loaded.")
            return
        
        self.input_field.clear()
        
        user_bubble = ChatBubble(message, is_user=True)
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, user_bubble)
        
        self.show_typing_indicator()
        
        self.set_input_enabled(False)
        self.update_status("Processing...", "#FFC107")
        
        self.agent_worker = AgentWorker(self.agent_executor, message)
        self.agent_worker.response_signal.connect(self.handle_agent_response)
        self.agent_worker.error_signal.connect(self.handle_agent_error)
        self.agent_worker.start()
        
        self.scroll_to_bottom()
    
    def show_typing_indicator(self):
        self.current_typing_indicator = TypingIndicator()
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, self.current_typing_indicator)
        self.current_typing_indicator.start_animation()
        self.scroll_to_bottom()
    
    def hide_typing_indicator(self):
        if self.current_typing_indicator:
            self.current_typing_indicator.stop_animation()
            self.chat_layout.removeWidget(self.current_typing_indicator)
            self.current_typing_indicator.deleteLater()
            self.current_typing_indicator = None
    
    def handle_agent_response(self, response):
        self.hide_typing_indicator()
        
        ai_bubble = ChatBubble("", is_user=False)
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, ai_bubble)
        
        self.typewriter_thread = TypewriterEffect(response, delay=30)
        self.typewriter_thread.character_signal.connect(
            lambda char: self.append_to_message(ai_bubble, char)
        )
        self.typewriter_thread.finished_signal.connect(self.on_typewriter_finished)
        self.typewriter_thread.start()
        
        self.scroll_to_bottom()
    
    def handle_agent_error(self, error_message):
        self.hide_typing_indicator()
        self.add_ai_message(f"❌ <b>Error:</b> {error_message}")
        self.set_input_enabled(True)
        self.update_status("Ready", "#28A745")
    
    def append_to_message(self, bubble, character):
        current_text = bubble.message_label.text()
        bubble.message_label.setText(current_text + character)
        self.scroll_to_bottom()
    
    def on_typewriter_finished(self):
        self.set_input_enabled(True)
        self.update_status("Ready", "#28A745")
        if self.typewriter_thread:
            self.typewriter_thread.quit()
            self.typewriter_thread.wait()
            self.typewriter_thread = None
    
    def add_ai_message(self, message):
        ai_bubble = ChatBubble(message, is_user=False)
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, ai_bubble)
        self.scroll_to_bottom()
    
    def set_input_enabled(self, enabled):
        self.input_field.setEnabled(enabled)
        self.send_button.setEnabled(enabled)
        if enabled:
            self.input_field.setFocus()
    
    def update_status(self, text, color):
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"""
            color: {color}; 
            font-size: 12px; 
            padding: 4px 8px; 
            background-color: rgba(255, 255, 255, 0.8); 
            border-radius: 10px;
            border: 1px solid {color};
        """)
    
    def scroll_to_bottom(self):
        QTimer.singleShot(50, lambda: self.chat_scroll.verticalScrollBar().setValue(
            self.chat_scroll.verticalScrollBar().maximum()
        ))
    
    def set_agent_executor(self, agent_executor):
        """Set the agent executor for processing queries"""
        self.agent_executor = agent_executor
        if agent_executor:
            self.update_status("Ready", "#28A745")
            self.add_ai_message("✅ <b>Memory analysis data loaded!</b> You can now ask questions about the memory dump.")
        else:
            self.update_status("No Data", "#DC3545")
    
    def cleanup(self):
        """Clean up threads before closing"""
        if self.typewriter_thread and self.typewriter_thread.isRunning():
            self.typewriter_thread.stop()
            
        if self.agent_worker and self.agent_worker.isRunning():
            self.agent_worker.stop()
            
        if self.current_typing_indicator:
            self.current_typing_indicator.stop_animation()
    
    def closeEvent(self, event):
        """Handle widget close event"""
        self.cleanup()
        super().closeEvent(event)