"""
Data Analytics and Visualization Module for Memory Forensics
Provides comprehensive data analysis, outlier detection, and visualizations
"""

import warnings
from typing import Any, Dict, List, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

warnings.filterwarnings("ignore")

# Set matplotlib backend for PyQt6 compatibility
import matplotlib

try:
    # Try Qt5Agg first (works with PyQt6)
    matplotlib.use("Qt5Agg")
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
except ImportError:
    try:
        # Fallback to Agg backend for testing
        matplotlib.use("Agg")
        from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
    except ImportError:
        # Final fallback
        from matplotlib.figure import Figure

        FigureCanvas = None

from matplotlib.figure import Figure

try:
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QFont
    from PyQt6.QtWidgets import (
        QComboBox,
        QFrame,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QPushButton,
        QScrollArea,
        QSizePolicy,
        QSpinBox,
        QSplitter,
        QVBoxLayout,
        QWidget,
    )

    PYQT6_AVAILABLE = True
except ImportError:
    # Fallback for testing without PyQt6
    PYQT6_AVAILABLE = False
    QWidget = object
    QVBoxLayout = object
    QHBoxLayout = object
    QLabel = object
    QScrollArea = object
    QFrame = object
    QSizePolicy = object
    QComboBox = object
    QPushButton = object
    QSpinBox = object
    QLineEdit = object
    QSplitter = object

    class Qt:
        class AlignmentFlag:
            AlignCenter = 0

        class Orientation:
            Vertical = 0


class OutlierDetector:
    """Advanced outlier detection algorithms for memory forensics data"""

    @staticmethod
    def iqr_outliers(data: List[float], factor: float = 1.5) -> List[Tuple[int, float]]:
        """Detect outliers using Interquartile Range method"""
        if len(data) < 4:
            return []

        q1 = np.percentile(data, 25)
        q3 = np.percentile(data, 75)
        iqr = q3 - q1
        lower_bound = q1 - factor * iqr
        upper_bound = q3 + factor * iqr

        outliers = []
        for i, value in enumerate(data):
            if value < lower_bound or value > upper_bound:
                outliers.append((i, value))

        return outliers

    @staticmethod
    def zscore_outliers(
        data: List[float], threshold: float = 2.5
    ) -> List[Tuple[int, float]]:
        """Detect outliers using Z-score method"""
        if len(data) < 2:
            return []

        mean = np.mean(data)
        std = np.std(data)
        if std == 0:
            return []

        outliers = []
        for i, value in enumerate(data):
            z_score = abs((value - mean) / std)
            if z_score > threshold:
                outliers.append((i, value))

        return outliers

    @staticmethod
    def modified_zscore_outliers(
        data: List[float], threshold: float = 3.5
    ) -> List[Tuple[int, float]]:
        """Detect outliers using Modified Z-score (MAD) method"""
        if len(data) < 2:
            return []

        median = np.median(data)
        mad = np.median([abs(x - median) for x in data])
        if mad == 0:
            return []

        outliers = []
        for i, value in enumerate(data):
            modified_z_score = 0.6745 * (value - median) / mad
            if abs(modified_z_score) > threshold:
                outliers.append((i, value))

        return outliers


class MemoryDataAnalyzer:
    """Main analyzer class for memory forensics data"""

    def __init__(self, metadata: Dict, results: Dict):
        self.metadata = metadata
        self.results = results
        self.df = self._create_dataframe()
        self.outlier_detector = OutlierDetector()

    def _create_dataframe(self) -> pd.DataFrame:
        """Convert metadata to pandas DataFrame for analysis"""
        data = []
        for pid, meta in self.metadata.items():
            row = {
                "PID": pid,
                "Process Name": meta.get("Process Name", "N/A"),
                "PPID": meta.get("PPID", "N/A"),
                "Network Connections": meta.get("No of Network Connections", 0),
                "Create Time": meta.get("Create Time", "N/A"),
            }
            data.append(row)

        return pd.DataFrame(data)

    def get_basic_statistics(self) -> Dict[str, Any]:
        """Calculate basic statistics for the dataset"""
        stats = {
            "total_processes": len(self.df),
            "unique_processes": self.df["Process Name"].nunique(),
            "processes_with_connections": len(
                self.df[self.df["Network Connections"] > 0]
            ),
            "total_network_connections": self.df["Network Connections"].sum(),
            "avg_connections_per_process": self.df["Network Connections"].mean(),
            "max_connections": self.df["Network Connections"].max(),
            "min_connections": self.df["Network Connections"].min(),
            "median_connections": self.df["Network Connections"].median(),
            "std_connections": self.df["Network Connections"].std(),
        }
        return stats

    def detect_network_outliers(self) -> Dict[str, List[Tuple[int, float]]]:
        """Detect outliers in network connections using multiple methods"""
        connection_data = self.df["Network Connections"].tolist()

        outliers = {
            "iqr": self.outlier_detector.iqr_outliers(connection_data),
            "zscore": self.outlier_detector.zscore_outliers(connection_data),
            "modified_zscore": self.outlier_detector.modified_zscore_outliers(
                connection_data
            ),
        }

        return outliers

    def get_outlier_details(
        self, outliers: Dict[str, List[Tuple[int, float]]]
    ) -> Dict[str, List[Dict]]:
        """Get detailed information about outliers"""
        outlier_details = {}

        for method, outlier_list in outliers.items():
            details = []
            for index, value in outlier_list:
                if index < len(self.df):
                    process_info = self.df.iloc[index]
                    details.append(
                        {
                            "PID": process_info["PID"],
                            "Process Name": process_info["Process Name"],
                            "Network Connections": value,
                            "PPID": process_info["PPID"],
                            "Index": index,
                        }
                    )
            outlier_details[method] = details

        return outlier_details

    def get_top_processes_by_connections(self, n: int = 10) -> pd.DataFrame:
        """Get top N processes by network connections"""
        return self.df.nlargest(n, "Network Connections")

    def get_process_distribution(self) -> Dict[str, int]:
        """Get distribution of processes by name"""
        return dict(self.df["Process Name"].value_counts())

    def get_connection_distribution(self) -> Dict[str, int]:
        """Get distribution of processes by connection count"""
        return dict(self.df["Network Connections"].value_counts().sort_index())


class AnalyticsVisualizer:
    """Create visualizations for memory forensics data"""

    def __init__(self, analyzer: MemoryDataAnalyzer):
        self.analyzer = analyzer
        self.setup_style()

    def setup_style(self):
        """Setup matplotlib and seaborn styling"""
        plt.style.use("default")
        sns.set_palette("husl")
        plt.rcParams["figure.facecolor"] = "white"
        plt.rcParams["axes.facecolor"] = "white"
        plt.rcParams["font.size"] = 10

    def create_network_connections_histogram(
        self, ax=None, color_scheme="Default", width=10, height=6
    ) -> Figure:
        """Create histogram of network connections"""
        if ax is None:
            fig, ax = plt.subplots(figsize=(width, height))
        else:
            fig = ax.figure

        connections = self.analyzer.df["Network Connections"]

        # Apply color scheme
        if color_scheme != "Default":
            try:
                cmap = plt.cm.get_cmap(color_scheme.lower())
                color = cmap(0.5)
            except:
                color = "skyblue"
        else:
            color = "skyblue"

        ax.hist(
            connections,
            bins=min(30, len(connections.unique())),
            alpha=0.7,
            color=color,
            edgecolor="black",
        )
        ax.set_xlabel("Network Connections")
        ax.set_ylabel("Number of Processes")
        ax.set_title("Distribution of Network Connections Across Processes", pad=20)
        ax.title.set_horizontalalignment("center")
        ax.grid(True, alpha=0.3)

        # Add statistics text
        stats = self.analyzer.get_basic_statistics()
        stats_text = f'Mean: {stats["avg_connections_per_process"]:.2f}\n'
        stats_text += f'Median: {stats["median_connections"]:.2f}\n'
        stats_text += f'Std: {stats["std_connections"]:.2f}'
        ax.text(
            0.02,
            0.98,
            stats_text,
            transform=ax.transAxes,
            verticalalignment="top",
            bbox=dict(boxstyle="round", facecolor="wheat", alpha=0.8),
        )

        plt.tight_layout()
        return fig

    def create_top_processes_chart(
        self, n: int = 10, ax=None, color_scheme="Default", width=12, height=8
    ) -> Figure:
        """Create bar chart of top processes by connections"""
        if ax is None:
            fig, ax = plt.subplots(figsize=(width, height))
        else:
            fig = ax.figure

        top_processes = self.analyzer.get_top_processes_by_connections(n)

        # Apply color scheme
        if color_scheme != "Default":
            try:
                cmap = plt.cm.get_cmap(color_scheme.lower())
                colors = [
                    cmap(i / len(top_processes)) for i in range(len(top_processes))
                ]
            except:
                colors = "lightcoral"
        else:
            colors = "lightcoral"

        bars = ax.bar(
            range(len(top_processes)),
            top_processes["Network Connections"],
            color=colors,
            alpha=0.8,
            edgecolor="black",
        )

        ax.set_xlabel("Process Rank")
        ax.set_ylabel("Network Connections")
        ax.set_title(f"Top {n} Processes by Network Connections", pad=20)
        ax.title.set_horizontalalignment("center")
        ax.set_xticks(range(len(top_processes)))
        ax.set_xticklabels([f"PID {pid}" for pid in top_processes["PID"]], rotation=45)

        # Add value labels on bars
        for i, bar in enumerate(bars):
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                height + 0.1,
                f"{int(height)}",
                ha="center",
                va="bottom",
            )

        plt.tight_layout()
        return fig

    def create_process_distribution_pie(
        self, top_n: int = 10, ax=None, color_scheme="Default", width=10, height=8
    ) -> Figure:
        """Create pie chart of process distribution"""
        if ax is None:
            fig, ax = plt.subplots(figsize=(width, height))
        else:
            fig = ax.figure

        process_dist = self.analyzer.get_process_distribution()
        top_processes = dict(list(process_dist.items())[:top_n])
        other_count = sum(list(process_dist.values())[top_n:])

        if other_count > 0:
            top_processes["Others"] = other_count

        # Apply color scheme
        if color_scheme != "Default":
            try:
                cmap = plt.cm.get_cmap(color_scheme.lower())
                colors = [
                    cmap(i / len(top_processes)) for i in range(len(top_processes))
                ]
            except:
                colors = None
        else:
            colors = None

        wedges, texts, autotexts = ax.pie(
            top_processes.values(),
            labels=top_processes.keys(),
            autopct="%1.1f%%",
            startangle=90,
            colors=colors,
        )
        ax.set_title(f"Process Distribution (Top {top_n})", pad=20)
        ax.title.set_horizontalalignment("center")

        # Make percentage text bold
        for autotext in autotexts:
            autotext.set_fontweight("bold")

        plt.tight_layout()
        return fig

    def create_outlier_visualization(
        self, outliers: Dict[str, List[Tuple[int, float]]], ax=None
    ) -> Figure:
        """Create visualization showing outliers"""
        if ax is None:
            fig, ax = plt.subplots(figsize=(12, 8))
        else:
            fig = ax.figure

        connections = self.analyzer.df["Network Connections"].tolist()
        indices = list(range(len(connections)))

        # Plot all points
        ax.scatter(
            indices, connections, alpha=0.6, color="lightblue", s=50, label="Normal"
        )

        # Plot outliers for each method
        colors = ["red", "orange", "purple"]

        for i, (method, outlier_list) in enumerate(outliers.items()):
            if outlier_list:
                outlier_indices = [idx for idx, val in outlier_list]
                outlier_values = [val for idx, val in outlier_list]
                ax.scatter(
                    outlier_indices,
                    outlier_values,
                    color=colors[i],
                    s=100,
                    alpha=0.8,
                    label=f"{method.upper()} Outliers ({len(outlier_list)})",
                )

        ax.set_xlabel("Process Index")
        ax.set_ylabel("Network Connections")
        ax.set_title("Network Connection Outliers Detection", pad=20)
        ax.title.set_horizontalalignment("center")
        ax.legend()
        ax.grid(True, alpha=0.3)

        plt.tight_layout()
        return fig

    def create_connection_boxplot(
        self, ax=None, color_scheme="Default", width=8, height=6
    ) -> Figure:
        """Create box plot of network connections"""
        if ax is None:
            fig, ax = plt.subplots(figsize=(width, height))
        else:
            fig = ax.figure

        connections = self.analyzer.df["Network Connections"]
        bp = ax.boxplot(connections, patch_artist=True)

        # Apply color scheme
        if color_scheme != "Default":
            try:
                cmap = plt.cm.get_cmap(color_scheme.lower())
                color = cmap(0.5)
            except:
                color = "lightgreen"
        else:
            color = "lightgreen"

        bp["boxes"][0].set_facecolor(color)
        bp["boxes"][0].set_alpha(0.7)

        ax.set_ylabel("Network Connections")
        ax.set_title("Network Connections Box Plot", pad=20)
        ax.title.set_horizontalalignment("center")
        ax.grid(True, alpha=0.3)

        # Add outlier count
        outliers = OutlierDetector.iqr_outliers(connections.tolist())
        ax.text(
            0.02,
            0.98,
            f"IQR Outliers: {len(outliers)}",
            transform=ax.transAxes,
            verticalalignment="top",
            bbox=dict(boxstyle="round", facecolor="yellow", alpha=0.8),
        )

        plt.tight_layout()
        return fig

    def create_scatter_plot(
        self,
        x_column: str,
        y_column: str,
        color_scheme: str = "Default",
        width: int = 10,
        height: int = 6,
        ax=None,
    ) -> Figure:
        """Create scatter plot for two numeric columns"""
        if ax is None:
            fig, ax = plt.subplots(figsize=(width, height))
        else:
            fig = ax.figure

        x_data = self.analyzer.df[x_column]
        y_data = self.analyzer.df[y_column]

        # Apply color scheme
        if color_scheme != "Default":
            try:
                cmap = plt.cm.get_cmap(color_scheme.lower())
                colors = cmap(np.linspace(0, 1, len(x_data)))
            except:
                colors = "blue"
        else:
            colors = "blue"

        scatter = ax.scatter(x_data, y_data, alpha=0.6, c=colors, s=50)
        ax.set_xlabel(x_column)
        ax.set_ylabel(y_column)
        ax.set_title(f"{x_column} vs {y_column} Scatter Plot", pad=20)
        ax.title.set_horizontalalignment("center")
        ax.grid(True, alpha=0.3)

        plt.tight_layout()
        return fig

    def create_heatmap(
        self,
        x_column: str,
        y_column: str,
        value_column: str,
        color_scheme: str = "Default",
        width: int = 10,
        height: int = 6,
        ax=None,
    ) -> Figure:
        """Create heatmap for categorical data"""
        if ax is None:
            fig, ax = plt.subplots(figsize=(width, height))
        else:
            fig = ax.figure

        # Create pivot table for heatmap
        try:
            pivot_data = self.analyzer.df.pivot_table(
                values=value_column,
                index=y_column,
                columns=x_column,
                aggfunc="count",
                fill_value=0,
            )

            # Apply color scheme
            if color_scheme != "Default":
                cmap = plt.cm.get_cmap(color_scheme.lower())
            else:
                cmap = "viridis"

            im = ax.imshow(pivot_data.values, cmap=cmap, aspect="auto")
            ax.set_xticks(range(len(pivot_data.columns)))
            ax.set_yticks(range(len(pivot_data.index)))
            ax.set_xticklabels(pivot_data.columns, rotation=45)
            ax.set_yticklabels(pivot_data.index)
            ax.set_xlabel(x_column)
            ax.set_ylabel(y_column)
            ax.set_title(
                f"Heatmap: {value_column} by {x_column} and {y_column}", pad=20
            )
            ax.title.set_horizontalalignment("center")

            # Add colorbar
            plt.colorbar(im, ax=ax)

        except Exception as e:
            ax.text(
                0.5,
                0.5,
                f"Cannot create heatmap:\n{str(e)}",
                ha="center",
                va="center",
                transform=ax.transAxes,
            )

        plt.tight_layout()
        return fig

    def create_line_plot(
        self,
        x_column: str,
        y_column: str,
        color_scheme: str = "Default",
        width: int = 10,
        height: int = 6,
        ax=None,
    ) -> Figure:
        """Create line plot for two numeric columns"""
        if ax is None:
            fig, ax = plt.subplots(figsize=(width, height))
        else:
            fig = ax.figure

        x_data = self.analyzer.df[x_column]
        y_data = self.analyzer.df[y_column]

        # Sort by x values for proper line plotting
        sorted_indices = x_data.argsort()
        x_sorted = x_data.iloc[sorted_indices]
        y_sorted = y_data.iloc[sorted_indices]

        ax.plot(x_sorted, y_sorted, marker="o", linewidth=2, markersize=4)
        ax.set_xlabel(x_column)
        ax.set_ylabel(y_column)
        ax.set_title(f"{y_column} vs {x_column} Line Plot", pad=20)
        ax.title.set_horizontalalignment("center")
        ax.grid(True, alpha=0.3)

        plt.tight_layout()
        return fig

    def create_filtered_visualization(
        self,
        viz_type: str,
        primary_column: str,
        secondary_column: str = None,
        filters: dict = None,
        **kwargs,
    ) -> Figure:
        """Create visualization with applied filters"""
        # Apply filters to data
        filtered_df = self.analyzer.df.copy()

        if filters:
            # Process name filter
            if filters.get("process_filter"):
                filtered_df = filtered_df[
                    filtered_df["Process Name"].str.contains(
                        filters["process_filter"], case=False, na=False
                    )
                ]

            # Value range filter
            if (
                filters.get("min_value") is not None
                and filters.get("max_value") is not None
            ):
                if primary_column in filtered_df.columns:
                    filtered_df = filtered_df[
                        (filtered_df[primary_column] >= filters["min_value"])
                        & (filtered_df[primary_column] <= filters["max_value"])
                    ]

            # Top N filter
            if filters.get("top_n") and viz_type in ["Bar Chart", "Pie Chart"]:
                if primary_column in filtered_df.columns:
                    filtered_df = filtered_df.nlargest(filters["top_n"], primary_column)

        # Create temporary analyzer with filtered data
        temp_analyzer = MemoryDataAnalyzer({}, {})
        temp_analyzer.df = filtered_df

        # Create temporary visualizer
        temp_visualizer = AnalyticsVisualizer(temp_analyzer)

        # Generate visualization based on type
        if viz_type == "Histogram":
            return temp_visualizer.create_network_connections_histogram(
                ax=kwargs.get("ax"),
                color_scheme=kwargs.get("color_scheme", "Default"),
                width=kwargs.get("width", 10),
                height=kwargs.get("height", 6),
            )
        elif viz_type == "Bar Chart":
            return temp_visualizer.create_top_processes_chart(
                filters.get("top_n", 10),
                ax=kwargs.get("ax"),
                color_scheme=kwargs.get("color_scheme", "Default"),
                width=kwargs.get("width", 12),
                height=kwargs.get("height", 8),
            )
        elif viz_type == "Pie Chart":
            return temp_visualizer.create_process_distribution_pie(
                filters.get("top_n", 10),
                ax=kwargs.get("ax"),
                color_scheme=kwargs.get("color_scheme", "Default"),
                width=kwargs.get("width", 10),
                height=kwargs.get("height", 8),
            )
        elif viz_type == "Box Plot":
            return temp_visualizer.create_connection_boxplot(
                ax=kwargs.get("ax"),
                color_scheme=kwargs.get("color_scheme", "Default"),
                width=kwargs.get("width", 8),
                height=kwargs.get("height", 6),
            )
        elif viz_type == "Scatter Plot" and secondary_column:
            return temp_visualizer.create_scatter_plot(
                primary_column,
                secondary_column,
                color_scheme=kwargs.get("color_scheme", "Default"),
                width=kwargs.get("width", 10),
                height=kwargs.get("height", 6),
                ax=kwargs.get("ax"),
            )
        elif viz_type == "Heatmap" and secondary_column:
            return temp_visualizer.create_heatmap(
                primary_column,
                secondary_column,
                "Network Connections",
                color_scheme=kwargs.get("color_scheme", "Default"),
                width=kwargs.get("width", 10),
                height=kwargs.get("height", 6),
                ax=kwargs.get("ax"),
            )
        elif viz_type == "Line Plot" and secondary_column:
            return temp_visualizer.create_line_plot(
                primary_column,
                secondary_column,
                color_scheme=kwargs.get("color_scheme", "Default"),
                width=kwargs.get("width", 10),
                height=kwargs.get("height", 6),
                ax=kwargs.get("ax"),
            )
        else:
            # Default to histogram if visualization type not supported
            return temp_visualizer.create_network_connections_histogram(
                ax=kwargs.get("ax"),
                color_scheme=kwargs.get("color_scheme", "Default"),
                width=kwargs.get("width", 10),
                height=kwargs.get("height", 6),
            )


if FigureCanvas is not None:

    class AnalyticsCanvas(FigureCanvas):
        """Custom FigureCanvas for embedding matplotlib plots in PyQt6"""

        def __init__(self, parent=None, width=5, height=4, dpi=100):
            self.fig = Figure(figsize=(width, height), dpi=dpi)
            super().__init__(self.fig)
            self.setParent(parent)

            self.setSizePolicy(
                QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
            )
            self.updateGeometry()

else:
    # Fallback for testing without PyQt6
    class AnalyticsCanvas:
        """Fallback canvas for testing without PyQt6"""

        def __init__(self, parent=None, width=5, height=4, dpi=100):
            self.fig = Figure(figsize=(width, height), dpi=dpi)
            self.parent = parent

        def draw(self):
            pass  # No-op for testing


class AnalyticsSelectionWidget(QWidget):
    """Widget for selecting analytics options and parameters"""

    def __init__(self, analyzer: MemoryDataAnalyzer, parent=None):
        if PYQT6_AVAILABLE:
            super().__init__(parent)
        self.analyzer = analyzer

        if PYQT6_AVAILABLE:
            self.setup_ui()
            self.populate_columns()

    def setup_ui(self):
        """Setup the selection interface"""
        layout = QVBoxLayout()
        layout.setContentsMargins(4, 4, 4, 4)  # Minimal margins
        layout.setSpacing(4)  # Minimal spacing

        # Compact title
        title = QLabel("📊 Analytics Config")
        title.setFont(QFont("Arial", 10, QFont.Weight.Bold))  # Reduced font size
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            """
            QLabel {
                color: #2c3e50;
                padding: 2px;
                background-color: #e9ecef;
                border-radius: 3px;
                margin-bottom: 2px;
            }
        """
        )
        title.setMaximumHeight(20)  # Compact title
        layout.addWidget(title)

        # Compact visualization type selection
        viz_layout = QVBoxLayout()  # Changed to vertical for space
        viz_layout.setSpacing(2)
        viz_label = QLabel("Visualization:")
        viz_label.setFont(QFont("Arial", 9, QFont.Weight.Bold))
        viz_label.setStyleSheet("color: #495057;")
        self.viz_combo = QComboBox()
        self.viz_combo.addItems(
            [
                "Histogram",
                "Bar Chart",
                "Pie Chart",
                "Scatter Plot",
                "Box Plot",
                "Heatmap",
                "Line Plot",
            ]
        )
        self.viz_combo.setStyleSheet(
            """
            QComboBox {
                padding: 3px 6px;
                border: 1px solid #ced4da;
                border-radius: 3px;
                background-color: white;
                font-size: 9px;
            }
            QComboBox:focus {
                border-color: #007AFF;
            }
            QComboBox::drop-down {
                border: none;
                width: 16px;
            }
        """
        )
        self.viz_combo.currentTextChanged.connect(self.on_viz_type_changed)
        viz_layout.addWidget(viz_label)
        viz_layout.addWidget(self.viz_combo)
        layout.addLayout(viz_layout)

        # Compact column selection
        col_layout = QVBoxLayout()  # Changed to vertical for space
        col_layout.setSpacing(2)
        col_label = QLabel("Primary Column:")
        col_label.setFont(QFont("Arial", 9, QFont.Weight.Bold))
        col_label.setStyleSheet("color: #495057;")
        self.primary_col_combo = QComboBox()
        self.primary_col_combo.setStyleSheet(
            """
            QComboBox {
                padding: 3px 6px;
                border: 1px solid #ced4da;
                border-radius: 3px;
                background-color: white;
                font-size: 9px;
            }
            QComboBox:focus {
                border-color: #007AFF;
            }
        """
        )
        self.primary_col_combo.currentTextChanged.connect(self.on_primary_col_changed)
        col_layout.addWidget(col_label)
        col_layout.addWidget(self.primary_col_combo)
        layout.addLayout(col_layout)

        # Secondary column (for scatter plots, heatmaps)
        self.secondary_col_layout = QHBoxLayout()
        self.secondary_col_layout.setSpacing(8)
        self.secondary_col_label = QLabel("Secondary Column:")
        self.secondary_col_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        self.secondary_col_label.setStyleSheet("color: #495057; min-width: 140px;")
        self.secondary_col_combo = QComboBox()
        self.secondary_col_combo.setStyleSheet(
            """
            QComboBox {
                padding: 6px 8px;
                border: 2px solid #ced4da;
                border-radius: 4px;
                background-color: white;
                min-width: 120px;
            }
            QComboBox:focus {
                border-color: #007AFF;
            }
        """
        )
        self.secondary_col_combo.setVisible(False)
        self.secondary_col_label.setVisible(False)
        self.secondary_col_layout.addWidget(self.secondary_col_label)
        self.secondary_col_layout.addWidget(self.secondary_col_combo)
        layout.addLayout(self.secondary_col_layout)

        # Filter options
        filter_group = QFrame()
        filter_group.setFrameStyle(QFrame.Shape.StyledPanel)
        filter_group.setStyleSheet(
            """
            QFrame {
                background-color: #ffffff;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                margin: 2px 0px;
            }
        """
        )
        filter_layout = QVBoxLayout(filter_group)
        filter_layout.setContentsMargins(8, 8, 8, 8)  # Reduced margins
        filter_layout.setSpacing(6)  # Reduced spacing

        filter_title = QLabel("Data Filters")
        filter_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))  # Reduced font size
        filter_title.setStyleSheet(
            """
            QLabel {
                color: #2c3e50;
                padding: 2px 0px;
                border-bottom: 1px solid #e9ecef;
                margin-bottom: 4px;
            }
        """
        )
        filter_layout.addWidget(filter_title)

        # Top N processes filter
        top_n_layout = QHBoxLayout()
        top_n_layout.setSpacing(8)
        self.top_n_label = QLabel("Top N Processes:")
        self.top_n_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        self.top_n_label.setStyleSheet("color: #495057; min-width: 120px;")
        self.top_n_spinbox = QSpinBox()
        self.top_n_spinbox.setRange(1, 100)
        self.top_n_spinbox.setValue(10)
        self.top_n_spinbox.setStyleSheet(
            """
            QSpinBox {
                padding: 4px 6px;
                border: 2px solid #ced4da;
                border-radius: 4px;
                background-color: white;
                min-width: 60px;
            }
            QSpinBox:focus {
                border-color: #007AFF;
            }
        """
        )
        self.top_n_spinbox.setVisible(False)
        self.top_n_label.setVisible(False)
        top_n_layout.addWidget(self.top_n_label)
        top_n_layout.addWidget(self.top_n_spinbox)
        filter_layout.addLayout(top_n_layout)

        # Range filter
        range_layout = QHBoxLayout()
        range_layout.setSpacing(8)
        self.range_label = QLabel("Value Range:")
        self.range_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        self.range_label.setStyleSheet("color: #495057; min-width: 120px;")
        self.min_value_spinbox = QSpinBox()
        self.min_value_spinbox.setRange(0, 10000)
        self.min_value_spinbox.setValue(0)
        self.min_value_spinbox.setStyleSheet(
            """
            QSpinBox {
                padding: 4px 6px;
                border: 2px solid #ced4da;
                border-radius: 4px;
                background-color: white;
                min-width: 60px;
            }
            QSpinBox:focus {
                border-color: #007AFF;
            }
        """
        )
        self.max_value_spinbox = QSpinBox()
        self.max_value_spinbox.setRange(0, 10000)
        self.max_value_spinbox.setValue(1000)
        self.max_value_spinbox.setStyleSheet(
            """
            QSpinBox {
                padding: 4px 6px;
                border: 2px solid #ced4da;
                border-radius: 4px;
                background-color: white;
                min-width: 60px;
            }
            QSpinBox:focus {
                border-color: #007AFF;
            }
        """
        )
        self.min_value_spinbox.setVisible(False)
        self.max_value_spinbox.setVisible(False)
        self.range_label.setVisible(False)
        self.to_label = QLabel("to")
        self.to_label.setStyleSheet("color: #6c757d; font-weight: bold; padding: 4px;")
        self.to_label.setVisible(False)
        range_layout.addWidget(self.range_label)
        range_layout.addWidget(self.min_value_spinbox)
        range_layout.addWidget(self.to_label)
        range_layout.addWidget(self.max_value_spinbox)
        filter_layout.addLayout(range_layout)

        # Process name filter
        process_layout = QHBoxLayout()
        process_layout.setSpacing(8)
        process_label = QLabel("Process Name Filter:")
        process_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        process_label.setStyleSheet("color: #495057; min-width: 120px;")
        self.process_filter_input = QLineEdit()
        self.process_filter_input.setPlaceholderText("Filter by process name...")
        self.process_filter_input.setStyleSheet(
            """
            QLineEdit {
                padding: 6px 8px;
                border: 2px solid #ced4da;
                border-radius: 4px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #007AFF;
            }
        """
        )
        process_layout.addWidget(process_label)
        process_layout.addWidget(self.process_filter_input)
        filter_layout.addLayout(process_layout)

        layout.addWidget(filter_group)

        # Visualization parameters
        params_group = QFrame()
        params_group.setFrameStyle(QFrame.Shape.StyledPanel)
        params_group.setStyleSheet(
            """
            QFrame {
                background-color: #ffffff;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                margin: 2px 0px;
            }
        """
        )
        params_layout = QVBoxLayout(params_group)
        params_layout.setContentsMargins(8, 8, 8, 8)  # Reduced margins
        params_layout.setSpacing(6)  # Reduced spacing

        params_title = QLabel("Visualization Parameters")
        params_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))  # Reduced font size
        params_title.setStyleSheet(
            """
            QLabel {
                color: #2c3e50;
                padding: 2px 0px;
                border-bottom: 1px solid #e9ecef;
                margin-bottom: 4px;
            }
        """
        )
        params_layout.addWidget(params_title)

        # Chart size
        size_layout = QHBoxLayout()
        size_layout.setSpacing(8)
        size_label = QLabel("Chart Size:")
        size_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        size_label.setStyleSheet("color: #495057; min-width: 120px;")
        self.width_spinbox = QSpinBox()
        self.width_spinbox.setRange(5, 20)
        self.width_spinbox.setValue(10)
        self.width_spinbox.setStyleSheet(
            """
            QSpinBox {
                padding: 4px 6px;
                border: 2px solid #ced4da;
                border-radius: 4px;
                background-color: white;
                min-width: 50px;
            }
            QSpinBox:focus {
                border-color: #007AFF;
            }
        """
        )
        self.height_spinbox = QSpinBox()
        self.height_spinbox.setRange(5, 20)
        self.height_spinbox.setValue(6)
        self.height_spinbox.setStyleSheet(
            """
            QSpinBox {
                padding: 4px 6px;
                border: 2px solid #ced4da;
                border-radius: 4px;
                background-color: white;
                min-width: 50px;
            }
            QSpinBox:focus {
                border-color: #007AFF;
            }
        """
        )
        size_x_label = QLabel("×")
        size_x_label.setStyleSheet("color: #6c757d; font-weight: bold; padding: 4px;")
        size_layout.addWidget(size_label)
        size_layout.addWidget(self.width_spinbox)
        size_layout.addWidget(size_x_label)
        size_layout.addWidget(self.height_spinbox)
        params_layout.addLayout(size_layout)

        # Color scheme
        color_layout = QHBoxLayout()
        color_layout.setSpacing(8)
        color_label = QLabel("Color Scheme:")
        color_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        color_label.setStyleSheet("color: #495057; min-width: 120px;")
        self.color_combo = QComboBox()
        self.color_combo.addItems(
            [
                "Default",
                "Viridis",
                "Plasma",
                "Inferno",
                "Magma",
                "Blues",
                "Reds",
                "Greens",
            ]
        )
        self.color_combo.setStyleSheet(
            """
            QComboBox {
                padding: 6px 8px;
                border: 2px solid #ced4da;
                border-radius: 4px;
                background-color: white;
                min-width: 120px;
            }
            QComboBox:focus {
                border-color: #007AFF;
            }
        """
        )
        color_layout.addWidget(color_label)
        color_layout.addWidget(self.color_combo)
        params_layout.addLayout(color_layout)

        layout.addWidget(params_group)

        # Action buttons - centered
        # Compact button layout
        button_layout = QVBoxLayout()  # Changed to vertical for space saving
        button_layout.setSpacing(2)  # Minimal spacing
        button_layout.setContentsMargins(0, 2, 0, 0)  # Minimal margin

        self.preview_btn = QPushButton("Preview")
        self.preview_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #007AFF;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 4px 6px;
                font-weight: bold;
                font-size: 9px;
                min-width: 50px;
            }
            QPushButton:hover {
                background-color: #0056CC;
            }
            QPushButton:pressed {
                background-color: #004499;
            }
        """
        )
        self.preview_btn.clicked.connect(self.generate_preview)

        self.generate_btn = QPushButton("Generate")
        self.generate_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #28A745;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 4px 6px;
                font-weight: bold;
                font-size: 9px;
                min-width: 50px;
            }
            QPushButton:hover {
                background-color: #1E7E34;
            }
            QPushButton:pressed {
                background-color: #155724;
            }
        """
        )
        self.generate_btn.clicked.connect(self.generate_full_chart)

        self.export_btn = QPushButton("Export")
        self.export_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #6C757D;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 4px 6px;
                font-weight: bold;
                font-size: 9px;
                min-width: 50px;
            }
            QPushButton:hover {
                background-color: #5A6268;
            }
            QPushButton:pressed {
                background-color: #495057;
            }
        """
        )
        self.export_btn.clicked.connect(self.export_chart)

        button_layout.addWidget(self.preview_btn)
        button_layout.addWidget(self.generate_btn)
        button_layout.addWidget(self.export_btn)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def populate_columns(self):
        """Populate column dropdowns with available data columns"""
        columns = list(self.analyzer.df.columns)
        self.primary_col_combo.clear()
        self.secondary_col_combo.clear()

        for col in columns:
            self.primary_col_combo.addItem(col)
            self.secondary_col_combo.addItem(col)

        # Set default selections
        if "Network Connections" in columns:
            self.primary_col_combo.setCurrentText("Network Connections")
        if "Process Name" in columns:
            self.secondary_col_combo.setCurrentText("Process Name")

    def on_viz_type_changed(self, viz_type):
        """Handle visualization type changes"""
        # Show/hide secondary column for scatter plots and heatmaps
        show_secondary = viz_type in ["Scatter Plot", "Heatmap"]
        self.secondary_col_combo.setVisible(show_secondary)
        self.secondary_col_label.setVisible(show_secondary)

        # Show/hide top N filter for bar charts and pie charts
        show_top_n = viz_type in ["Bar Chart", "Pie Chart"]
        self.top_n_spinbox.setVisible(show_top_n)
        self.top_n_label.setVisible(show_top_n)

    def on_primary_col_changed(self, column):
        """Handle primary column changes"""
        # Update range filter limits based on column data
        if column and column in self.analyzer.df.columns:
            data = self.analyzer.df[column]
            if pd.api.types.is_numeric_dtype(data):
                min_val = int(data.min())
                max_val = int(data.max())
                self.min_value_spinbox.setRange(min_val, max_val)
                self.max_value_spinbox.setRange(min_val, max_val)
                self.min_value_spinbox.setValue(min_val)
                self.max_value_spinbox.setValue(max_val)

                # Show range filter for numeric columns
                self.min_value_spinbox.setVisible(True)
                self.max_value_spinbox.setVisible(True)
                self.range_label.setVisible(True)
                self.to_label.setVisible(True)
            else:
                # Hide range filter for non-numeric columns
                self.min_value_spinbox.setVisible(False)
                self.max_value_spinbox.setVisible(False)
                self.range_label.setVisible(False)
                self.to_label.setVisible(False)

    def generate_preview(self):
        """Generate a preview of the selected visualization"""
        # This will be connected to the main analytics widget

    def generate_full_chart(self):
        """Generate the full chart with selected options"""
        # This will be connected to the main analytics widget

    def export_chart(self):
        """Export the current chart"""
        # This will be connected to the main analytics widget

    def get_selection_params(self):
        """Get current selection parameters"""
        return {
            "viz_type": self.viz_combo.currentText(),
            "primary_column": self.primary_col_combo.currentText(),
            "secondary_column": (
                self.secondary_col_combo.currentText()
                if self.secondary_col_combo.isVisible()
                else None
            ),
            "top_n": (
                self.top_n_spinbox.value() if self.top_n_spinbox.isVisible() else None
            ),
            "min_value": (
                self.min_value_spinbox.value()
                if self.min_value_spinbox.isVisible()
                else None
            ),
            "max_value": (
                self.max_value_spinbox.value()
                if self.max_value_spinbox.isVisible()
                else None
            ),
            "process_filter": self.process_filter_input.text().strip() or None,
            "width": self.width_spinbox.value(),
            "height": self.height_spinbox.value(),
            "color_scheme": self.color_combo.currentText(),
        }


class AnalyticsWidget(QWidget):
    """Main analytics widget containing all visualizations and analysis"""

    def __init__(self, metadata: Dict, results: Dict, parent=None):
        if PYQT6_AVAILABLE:
            super().__init__(parent)
        self.metadata = metadata
        self.results = results

        self.analyzer = MemoryDataAnalyzer(metadata, results)
        self.visualizer = AnalyticsVisualizer(self.analyzer)

        if PYQT6_AVAILABLE:
            self.setup_ui()
            self.setup_selection_widget()

    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout()
        layout.setContentsMargins(2, 2, 2, 2)  # Minimal margins
        layout.setSpacing(2)  # Minimal spacing

        # Compact header with title
        title = QLabel("📊 Memory Analytics & Visualization")
        title.setFont(QFont("Arial", 12, QFont.Weight.Bold))  # Reduced font size
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            """
            QLabel {
                color: #2c3e50;
                padding: 2px;
                margin-bottom: 4px;
            }
        """
        )
        title.setMaximumHeight(24)  # Compact title
        layout.addWidget(title)

        # Create splitter for selection panel and visualization area
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setStyleSheet(
            """
            QSplitter::handle {
                background-color: #bdc3c7;
                width: 2px;
            }
            QSplitter::handle:hover {
                background-color: #95a5a6;
            }
        """
        )

        # Selection panel (left side) - more compact styling
        self.selection_widget = AnalyticsSelectionWidget(self.analyzer, self)
        self.selection_widget.setStyleSheet(
            """
            QWidget {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 2px;
            }
        """
        )
        self.selection_widget.preview_btn.clicked.connect(self.generate_preview)
        self.selection_widget.generate_btn.clicked.connect(self.generate_full_chart)
        self.selection_widget.export_btn.clicked.connect(self.export_chart)

        # Visualization area (right side) - more compact styling
        self.viz_scroll_area = QScrollArea()
        self.viz_scroll_area.setWidgetResizable(True)
        self.viz_scroll_area.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.viz_scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.viz_scroll_area.setStyleSheet(
            """
            QScrollArea {
                background-color: #ffffff;
                border: 1px solid #dee2e6;
                border-radius: 4px;
            }
        """
        )

        self.viz_content_widget = QWidget()
        self.viz_content_layout = QVBoxLayout(self.viz_content_widget)
        self.viz_content_layout.setContentsMargins(1, 1, 1, 1)  # Minimal margins
        self.viz_content_layout.setSpacing(1)  # Minimal spacing

        # Compact statistics section
        self.stats_widget = self.create_stats_section()
        self.viz_content_layout.addWidget(self.stats_widget)

        # Canvas area for generated visualizations
        self.canvas_container = QFrame()
        self.canvas_container.setFrameStyle(QFrame.Shape.StyledPanel)
        self.canvas_container.setStyleSheet(
            """
            QFrame {
                background-color: #ffffff;
                border: 1px solid #e9ecef;
                border-radius: 3px;
                margin: 1px;
            }
        """
        )
        self.canvas_layout = QVBoxLayout(self.canvas_container)
        self.canvas_layout.setContentsMargins(2, 2, 2, 2)  # Minimal margins
        self.canvas_layout.setSpacing(1)  # Minimal spacing

        self.canvas_label = QLabel(
            "Select visualization options and click 'Preview' or 'Generate Full Chart'"
        )
        self.canvas_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.canvas_label.setStyleSheet(
            """
            QLabel {
                color: #6c757d;
                font-style: italic;
                font-size: 9px;
                padding: 6px;
                background-color: #f8f9fa;
                border: 1px dashed #dee2e6;
                border-radius: 2px;
            }
        """
        )
        self.canvas_label.setMaximumHeight(30)  # Compact placeholder
        self.canvas_layout.addWidget(self.canvas_label)

        self.viz_content_layout.addWidget(self.canvas_container)
        self.viz_scroll_area.setWidget(self.viz_content_widget)

        # Add to splitter with optimized proportions
        self.splitter.addWidget(self.selection_widget)
        self.splitter.addWidget(self.viz_scroll_area)
        self.splitter.setSizes(
            [200, 1300]
        )  # More space for visualization: 200px config, 1300px viz

        layout.addWidget(self.splitter)
        self.setLayout(layout)

    def setup_selection_widget(self):
        """Setup the selection widget connections"""
        # This is called after UI setup to ensure proper initialization

    def create_stats_section(self):
        """Create statistics section"""
        widget = QFrame()
        widget.setFrameStyle(QFrame.Shape.StyledPanel)
        widget.setStyleSheet(
            """
            QFrame {
                background-color: #ffffff;
                border: 1px solid #dee2e6;
                border-radius: 3px;
                margin: 2px;
            }
        """
        )
        layout = QVBoxLayout()
        layout.setContentsMargins(4, 4, 4, 4)  # Minimal margins
        layout.setSpacing(2)  # Minimal spacing

        title = QLabel("Dataset Statistics")
        title.setFont(QFont("Arial", 10, QFont.Weight.Bold))  # Reduced font size
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            """
            QLabel {
                color: #2c3e50;
                padding: 1px 0px;
                border-bottom: 1px solid #e9ecef;
                margin-bottom: 2px;
            }
        """
        )
        title.setMaximumHeight(20)  # Compact title
        layout.addWidget(title)

        self.stats_label = QLabel()
        self.stats_label.setWordWrap(True)
        self.stats_label.setStyleSheet(
            """
            QLabel {
                color: #495057;
                font-size: 9px;
                line-height: 1.2;
                padding: 4px;
                background-color: #f8f9fa;
                border-radius: 2px;
            }
        """
        )
        self.stats_label.setMaximumHeight(60)  # Very compact stats
        layout.addWidget(self.stats_label)

        widget.setLayout(layout)
        return widget

    def create_visualizations_section(self):
        """Create visualizations section"""
        widget = QFrame()
        widget.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout()

        title = QLabel("Data Visualizations")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        # Create canvas widgets for plots
        self.hist_canvas = AnalyticsCanvas(self, width=10, height=6)
        self.bar_canvas = AnalyticsCanvas(self, width=12, height=8)
        self.pie_canvas = AnalyticsCanvas(self, width=10, height=8)
        self.outlier_canvas = AnalyticsCanvas(self, width=12, height=8)
        self.box_canvas = AnalyticsCanvas(self, width=8, height=6)

        layout.addWidget(self.hist_canvas)
        layout.addWidget(self.bar_canvas)
        layout.addWidget(self.pie_canvas)
        layout.addWidget(self.outlier_canvas)
        layout.addWidget(self.box_canvas)

        widget.setLayout(layout)
        return widget

    def create_outliers_section(self):
        """Create outliers section"""
        widget = QFrame()
        widget.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout()

        title = QLabel("Outlier Analysis")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        self.outliers_label = QLabel()
        self.outliers_label.setWordWrap(True)
        layout.addWidget(self.outliers_label)

        widget.setLayout(layout)
        return widget

    def generate_analytics(self):
        """Generate all analytics and visualizations"""
        # Generate statistics
        stats = self.analyzer.get_basic_statistics()
        stats_text = f"""
        <b>Dataset Overview:</b><br>
        • Total Processes: {stats['total_processes']}<br>
        • Unique Process Names: {stats['unique_processes']}<br>
        • Processes with Network Connections: {stats['processes_with_connections']}<br>
        • Total Network Connections: {stats['total_network_connections']}<br><br>
        
        <b>Network Connection Statistics:</b><br>
        • Average: {stats['avg_connections_per_process']:.2f}<br>
        • Median: {stats['median_connections']:.2f}<br>
        • Standard Deviation: {stats['std_connections']:.2f}<br>
        • Maximum: {stats['max_connections']}<br>
        • Minimum: {stats['min_connections']}<br>
        """
        self.stats_label.setText(stats_text)

        # Generate visualizations
        self.visualizer.create_network_connections_histogram(
            self.hist_canvas.fig.add_subplot(111)
        )
        self.hist_canvas.draw()

        self.visualizer.create_top_processes_chart(
            10, self.bar_canvas.fig.add_subplot(111)
        )
        self.bar_canvas.draw()

        self.visualizer.create_process_distribution_pie(
            10, self.pie_canvas.fig.add_subplot(111)
        )
        self.pie_canvas.draw()

        # Generate outlier analysis
        outliers = self.analyzer.detect_network_outliers()
        outlier_details = self.analyzer.get_outlier_details(outliers)

        self.visualizer.create_outlier_visualization(
            outliers, self.outlier_canvas.fig.add_subplot(111)
        )
        self.outlier_canvas.draw()

        self.visualizer.create_connection_boxplot(self.box_canvas.fig.add_subplot(111))
        self.box_canvas.draw()

        # Generate outlier details text
        outlier_text = "<b>Outlier Detection Results:</b><br><br>"

        for method, details in outlier_details.items():
            outlier_text += (
                f"<b>{method.upper()} Method:</b> {len(details)} outliers found<br>"
            )
            if details:
                outlier_text += "<ul>"
                for detail in details[:10]:  # Show top 10 outliers
                    outlier_text += f"<li>PID {detail['PID']}: {detail['Process Name']} ({detail['Network Connections']} connections)</li>"
                if len(details) > 10:
                    outlier_text += (
                        f"<li>... and {len(details) - 10} more outliers</li>"
                    )
                outlier_text += "</ul>"
            outlier_text += "<br>"

        self.outliers_label.setText(outlier_text)

    def generate_preview(self):
        """Generate a preview of the selected visualization"""
        try:
            params = self.selection_widget.get_selection_params()

            # Clear existing canvas content
            self.clear_canvas_container()

            # Create preview canvas
            preview_canvas = AnalyticsCanvas(
                self.canvas_container, width=params["width"], height=params["height"]
            )

            # Generate visualization
            fig = self.visualizer.create_filtered_visualization(
                viz_type=params["viz_type"],
                primary_column=params["primary_column"],
                secondary_column=params["secondary_column"],
                filters={
                    "process_filter": params["process_filter"],
                    "min_value": params["min_value"],
                    "max_value": params["max_value"],
                    "top_n": params["top_n"],
                },
                color_scheme=params["color_scheme"],
                width=params["width"],
                height=params["height"],
                ax=preview_canvas.fig.add_subplot(111),
            )

            preview_canvas.draw()
            self.canvas_layout.addWidget(preview_canvas)

            # Remove preview label to give more space to visualization

        except Exception as e:
            error_label = QLabel(f"Error generating preview: {str(e)}")
            error_label.setStyleSheet(
                """
                QLabel {
                    color: #DC3545;
                    font-weight: bold;
                    font-size: 12px;
                    padding: 10px;
                    background-color: #f8d7da;
                    border: 1px solid #f5c6cb;
                    border-radius: 4px;
                    margin: 4px;
                }
            """
            )
            error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.clear_canvas_container()
            self.canvas_layout.addWidget(error_label)

    def generate_full_chart(self):
        """Generate the full chart with selected options"""
        try:
            params = self.selection_widget.get_selection_params()

            # Clear existing canvas content
            self.clear_canvas_container()

            # Create full canvas
            full_canvas = AnalyticsCanvas(
                self.canvas_container,
                width=params["width"] * 1.5,
                height=params["height"] * 1.5,
            )

            # Generate visualization
            fig = self.visualizer.create_filtered_visualization(
                viz_type=params["viz_type"],
                primary_column=params["primary_column"],
                secondary_column=params["secondary_column"],
                filters={
                    "process_filter": params["process_filter"],
                    "min_value": params["min_value"],
                    "max_value": params["max_value"],
                    "top_n": params["top_n"],
                },
                color_scheme=params["color_scheme"],
                width=params["width"] * 1.5,
                height=params["height"] * 1.5,
                ax=full_canvas.fig.add_subplot(111),
            )

            full_canvas.draw()
            self.canvas_layout.addWidget(full_canvas)

            # Remove the extra info label to save space and improve view

        except Exception as e:
            error_label = QLabel(f"Error generating chart: {str(e)}")
            error_label.setStyleSheet(
                """
                QLabel {
                    color: #DC3545;
                    font-weight: bold;
                    font-size: 12px;
                    padding: 10px;
                    background-color: #f8d7da;
                    border: 1px solid #f5c6cb;
                    border-radius: 4px;
                    margin: 4px;
                }
            """
            )
            error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.clear_canvas_container()
            self.canvas_layout.addWidget(error_label)

    def export_chart(self):
        """Export the current chart"""
        try:
            import os

            from PyQt6.QtWidgets import QFileDialog

            params = self.selection_widget.get_selection_params()

            # Get export path
            default_filename = (
                f"{params['viz_type'].replace(' ', '_')}_{params['primary_column']}.png"
            )
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Chart",
                default_filename,
                "PNG Files (*.png);;PDF Files (*.pdf);;SVG Files (*.svg)",
            )

            if file_path:
                # Generate the chart for export
                fig = self.visualizer.create_filtered_visualization(
                    viz_type=params["viz_type"],
                    primary_column=params["primary_column"],
                    secondary_column=params["secondary_column"],
                    filters={
                        "process_filter": params["process_filter"],
                        "min_value": params["min_value"],
                        "max_value": params["max_value"],
                        "top_n": params["top_n"],
                    },
                    color_scheme=params["color_scheme"],
                    width=params["width"],
                    height=params["height"],
                )

                # Save the figure
                fig.savefig(file_path, dpi=300, bbox_inches="tight")

                # Show success message
                success_label = QLabel(
                    f"Chart exported successfully to: {os.path.basename(file_path)}"
                )
                success_label.setStyleSheet(
                    """
                    QLabel {
                        color: #28A745;
                        font-weight: bold;
                        font-size: 12px;
                        padding: 10px;
                        background-color: #e8f5e8;
                        border: 1px solid #c8e6c9;
                        border-radius: 4px;
                        margin: 4px;
                    }
                """
                )
                success_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

                # Add to canvas if not already there
                if not any(
                    isinstance(w, QLabel) and "exported successfully" in w.text()
                    for w in self.canvas_container.findChildren(QLabel)
                ):
                    self.canvas_layout.addWidget(success_label)

        except Exception as e:
            error_label = QLabel(f"Error exporting chart: {str(e)}")
            error_label.setStyleSheet(
                """
                QLabel {
                    color: #DC3545;
                    font-weight: bold;
                    font-size: 12px;
                    padding: 10px;
                    background-color: #f8d7da;
                    border: 1px solid #f5c6cb;
                    border-radius: 4px;
                    margin: 4px;
                }
            """
            )
            error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.clear_canvas_container()
            self.canvas_layout.addWidget(error_label)

    def clear_canvas_container(self):
        """Clear all widgets from the canvas container"""
        while self.canvas_layout.count():
            child = self.canvas_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def generate_analytics(self):
        """Generate all analytics and visualizations (legacy method for compatibility)"""
        # Generate statistics
        stats = self.analyzer.get_basic_statistics()
        stats_text = f"""
        <b>Dataset Overview:</b><br>
        • Total Processes: {stats['total_processes']}<br>
        • Unique Process Names: {stats['unique_processes']}<br>
        • Processes with Network Connections: {stats['processes_with_connections']}<br>
        • Total Network Connections: {stats['total_network_connections']}<br><br>
        
        <b>Network Connection Statistics:</b><br>
        • Average: {stats['avg_connections_per_process']:.2f}<br>
        • Median: {stats['median_connections']:.2f}<br>
        • Standard Deviation: {stats['std_connections']:.2f}<br>
        • Maximum: {stats['max_connections']}<br>
        • Minimum: {stats['min_connections']}<br>
        """
        self.stats_label.setText(stats_text)
