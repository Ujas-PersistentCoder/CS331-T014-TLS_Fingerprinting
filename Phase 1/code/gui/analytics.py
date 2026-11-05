from PyQt6.QtWidgets import QWidget, QVBoxLayout
from PyQt6.QtGui import QPalette, QIcon
from PyQt6.QtCore import Qt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure
from collections import Counter

class AnalyticsWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Analytics - Client Distribution")
        self.resize(700, 500)
        self.setWindowFlag(Qt.WindowType.Window)
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)
        
        self.figure = Figure(figsize=(6, 5))
        self.canvas = FigureCanvasQTAgg(self.figure)
        self.layout.addWidget(self.canvas)
        
        self.pieAx = self.figure.add_subplot(111)
        self.rowCacheRef = []
        
        # A sleek, modern color palette for the donut chart
        self.chartColors = [
            "#47B39C", "#FFC154", "#EC6B56", "#457B9D", 
            "#E63946", "#008080", "#1D3557", "#A8DADC",
            "#F4A261", "#2A9D8F", "#E9C46A", "#264653"
        ]

    def setRowCache(self, rowCache):
        self.rowCacheRef = rowCache

    def refreshCharts(self):
        self.pieAx.clear()

        bgColor = self.palette().color(QPalette.ColorRole.Window).name()
        textColor = self.palette().color(QPalette.ColorRole.WindowText).name()

        self.figure.patch.set_facecolor(bgColor)
        self.pieAx.set_facecolor(bgColor)

        if not self.rowCacheRef:
            self.canvas.draw()
            return

        matches = []
        for row in self.rowCacheRef:
            match = row.get("ja3Match", "Unknown")
            if match == "Unknown":
                match = row.get("ja4Match", "Unknown")
            matches.append(match)

        pieCounts = Counter(matches)
        labels = list(pieCounts.keys())
        sizes = list(pieCounts.values())

        if sizes:
            wedges, texts, autotexts = self.pieAx.pie(
                sizes,
                autopct='%1.1f%%',
                startangle=90,
                pctdistance=0.75,
                colors=self.chartColors,
                wedgeprops=dict(width=0.4, edgecolor=bgColor, linewidth=2),
                textprops={'color': textColor, 'weight': 'bold', 'fontsize': 10}
            )
            
            self.pieAx.set_title("Client Fingerprint Distribution", color=textColor, weight='bold', pad=20, fontsize=14)
            
            legend = self.pieAx.legend(
                wedges, labels,
                title="Identified Clients",
                loc="center left",
                bbox_to_anchor=(0.9, 0, 0.5, 1),
                frameon=False,
                labelcolor=textColor
            )
            legend.get_title().set_color(textColor)
            legend.get_title().set_weight("bold")

        self.figure.tight_layout()
        self.canvas.draw()