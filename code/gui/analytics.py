from PyQt6.QtWidgets import QWidget, QVBoxLayout
from PyQt6.QtCore import pyqtProperty, QPropertyAnimation, QEasingCurve, QTimer
from PyQt6.QtGui import QPalette
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure
import matplotlib.dates as mdates
from collections import Counter
from datetime import datetime, timedelta

class AnalyticsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("border-right: 1px solid #ccc;")
        
        self.panelLayout = QVBoxLayout(self)
        self.panelLayout.setContentsMargins(0, 0, 0, 0)
        
        self.figure = Figure(figsize=(4, 6))
        self.canvas = FigureCanvasQTAgg(self.figure)
        self.panelLayout.addWidget(self.canvas)
        
        self.lineAx = self.figure.add_subplot(211)
        self.pieAx = self.figure.add_subplot(212)
        
        self.targetWidth = 380
        self.isOpen = False
        
        self.setFixedWidth(0)
        self.setVisible(False)
        self.canvas.setVisible(False)
        
        self.animation = QPropertyAnimation(self, b"panelWidth")
        self.animation.setDuration(250)
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.animation.finished.connect(self.onAnimationFinished)
        
        self.updateTimer = QTimer(self)
        self.updateTimer.timeout.connect(self.refreshCharts)
        
        self.rowCacheRef = []

    def getPanelWidth(self):
        return self.width()

    def setPanelWidth(self, width):
        self.setFixedWidth(width)
        if width <= 10:
            self.canvas.setVisible(False)
        else:
            self.canvas.setVisible(True)

    panelWidth = pyqtProperty(int, getPanelWidth, setPanelWidth)

    def setRowCache(self, rowCache):
        self.rowCacheRef = rowCache

    def togglePanel(self):
        if not self.isOpen:
            self.setVisible(True)
            self.animation.stop()
            self.animation.setStartValue(self.width())
            self.animation.setEndValue(self.targetWidth)
            self.isOpen = True
            self.animation.start()
        else:
            self.animation.stop()
            self.animation.setStartValue(self.width())
            self.animation.setEndValue(0)
            self.isOpen = False
            self.animation.start()

    def onAnimationFinished(self):
        if not self.isOpen:
            self.setVisible(False)
        else:
            self.refreshCharts()

    def startLiveUpdates(self):
        self.updateTimer.start(1000)

    def stopLiveUpdates(self):
        self.updateTimer.stop()
        if self.isOpen:
            self.refreshCharts()

    def refreshCharts(self):
        if not self.isOpen or self.width() < 100:
            return

        self.pieAx.clear()
        self.lineAx.clear()

        bgColor = self.palette().color(QPalette.ColorRole.Window).name()
        textColor = self.palette().color(QPalette.ColorRole.WindowText).name()

        self.figure.patch.set_facecolor(bgColor)
        for ax in (self.pieAx, self.lineAx):
            ax.set_facecolor(bgColor)
            ax.tick_params(colors=textColor)
            for spine in ax.spines.values():
                spine.set_edgecolor(textColor)
            ax.title.set_color(textColor)

        if not self.rowCacheRef:
            self.canvas.draw()
            return

        matches = []
        timeBuckets = Counter()

        for row in self.rowCacheRef:
            match = row.get("ja3Match", "Unknown")
            if match == "Unknown":
                match = row.get("ja4Match", "Unknown")
            matches.append(match)

            capTime = row.get("captureTime")
            if capTime:
                bucket = capTime[:19]
                timeBuckets[bucket] += 1

        pieCounts = Counter(matches)
        labels = list(pieCounts.keys())
        sizes = list(pieCounts.values())

        if sizes:
            self.pieAx.pie(
                sizes, labels=labels, autopct='%1.1f%%', startangle=90,
                textprops={'color': textColor}
            )
            self.pieAx.set_title("Client Matches")

        if timeBuckets:
            parsedTimes = {datetime.strptime(k, "%Y-%m-%d %H:%M:%S"): v for k, v in timeBuckets.items()}
            sortedDates = sorted(parsedTimes.keys())

            xData = []
            yData = []

            for i in range(len(sortedDates)):
                currentDate = sortedDates[i]
                xData.append(currentDate)
                yData.append(parsedTimes[currentDate])

                if i < len(sortedDates) - 1:
                    nextDate = sortedDates[i + 1]
                    gapSeconds = (nextDate - currentDate).total_seconds()
                    if gapSeconds > 1:
                        xData.append(currentDate + timedelta(seconds=1))
                        yData.append(0)
                        if gapSeconds > 2:
                            xData.append(nextDate - timedelta(seconds=1))
                            yData.append(0)

            self.lineAx.plot(xData, yData, marker='o', color='tab:blue')
            self.lineAx.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            self.lineAx.set_title("Messages Over Time")
            self.lineAx.tick_params(axis='x', rotation=45)

        self.figure.tight_layout()
        self.canvas.draw()