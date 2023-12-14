import sys
from PyQt5.QtWidgets import QApplication
from plugins.RustNet import RustNetApp

def design():
    return """
    RustNetApp {
        background-color: #2d2d2d;  /* Dark background color */
        color: #ffffff;  /* Light text color */
        border: none;  /* No border */
    }

    QLabel {
        color: #ffffff;  /* Light text color for labels */
        border: none;  /* No border */
    }

    QPushButton {
        background-color: #3498db;  /* Dark blue background for buttons */
        color: #ffffff;  /* Light text color for buttons */
        border: none;  /* No border */
    }

    QPushButton:hover {
        background-color: #2980b9;  /* Darker blue hover color for buttons */
        border: none;  /* No border */
    }

    QTextEdit {
        background-color: #2c3e50;  /* Dark background for text edit */
        color: #ecf0f1;  /* Light text color for text edit */
        border: none;  /* No border */
    }
    """

app = QApplication(sys.argv)
app.setStyleSheet(design())
window = RustNetApp()
window.show()
sys.exit(app.exec_())
