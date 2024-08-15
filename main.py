import sys
import subprocess

modules_to_install = ['PyQt5', 'pefile', 'reportlab']

for module in modules_to_install:
    try:
        __import__(module)
    except ImportError:
        print(f"{module} 모듈이 없습니다. 모듈을 설치합니다.")
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', module])

# 다시 import
import PyQt5
import pefile
import reportlab
import datetime
import struct
    
from pe_viewer_2_4 import Ui_MainWindow  # 수정부분
from PyQt5 import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

class kinwriter(QMainWindow, Ui_MainWindow):

    def __init__(self):
        super().__init__()

        self.setupUi(self)
        # self.timer = QTimer(self)
        # self.timer.setSingleShot(False)
        # self.timer.setInterval(5000) # in milliseconds, so 5000 = 5 seconds
        # # self.timer.timeout.connect(self.start_Macro)
        # self.timer.start()i0nscn2kdlr2k

        # print(self.hasMouseTracking())

        self.show()


app = QApplication([])
sn = kinwriter()
QApplication.processEvents()
sys.exit(app.exec_())