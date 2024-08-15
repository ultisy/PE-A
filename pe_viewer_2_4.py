import importlib
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QMessageBox, QPlainTextEdit
from PyQt5.QtWidgets import *
import pefile
import struct
import datetime
from hex_viewer import HexViewer
from detail import DetailWindow


# 메인 PE_viewer ui
class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("PE_Viewer")
        MainWindow.resize(1000, 1000)

        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName("verticalLayout")

        self.horizontalLayout_Path = QtWidgets.QHBoxLayout()
        self.horizontalLayout_Path.setObjectName("horizontalLayout_Path")

        self.PathButton = QtWidgets.QPushButton(self.centralwidget)
        self.PathButton.setObjectName("PathButton")
        self.horizontalLayout_Path.addWidget(self.PathButton)

        self.Pathbar = QtWidgets.QLineEdit(self.centralwidget)
        self.Pathbar.setObjectName("Pathbar")
        self.Pathbar.setPlaceholderText(" 경로를 설정하고 분석버튼을 누르세요.")
        self.Pathbar.setReadOnly(True)
        self.horizontalLayout_Path.addWidget(self.Pathbar)

        self.PathButton1 = QtWidgets.QPushButton(self.centralwidget)
        self.PathButton1.setObjectName("PathButton1")
        self.horizontalLayout_Path.addWidget(self.PathButton1)

        self.PathButton2 = QtWidgets.QPushButton(self.centralwidget)
        self.PathButton2.setObjectName("PathButton2")
        self.horizontalLayout_Path.addWidget(self.PathButton2)

        self.verticalLayout.addLayout(self.horizontalLayout_Path)

        self.label_dos = QtWidgets.QLabel(self.centralwidget)
        self.label_dos.setObjectName("label_dos")
        self.verticalLayout.addWidget(self.label_dos)

        self.tableWidget_1 = QTableWidget(self)
        self.tableWidget_1.setObjectName("tablewidget_1")
        self.tableWidget_1.setRowCount(2)
        self.tableWidget_1.setColumnCount(2)
        self.tableWidget_1.setHorizontalHeaderLabels(["Variable Name", "Value"])
        self.verticalLayout.addWidget(self.tableWidget_1)
        self.tableWidget_1.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tableWidget_1.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.label_nt = QtWidgets.QLabel(self.centralwidget)
        self.label_nt.setObjectName("label_nt")
        self.verticalLayout.addWidget(self.label_nt)

        self.tableWidget_2 = QTableWidget(self)
        self.tableWidget_2.setObjectName("tablewidget_2")
        self.tableWidget_2.setRowCount(12)
        self.tableWidget_2.setColumnCount(2)
        self.tableWidget_2.setHorizontalHeaderLabels(["Variable Name", "Value"])
        self.verticalLayout.addWidget(self.tableWidget_2)
        self.tableWidget_2.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tableWidget_2.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.label_section = QtWidgets.QLabel(self.centralwidget)
        self.label_section.setObjectName("label_section")
        self.verticalLayout.addWidget(self.label_section)

        self.tableWidget_3 = QTableWidget(self)
        self.tableWidget_3.setObjectName("tablewidget_3")
        self.tableWidget_3.setRowCount(5)
        self.tableWidget_3.setColumnCount(5)
        self.tableWidget_3.setHorizontalHeaderLabels(["Name", "Virtual Addres", "SizeOfRawData", "PointerToRawData", "Characteristics"])
        self.verticalLayout.addWidget(self.tableWidget_3)
        self.tableWidget_3.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tableWidget_3.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.horizontalLayout_Buttons = QtWidgets.QHBoxLayout()
        self.horizontalLayout_Buttons.setObjectName("horizontalLayout_Buttons")

        self.pushButton_1 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_1.setObjectName("pushButton_1")
        self.horizontalLayout_Buttons.addWidget(self.pushButton_1)

        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setObjectName("pushButton_2")
        self.horizontalLayout_Buttons.addWidget(self.pushButton_2)

        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setObjectName("pushButton_3")
        self.horizontalLayout_Buttons.addWidget(self.pushButton_3)

        self.verticalLayout.addLayout(self.horizontalLayout_Buttons)

        self.label_ispacked = QtWidgets.QLabel(self.centralwidget)
        self.label_ispacked.setObjectName("label_ispacked")
        self.verticalLayout.addWidget(self.label_ispacked)

        self.horizontalLayout_Path = QtWidgets.QHBoxLayout()
        self.horizontalLayout_Path.setObjectName("horizontalLayout_Path")

        self.ispackedbar = QtWidgets.QLineEdit(self.centralwidget)
        self.ispackedbar.setObjectName("ispackedbar")
        self.ispackedbar.setReadOnly(True)
        self.horizontalLayout_Path.addWidget(self.ispackedbar)

        self.detailButton = QtWidgets.QPushButton(self.centralwidget)
        self.detailButton.setObjectName("detailButton")
        self.detailButton.setText("detial")
        self.detailButton.clicked.connect(self.open_detail_window)
        self.horizontalLayout_Path.addWidget(self.detailButton)

        self.verticalLayout.addLayout(self.horizontalLayout_Path)

        # Hex button placed separately at the bottom
        self.pushButton_Hex = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_Hex.setObjectName("pushButton_Hex")
        self.pushButton_Hex.setText("Hex")
        self.verticalLayout.addWidget(self.pushButton_Hex)

        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)

        self.PathButton1.clicked.connect(self.file_anl)
        self.PathButton.clicked.connect(lambda: self.p_find(self.Pathbar))
        self.pushButton_1.clicked.connect(self.dos_header_info1)
        self.pushButton_2.clicked.connect(self.nt_header_info1)
        self.pushButton_3.clicked.connect(self.sections_header_info1)
        self.pushButton_Hex.clicked.connect(self.open_hex_viewer)
        self.PathButton2.clicked.connect(self.open_pdf_sample)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        self.path = ""

    import importlib

    def open_pdf_sample(self):
        if self.path:
            try:
                # 여기서 pdf_sample을 가져오기
                import pdf_sample
                importlib.reload(pdf_sample)  # 모듈 다시 로드
                pdf_sample.main(self.path)  # 현재 경로를 pdf_sample.py에 전달
            except ImportError:
                self.show_warning("pdf_sample 모듈을 찾을 수 없습니다.")
        else:
            self.show_warning("선택된 파일 경로가 없습니다.")

    def open_detail_window(self):
        if self.path:
            try:
                pe = pefile.PE(self.path)
                entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                ep_section = pe.get_section_by_rva(entry_point)
                file_offset = ep_section.PointerToRawData
                first_byte = ep_section.get_data()[:1]
                linker_info = pe.FILE_HEADER.Machine
                subsystem = pe.OPTIONAL_HEADER.Subsystem
                compiler_info = pe.FILE_HEADER.Machine

                # Create and show the detail window
                detail_window = DetailWindow()
                detail_window.set_detail_info(entry_point, ep_section, file_offset, first_byte, linker_info, subsystem, compiler_info)
                detail_window.exec_()
            except Exception as e:
                result = f"오류 발생: {str(e)}"
                self.show_warning(result)
        else:
            self.show_warning("파일 없음")


    def open_hex_viewer(self):
        if self.path:
            try:
                with open(self.path, 'rb') as file:
                    hex_data = self.get_hex_data(file)
                hex_viewer = HexViewer(hex_data, self.path)  # 파일 경로를 HexViewer로 전달
                hex_viewer.exec_()
            except Exception as e:
                result = f"오류 발생: {str(e)}"
                self.show_warning(result)
        else:
            self.show_warning("파일 없음")
    def get_hex_data(self, file):
        offset = 0
        chunk_size = 16
        hex_data = ""

        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break

            hex_values = '  '.join(f'{byte:02X}' for byte in chunk)
            ascii_chars = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)

            hex_data += f'{offset:08X}: {hex_values.ljust(chunk_size * 3)} {ascii_chars}\n'
            offset += chunk_size

        return hex_data

    def p_find(self, X):
        file, check = QtWidgets.QFileDialog.getOpenFileName(self, '파일 선택창', "",
                                                            "Text Files (* 모든파일);;Text Files (*.exe)")
        if check:
            X.setText(file)

    def is_packed(self, pe):
        # 패킹된 파일과 관련된 일반적인 특성을 확인합니다.
        packed_sections = ['UPX', 'ASPack', 'ASProtect', 'PECompact', 'Packed', 'Krypton']
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            if any(packed_keyword in section_name for packed_keyword in packed_sections):
                return True
        return False

    def file_anl(self):
        file_path = self.Pathbar.text()
        if not file_path:
            result = "경로가 설정되지 않았습니다."
            self.show_warning(result)
        else:
            try:
                self.path = file_path
                pe = pefile.PE(self.path)
                result = "성공"
                self.show_success(result)
                # 파일이 패킹되어 있는지 확인
                is_packed = self.is_packed(pe)
                if is_packed:
                    result = "파일이 패킹되어 있습니다."
                else:
                    result = "파일은 패킹되어 있지 않습니다."

                # 결과를 텍스트 영역에 표시
                self.ispackedbar.setText(result)

            except pefile.PEFormatError as e:
                result = f"파일을 열지 못했습니다. PE 포맷 오류: {str(e)}"
                result_hex = f"HEX 값은 확인 가능합니다"
                self.show_warning(result)
                self.show_warning(result_hex)
            except Exception as e:
                result = f"파일을 열지 못했습니다. 오류: {str(e)}"
                self.show_warning(result)


    def show_success(self, message):
        msg_box = QMessageBox()
        msg_box.setWindowTitle("성공")
        msg_box.setText(message)
        msg_box.exec_()
    def show_warning(self, message):
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle("경고")
        msg_box.setText(message)
        msg_box.exec_()

    def populate_dos_header_table(self, dos_header_info):
        self.tableWidget_1.setRowCount(len(dos_header_info))
        for row, (key, value) in enumerate(dos_header_info):
            item_key = QTableWidgetItem(key)
            item_value = QTableWidgetItem(value)
            self.tableWidget_1.setItem(row, 0, item_key)
            self.tableWidget_1.setItem(row, 1, item_value)

    def dos_header_info1(self):
        if self.path:
            pe = pefile.PE(self.path)
            dhl_result = self.dos_header_info(pe)
            self.populate_dos_header_table(dhl_result)

    def populate_nt_header_table(self, nt_header_info):
        self.tableWidget_2.setRowCount(len(nt_header_info))
        for row, (key, value) in enumerate(nt_header_info):
            item_key = QTableWidgetItem(key)
            item_value = QTableWidgetItem(value)
            self.tableWidget_2.setItem(row, 0, item_key)
            self.tableWidget_2.setItem(row, 1, item_value)

    def nt_header_info1(self):
        if self.path:
            pe = pefile.PE(self.path)
            nthl_result = self.nt_header_info(pe)
            self.populate_nt_header_table(nthl_result)

    def populate_sections_header_table(self, sections_header_info):
        self.tableWidget_3.setRowCount(len(sections_header_info))
        for row, item in enumerate(sections_header_info):
            for col, value in enumerate(item):
                table_item = QTableWidgetItem(str(value))
                self.tableWidget_3.setItem(row, col, table_item)

    def sections_header_info1(self):
        if self.path:
            pe = pefile.PE(self.path)
            sect_result = self.sections_header_info(pe)
            self.populate_sections_header_table(sect_result)

    def dos_header_info(self, pe):
        dhl = []
        dhl.append(["e_magic", struct.pack('<H', pe.DOS_HEADER.e_magic).decode('utf8')])
        dhl.append(["e_lfanew", hex(pe.DOS_HEADER.e_lfanew)])
        return dhl

    def nt_header_info(self, pe):
        nthl = []
        nthl.append(["Signature", struct.pack('<I', pe.NT_HEADERS.Signature).decode('utf8')])
        nthl.append(["Machine", hex(pe.FILE_HEADER.Machine)])

        timeStr = '1970-01-01 00:00:00'
        Thistime = datetime.datetime.strptime(timeStr, '%Y-%m-%d %H:%M:%S')
        LastBuildtime = Thistime + datetime.timedelta(seconds=pe.FILE_HEADER.TimeDateStamp)

        nthl.append(["TimeDateStamp", str(LastBuildtime)])
        nthl.append(["NumberOfSections", str(pe.FILE_HEADER.NumberOfSections)])
        nthl.append(["SizeOfOptionalHeader", hex(pe.FILE_HEADER.SizeOfOptionalHeader)])
        nthl.append(["Characteristics", hex(pe.FILE_HEADER.Characteristics)])
        nthl.append(["Magic", hex(pe.OPTIONAL_HEADER.Magic)])
        nthl.append(["SizeOfCode", hex(pe.OPTIONAL_HEADER.SizeOfCode)])
        nthl.append(["AddressOfEntryPoint", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)])
        nthl.append(["ImageBase", hex(pe.OPTIONAL_HEADER.ImageBase)])
        nthl.append(["SectionAlignment", str(pe.OPTIONAL_HEADER.SectionAlignment)])
        nthl.append(["FileAlignment", str(pe.OPTIONAL_HEADER.FileAlignment)])
        return nthl

    def sections_header_info(self, pe):
        section_data = []
        for section in pe.sections:
            section_data.append(
                [section.Name.decode('utf8').replace('\x00', ''), hex(section.VirtualAddress),
                 hex(section.SizeOfRawData), hex(section.PointerToRawData), hex(section.Characteristics)])
        return section_data

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "PE Viewer"))
        self.label_dos.setText(_translate("MainWindow",
                                        "<html><head/><body><p><span style=\" font-size:10pt; font-weight:600;\">Dos_Header : </span></p></body></html>"))
        self.label_nt.setText(_translate("MainWindow",
                                        "<html><head/><body><p><span style=\" font-size:10pt; font-weight:600;\">NT_Header : </span></p></body></html>"))
        self.label_section.setText(_translate("MainWindow",
                                        "<html><head/><body><p><span style=\" font-size:10pt; font-weight:600;\">Sections Header : </span></p></body></html>"))
        self.label_ispacked.setText(_translate("MainWindow",
                                              "<html><head/><body><p><span style=\" font-size:10pt; font-weight:600;\">패킹 여부 : </span></p></body></html>"))
        self.PathButton.setText(_translate("MainWindow", "경로 설정"))
        self.PathButton1.setText(_translate("MainWindow", "분석"))
        self.PathButton2.setText(_translate("MainWindow", "PDF"))
        self.pushButton_1.setText(_translate("MainWindow", "DOS header"))
        self.pushButton_3.setText(_translate("MainWindow", "Sections header"))
        self.pushButton_2.setText(_translate("MainWindow", "NT header"))
        self.pushButton_Hex.setText(_translate("MainWindow", "Hex"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())