from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QMessageBox, QPlainTextEdit, QDialog
class HexViewer(QDialog):
    def __init__(self, hex_data, file_path):
        super().__init__()
        self.setWindowTitle("Hex Viewer")
        self.setGeometry(800, 800, 1400, 800)

        self.hex_data = hex_data
        self.path = file_path  # 헥스값 편집을 위한 파일 경로 추가

        self.plainTextEditHex = QPlainTextEdit(self)
        self.plainTextEditHex.setGeometry(QtCore.QRect(10, 10, 780, 580))
        self.plainTextEditHex.setObjectName("plainTextEditHex")
        self.plainTextEditHex.setPlainText(self.hex_data)
        font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont)
        self.plainTextEditHex.setFont(font)

        # 스크롤 기능
        scroll_bar = QtWidgets.QScrollBar(QtCore.Qt.Horizontal, self)
        scroll_bar.valueChanged.connect(self.scroll_hex_viewer)
        self.plainTextEditHex.setHorizontalScrollBar(scroll_bar)

        # 값 검색
        self.searchLineEdit = QtWidgets.QLineEdit(self)
        self.searchLineEdit.setPlaceholderText("검색할 값 또는 패턴을 입력하세요.")
        self.searchLineEdit.returnPressed.connect(self.search_hex_value)

        # 검색 버튼
        self.searchButton = QtWidgets.QPushButton(self)
        self.searchButton.setText("검색")
        self.searchButton.clicked.connect(self.search_hex_value)

        self.searchLayout = QtWidgets.QHBoxLayout()
        self.searchLayout.addWidget(self.searchLineEdit)
        self.searchLayout.addWidget(self.searchButton)

        self.mainLayout = QtWidgets.QVBoxLayout()
        self.mainLayout.addWidget(self.plainTextEditHex)
        self.mainLayout.addLayout(self.searchLayout)

        # Hex Edit offset - 수정할 오프셋 지정
        self.LineEdit_offest = QtWidgets.QLineEdit(self)
        self.LineEdit_offest.setPlaceholderText("수정을 시작할 오프셋을 입력하세요.")
        self.LineEdit_offest.returnPressed.connect(self.hex_edit_offset)

        # offset 지정 버튼
        self.LineEdit_offestButton = QtWidgets.QPushButton(self)
        self.LineEdit_offestButton.setText("지정")
        self.LineEdit_offestButton.clicked.connect(self.hex_edit_offset)


        self.LineEditLayout = QtWidgets.QHBoxLayout()
        self.LineEditLayout.addWidget(self.LineEdit_offest)
        self.LineEditLayout.addWidget(self.LineEdit_offestButton)

        # Hex Edit hexadecimal - 수정할 16진수 값 지정
        self.LineEdit_Hex = QtWidgets.QLineEdit(self)
        self.LineEdit_Hex.setPlaceholderText("입력할 16진수 데이터를 입력하세요. (공백으로 구분) ")
        self.LineEdit_Hex.returnPressed.connect(self.hex_edit_hex)

        # Add Hex Edit buttons and layout
        self.HexEditButton = QtWidgets.QPushButton(self)
        self.HexEditButton.setText("Hex Edit")
        self.HexEditButton.clicked.connect(self.hex_edit)
        self.LineEditLayout.addWidget(self.LineEdit_Hex)
        self.LineEditLayout.addWidget(self.HexEditButton)

        self.mainLayout.addLayout(self.LineEditLayout)

        self.setLayout(self.mainLayout)


    # Hex viewer 스크롤
    def scroll_hex_viewer(self, value):
        self.plainTextEditHex.horizontalScrollBar().setValue(value)

    # Hex viewer 검색 기능
    def search_hex_value(self):
        search_text = self.searchLineEdit.text()
        start_index = self.hex_data.find(search_text)
        if start_index != -1:
            self.plainTextEditHex.setFocus()
            cursor = self.plainTextEditHex.textCursor()
            cursor.setPosition(start_index)
            cursor.setPosition(start_index + len(search_text), QtGui.QTextCursor.KeepAnchor)
            self.plainTextEditHex.setTextCursor(cursor)
        else:
            self.show_warning("검색 결과를 찾을 수 없습니다.")

    # 수정할 Hex값의 오프셋 값을 입력 받는 경로 설정
    def hex_edit_offset(self):  # 파일 경로 추가
        with open(self.path, 'rb') as file:
            user_offset = int(self.LineEdit_offest.text(), 16)
            file.seek(user_offset)
        return user_offset

    # 수정할 hex값 입력
    def hex_edit_hex(self):  # 파일 경로 추가
        return bytes.fromhex(self.LineEdit_Hex.text().replace(' ', ''))

    # Hex값 수정
    def hex_edit(self):
        if self.path:
            try:
                with open(self.path, 'rb+') as file:
                    user_offset = self.hex_edit_offset()
                    file.seek(user_offset)

                    data_to_write = self.hex_edit_hex()
                    file.write(data_to_write)

                    self.show_message("Hex 값이 성공적으로 수정되었습니다.")
            except Exception as e:
                result = f"오류 발생: {str(e)}"
                self.show_warning(result)
        else:
            self.show_warning("파일 없음")

    # 오류 메세지 박스
    def show_message(self, message):
        msg_box = QMessageBox()
        msg_box.setWindowTitle("메시지")
        msg_box.setText(message)
        msg_box.exec_()

    # 오류 메세지
    def show_warning(self, message):
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle("경고")
        msg_box.setText(message)
        msg_box.exec_()