from PyQt5.QtWidgets import *

class DetailWindow(QDialog):
    def __init__(self, parent=None):
        super(DetailWindow, self).__init__(parent)
        self.setWindowTitle("Detail Information")

        self.layout = QVBoxLayout(self)

        self.layout.addWidget(QLabel("-------------------------Detail Information------------------------"))

        self.entry_point_layout = self.create_label_with_text("Entry Point")
        self.layout.addLayout(self.entry_point_layout)

        self.ep_section_layout = self.create_label_with_text("Ep_Section")
        self.layout.addLayout(self.ep_section_layout)

        self.file_offset_layout = self.create_label_with_text("File Offset")
        self.layout.addLayout(self.file_offset_layout)

        self.first_16bytes_layout = self.create_label_with_text("First 16 Bytes")
        self.layout.addLayout(self.first_16bytes_layout)

        self.linker_info_layout = self.create_label_with_text("Linker Info")
        self.layout.addLayout(self.linker_info_layout)

        self.subsystem_layout = self.create_label_with_text("Subsystem")
        self.layout.addLayout(self.subsystem_layout)

        self.compiler_info_layout = self.create_label_with_text("Compiler Info")
        self.layout.addLayout(self.compiler_info_layout)

    def create_label_with_text(self, label_text):
        layout = QHBoxLayout()

        label = QLabel(label_text)
        layout.addWidget(label)

        plain_text = QLabel()
        layout.addWidget(plain_text)

        return layout
    def set_detail_info(self, entry_point, ep_section, file_offset, first_byte, linker_info, subsystem, compiler_info):
        self.set_text_in_layout(self.entry_point_layout, hex(entry_point))
        self.set_text_in_layout(self.ep_section_layout, str(ep_section))
        self.set_text_in_layout(self.file_offset_layout, hex(file_offset))
        self.set_text_in_layout(self.first_16bytes_layout, first_byte.hex())
        self.set_text_in_layout(self.linker_info_layout, hex(linker_info))
        self.set_text_in_layout(self.subsystem_layout, hex(subsystem))
        self.set_text_in_layout(self.compiler_info_layout, hex(compiler_info))

    def set_text_in_layout(self, layout, text):
        label, plain_text = layout.itemAt(0).widget(), layout.itemAt(1).widget()
        plain_text.setText(text)


