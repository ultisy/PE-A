# pdf_sample.py
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import datetime as dt
import pefile
import struct
import sys

pdfmetrics.registerFont(TTFont("맑은 고딕", "malgun.ttf"))
pdf = canvas.Canvas('PE_Report.pdf')


def main(path):
    # PE 파일 경로
    pe = pefile.PE(path)

    pdf.setFont("맑은 고딕", 30)
    pdf.drawCentredString(300, 780, 'PE 분석 보고서')

    pdf.setLineWidth(0.3)
    pdf.line(30, 760, 580, 760)
    pdf.line(30, 757, 580, 757)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="헤더",
        fontName="맑은 고딕"
    ))

    now = dt.datetime.now()

    p1 = Paragraph(now.strftime("%Y %B %d %A . %H시 %M분 %S초"), style=styles["헤더"])
    p1.wrapOn(pdf, 400, 100)
    p1.drawOn(pdf, 350, 720)
    p2 = Paragraph(now.strftime("작성자 : 홍길동"), style=styles["헤더"])
    p2.wrapOn(pdf, 400, 100)
    p2.drawOn(pdf, 480, 705)

    def dos_header_info(pe):
        dos_header_list = []
        dos_header_list.append(["실제 변수명", "값", "의미"])
        dos_header_list.append(["e_magic", struct.pack('<H', pe.DOS_HEADER.e_magic).decode('utf8'), "DOS Signature"])
        dos_header_list.append(["e_lfanew", hex(pe.DOS_HEADER.e_lfanew), "NT header offset"])
        return dos_header_list

    pdf.setFont("맑은 고딕", 10)
    pdf.drawString(60, 680, "[DOS Header]")
    y = 665
    # 이중 리스트의 각 항목을 PDF에 추가
    for sublist in dos_header_info(pe):
        x = 70  # 시작 x 좌표
        for item in sublist:
            pdf.drawString(x, y, item)
            x += 110  # 다음 항목을 위해 x 좌표 이동
        y -= 10  # 다음 줄로 이동하기 위해 y 좌표 이동

    pdf.drawString(60, 625, "[NT Header]")

    def nt_header_info(pe):
        nt_header_list = []
        nt_header_list.append(["실제 변수명", "값", "의미"])
        nt_header_list.append(["Signature", struct.pack('<I', pe.NT_HEADERS.Signature).decode('utf8'), "NF Signature"])
        nt_header_list.append(["Machine", hex(pe.FILE_HEADER.Machine), "CPU 별 고유값 (x86 = 0x14c / x64 = 0x8664)"])
        nt_header_list.append(["NumberOfSections", pe.FILE_HEADER.NumberOfSections, "Section의 총 개수"])
        nt_header_list.append(["SizeOfOptionalHeader", hex(pe.FILE_HEADER.SizeOfOptionalHeader), "OptionalHeader의 크기"])
        nt_header_list.append(["Characteristics", hex(pe.FILE_HEADER.Characteristics), "이 파일의 속성"])
        nt_header_list.append(
            ["Magic", hex(pe.OPTIONAL_HEADER.Magic), "Optional header를 구분하는 Signature (32bit=10b / 64bit=20b)"])
        nt_header_list.append(
            ["SizeOfCode", hex(pe.OPTIONAL_HEADER.SizeOfCode), "IMAGE_SCN_CNT_CODE 속성을 갖는 섹션들의 총 사이즈 크기"])
        nt_header_list.append(
            ["AddressOfEntryPoint", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "PE 파일이 메모리 로드 후 처음 실행되어야 하는 코드 주소"])
        nt_header_list.append(["ImageBase", hex(pe.OPTIONAL_HEADER.ImageBase), "PE파일이 매핑되는 시작주소"])
        nt_header_list.append(["SectionAlignment", pe.OPTIONAL_HEADER.SectionAlignment, "메모리 상에서의 최소 섹션 단위"])
        nt_header_list.append(["FileAlignment", pe.OPTIONAL_HEADER.FileAlignment, "파일 상에서의 최소 섹션 단위"])
        return nt_header_list

    y = 610
    # 이중 리스트의 각 항목을 PDF에 추가
    for sublist in nt_header_info(pe):
        x = 70  # 시작 x 좌표
        for item in sublist:
            pdf.drawString(x, y, str(item))
            x += 110  # 다음 항목을 위해 x 좌표 이동
        y -= 12  # 다음 줄로 이동하기 위해 y 좌표 이동

    pdf.drawString(60, 460, "[Sections Header]")

    pdf.drawString(60, 450, "Name                     Section 이름")
    pdf.drawString(60, 440, "VirtualAddress          섹션의 RAV(ImageBase + VA)를 위한 VA 값")
    pdf.drawString(60, 430, "SizeOfRawData         파일 상에서 섹션이 차지하는 크기")
    pdf.drawString(60, 420, "PointerToRawData     파일 상에서 섹션이 시작하는 위치")
    pdf.drawString(60, 410, "Characteristics          섹션의 특징을 나타냄")

    pdf.drawString(60, 390,
                   "   ""Name""              ""Virtual Address""           ""SizeOfRawData""        ""PointerToRawData""    ""Characteristics")

    def section_data_info(pe):
        section_data = []
        for section in pe.sections:
            section_data.append(
                [section.Name.decode('utf8').replace('\x00', ''), hex(section.VirtualAddress),
                 hex(section.SizeOfRawData), hex(section.PointerToRawData), hex(section.Characteristics)])
        return section_data

    y = 380
    # 이중 리스트의 각 항목을 PDF에 추가
    for sublist in section_data_info(pe):
        x = 70  # 시작 x 좌표
        for item in sublist:
            pdf.drawString(x, y, item)
            x += 95  # 다음 항목을 위해 x 좌표 이동
        y -= 10  # 다음 줄로 이동하기 위해 y 좌표 이동


    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_section = pe.get_section_by_rva(entry_point)
    file_offset = ep_section.PointerToRawData
    first_byte = ep_section.get_data()[:1]
    linker_info = pe.FILE_HEADER.Machine
    subsystem = pe.OPTIONAL_HEADER.Subsystem
    compiler_info = pe.FILE_HEADER.Machine

    pdf.drawString(60, 290, "[Details about Packed File]")
    def Detail_info(pe):
        Detail_list = []
        Detail_list.append(["Entry Point", hex(entry_point)])
        Detail_list.append(["Ep_Section", str(ep_section.Name.decode())])
        Detail_list.append(["File Offset", hex(file_offset)])
        Detail_list.append(["First 16 Bytes", first_byte])
        Detail_list.append(["Linker Info", hex(linker_info)])
        Detail_list.append(["Subsystem", hex(subsystem)])
        Detail_list.append(["Compiler Info", hex(compiler_info)])
        return Detail_list

    y = 280
    # 이중 리스트의 각 항목을 PDF에 추가
    for sublist in Detail_info(pe):
        x = 70  # 시작 x 좌표
        for item in sublist:
            pdf.drawString(x, y, str(item))
            x += 95  # 다음 항목을 위해 x 좌표 이동
        y -= 10  # 다음 줄로 이동하기 위해 y 좌표 이동


    pdf.drawString(60, 200, "컴파일러 정보:   intel 368/x86 = 0x14c , intel 64 = 0x0200 , AMD64 = 0x8664")

    pdf.save()



if __name__ == "__main__":
    # 명령행 인수를 처리하려면
    if len(sys.argv) != 2:
        print("")
    else:
        file_path = sys.argv[1]
        main(file_path)
