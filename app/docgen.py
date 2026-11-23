import io


def make_docx(canary_url: str, title: str = "Informe confidencial") -> bytes:
    from docx import Document

    doc = Document()
    doc.add_heading(title, level=1)
    doc.add_paragraph("Documento interno. Distribucion restringida.")
    doc.add_paragraph("")
    p = doc.add_paragraph("Acceso al panel de respaldo: ")
    _add_hyperlink(doc, p, canary_url, "abrir aqui")
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _add_hyperlink(document, paragraph, url: str, text: str) -> None:
    from docx.oxml.shared import OxmlElement, qn

    part = paragraph.part
    r_id = part.relate_to(
        url,
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
        is_external=True,
    )
    hyperlink = OxmlElement("w:hyperlink")
    hyperlink.set(qn("r:id"), r_id)

    run = OxmlElement("w:r")
    rPr = OxmlElement("w:rPr")
    color = OxmlElement("w:color")
    color.set(qn("w:val"), "0563C1")
    rPr.append(color)
    underline = OxmlElement("w:u")
    underline.set(qn("w:val"), "single")
    rPr.append(underline)
    run.append(rPr)
    t = OxmlElement("w:t")
    t.text = text
    run.append(t)
    hyperlink.append(run)
    paragraph._p.append(hyperlink)


def make_xlsx(canary_url: str) -> bytes:
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = "Inventario"
    ws["A1"] = "Sistema"
    ws["B1"] = "Acceso"
    ws["A2"] = "Panel de respaldo"
    cell = ws["B2"]
    cell.value = "abrir"
    cell.hyperlink = canary_url
    cell.style = "Hyperlink"
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def make_pdf(canary_url: str) -> bytes:
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    c.setTitle("Informe confidencial")
    c.drawString(72, 780, "Informe confidencial")
    c.drawString(72, 760, "Acceso al panel de respaldo:")
    c.setFillColorRGB(0.05, 0.39, 0.75)
    c.drawString(72, 740, canary_url)
    c.linkURL(canary_url, (72, 735, 420, 750), relative=0)
    c.showPage()
    c.save()
    return buf.getvalue()
