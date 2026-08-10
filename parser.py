import xml.etree.ElementTree as ET
from decimal import Decimal
from dataclasses import dataclass

NS = {
    "cfdi": "http://www.sat.gob.mx/cfd/4",
    "tfd":  "http://www.sat.gob.mx/TimbreFiscalDigital"
}

@dataclass
class DatosCFDI:
    uuid:          str
    fecha:         str
    emisor_rfc:    str
    emisor_nombre: str
    receptor_rfc:  str
    subtotal:      Decimal
    iva:           Decimal
    total:         Decimal
    isr_retencion: Decimal
    iva_retencion: Decimal
    concepto:      str

def leer_cfdi(xml_bytes: bytes) -> DatosCFDI:
    root = ET.fromstring(xml_bytes)
    subtotal = Decimal(root.get("SubTotal", "0"))
    total    = Decimal(root.get("Total",    "0"))
    fecha    = root.get("Fecha", "")[:10]
    emisor   = root.find("cfdi:Emisor",   NS)
    receptor = root.find("cfdi:Receptor", NS)
    comp     = root.find("cfdi:Complemento", NS)
    tfd      = comp.find("tfd:TimbreFiscalDigital", NS) if comp is not None else None

    # IVA trasladado
    iva = Decimal("0")
    # Retenciones
    isr_ret = Decimal("0")
    iva_ret = Decimal("0")

    impuestos = root.find("cfdi:Impuestos", NS)
    if impuestos is not None:
        for t in impuestos.iter("{http://www.sat.gob.mx/cfd/4}Traslado"):
            if t.get("Impuesto") == "002":
                iva += Decimal(t.get("Importe", "0"))
        for r in impuestos.iter("{http://www.sat.gob.mx/cfd/4}Retencion"):
            if r.get("Impuesto") == "001":
                isr_ret += Decimal(r.get("Importe", "0"))
            if r.get("Impuesto") == "002":
                iva_ret += Decimal(r.get("Importe", "0"))

    conceptos = root.find("cfdi:Conceptos", NS)
    c0 = conceptos.find("cfdi:Concepto", NS) if conceptos is not None else None
    desc = c0.get("Descripcion", "") if c0 is not None else ""

    return DatosCFDI(
        uuid          = tfd.get("UUID") if tfd is not None else f"LOCAL-{fecha}",
        fecha         = fecha,
        emisor_rfc    = emisor.get("Rfc")    if emisor   is not None else "",
        emisor_nombre = emisor.get("Nombre") if emisor   is not None else "",
        receptor_rfc  = receptor.get("Rfc")  if receptor is not None else "",
        subtotal      = subtotal,
        iva           = Decimal(str(round(float(iva), 2))),
        total         = total,
        isr_retencion = Decimal(str(round(float(isr_ret), 2))),
        iva_retencion = Decimal(str(round(float(iva_ret), 2))),
        concepto      = desc,
    )
