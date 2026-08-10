from decimal import Decimal
from dataclasses import dataclass
from typing import List
from parser import DatosCFDI

@dataclass
class Partida:
    cuenta:  str
    nombre:  str
    concepto:str
    cargo:   Decimal
    abono:   Decimal
    orden:   int

def generar_provision(cfdi: DatosCFDI) -> List[Partida]:
    d = f"Fact. {cfdi.emisor_rfc} | {cfdi.concepto[:35]}"
    Z = Decimal("0")
    rows = [
        Partida("6010-001", "Gastos generales",      d,               cfdi.subtotal, Z,          1),
        Partida("1180-001", "IVA acreditable",        "IVA acreditable",cfdi.iva,    Z,          2),
    ]
    orden = 3
    if cfdi.isr_retencion > 0:
        rows.append(Partida("2150-001", "ISR retenido por pagar", d, Z, cfdi.isr_retencion, orden))
        orden += 1
    if cfdi.iva_retencion > 0:
        rows.append(Partida("2160-001", "IVA retenido por pagar", d, Z, cfdi.iva_retencion, orden))
        orden += 1
    rows.append(Partida("2100-001", "Proveedores", d, Z, cfdi.total, orden))
    return rows

def generar_pago(cfdi: DatosCFDI, banco: str = "1020-001", ref: str = "") -> List[Partida]:
    d = f"Pago {cfdi.emisor_rfc} {ref}".strip()
    Z = Decimal("0")
    return [
        Partida("2100-001", "Proveedores", d, cfdi.total, Z,          1),
        Partida(banco,      "Bancos",      d, Z,          cfdi.total, 2),
    ]
