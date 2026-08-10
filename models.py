from sqlalchemy import Column, String, Numeric, Date, Enum, Integer, ForeignKey
from sqlalchemy.orm import relationship
from database import Base
import uuid

def new_id():
    return str(uuid.uuid4())

class Factura(Base):
    __tablename__ = "facturas"
    id            = Column(String, primary_key=True, default=new_id)
    uuid_sat      = Column(String, unique=True, index=True)
    fecha         = Column(Date)
    emisor_rfc    = Column(String(13))
    emisor_nombre = Column(String)
    receptor_rfc  = Column(String(13))
    subtotal      = Column(Numeric(15, 2))
    iva           = Column(Numeric(15, 2))
    total         = Column(Numeric(15, 2))
    isr_retencion = Column(Numeric(15, 2), default=0)
    iva_retencion = Column(Numeric(15, 2), default=0)
    concepto      = Column(String)
    status        = Column(
        Enum("pendiente", "provisionada", "pagada", name="factura_status"),
        default="pendiente"
    )
    polizas = relationship("Poliza", back_populates="factura")

class Poliza(Base):
    __tablename__ = "polizas"
    id         = Column(String, primary_key=True, default=new_id)
    factura_id = Column(String, ForeignKey("facturas.id"))
    tipo       = Column(Enum("provision", "pago", name="poliza_tipo"))
    fecha      = Column(Date)
    referencia = Column(String)
    factura    = relationship("Factura", back_populates="polizas")
    partidas   = relationship("Partida", back_populates="poliza", order_by="Partida.orden")

class Partida(Base):
    __tablename__ = "partidas"
    id            = Column(String, primary_key=True, default=new_id)
    poliza_id     = Column(String, ForeignKey("polizas.id"))
    cuenta        = Column(String)
    nombre_cuenta = Column(String)
    concepto      = Column(String)
    cargo         = Column(Numeric(15, 2), default=0)
    abono         = Column(Numeric(15, 2), default=0)
    orden         = Column(Integer)
    poliza        = relationship("Poliza", back_populates="partidas")
