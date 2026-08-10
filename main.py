from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import Base, engine
from routers import facturas, sat_descarga

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ContaFlow API",
    description="Del XML a la póliza — automático",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(facturas.router, prefix="/facturas", tags=["Facturas"])
app.include_router(sat_descarga.router, prefix="/sat", tags=["SAT"])
