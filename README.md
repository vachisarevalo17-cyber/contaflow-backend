# ContaFlow Backend

API para ContaFlow — Del XML a la póliza, automático.

## Endpoints principales

- `POST /facturas/upload` — Sube XML del SAT → genera póliza
- `POST /facturas/{id}/pago` — Registra pago
- `GET /facturas` — Lista facturas
- `POST /sat/descargar` — Descarga masiva del SAT con e.firma

## Deploy en Railway

1. Sube esta carpeta a GitHub
2. Conecta el repo en railway.app
3. Agrega PostgreSQL en Railway
4. Listo ✅
