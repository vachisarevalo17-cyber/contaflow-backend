# ContaFlow MX 🇲🇽

App de contabilidad para PYMES y contadores independientes.  
Conversión automática de CFDI XML → Pólizas contables.

## Características
- 📁 Importar CFDI XML (individual o masivo)
- 📊 Pólizas contables automáticas
- 📥 Descarga masiva del SAT (Servicio de Descarga Masiva)
- 📱 PWA instalable (funciona offline)
- 📈 Exportar a Excel con formato profesional

## Despliegue

Conecta este repositorio a [Netlify](https://netlify.com) con la configuración de `netlify.toml` incluida.

## Estructura
```
/
├── ContaFlow.html          # App principal
├── manifest.json           # PWA manifest
├── sw.js                   # Service Worker
├── netlify.toml            # Configuración Netlify
└── netlify/
    └── functions/
        ├── package.json    # Dependencias del backend
        └── sat-descarga.js # API Descarga Masiva SAT
```

## Variables de entorno
No se requieren variables de entorno adicionales.

## Uso del SAT Descarga Masiva
En la app, ve a **☁️ Datos → Descargar del SAT** y sube tu FIEL (.cer + .key + contraseña).  
Tu FIEL solo se usa para firmar la solicitud y nunca se almacena.
