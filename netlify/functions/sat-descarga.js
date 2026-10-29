'use strict';
/**
 * ContaFlow MX — Netlify Function: sat-descarga
 * Integración con SAT Descarga Masiva de CFDI (servicio oficial del SAT)
 *
 * Flujo completo:
 *   1. POST { action:'autenticar', certBase64, keyBase64, keyPass }
 *      → { ok:true, token, rfc }
 *   2. POST { action:'solicitar', token, rfc, fechaInicio, fechaFin, tipoSol, tipoComp }
 *      → { ok:true, idSolicitud, codEstatus }
 *   3. POST { action:'verificar', token, rfc, idSolicitud }
 *      → { ok:true, estado, paquetes:[], numCfdis }
 *   4. POST { action:'descargar', token, rfc, idPaquete }
 *      → { ok:true, xmlFiles:[{nombre, contenido}] }
 */

const forge = require('node-forge');
const fetch = require('node-fetch');
const AdmZip = require('adm-zip');
const crypto = require('crypto');

/* ── CORS ─────────────────────────────────────────────────────────────────── */
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json; charset=utf-8'
};

/* ── SAT ENDPOINTS ────────────────────────────────────────────────────────── */
const EP = {
  auth:     'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/autenticaservice.svc',
  solicitar:'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/solicitudservice.svc',
  verificar:'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/verificasolicitudservice.svc',
  descargar:'https://cfdidescargamasivadescarga.clouda.sat.gob.mx/descargaservice.svc'
};
const SA = {
  auth:     'http://DescargaMasivaTerceros.gob.mx/IAutenticaService/Autentica',
  solicitar:'http://DescargaMasivaTerceros.gob.mx/ISolicitudService/SolicitaDescarga',
  verificar:'http://DescargaMasivaTerceros.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga',
  descargar:'http://DescargaMasivaTerceros.gob.mx/IDescargaMasivaService/Descargar'
};

/* ── UTILIDADES ───────────────────────────────────────────────────────────── */
function isoNow()       { return new Date().toISOString().replace(/\.\d{3}Z/, '.000Z'); }
function isoPlus(mins)  { return new Date(Date.now()+mins*60000).toISOString().replace(/\.\d{3}Z/, '.000Z'); }

function sha1b64(str) {
  return crypto.createHash('sha1').update(Buffer.from(str,'utf8')).digest('base64');
}
function rsaSha1b64(str, pemKey) {
  return crypto.createSign('RSA-SHA1').update(Buffer.from(str,'utf8')).sign(pemKey,'base64');
}

/* ── PARSEO FIEL ──────────────────────────────────────────────────────────── */
function parseFiel(certB64, keyB64, keyPass) {
  // Certificado (DER → PEM → base64 limpio para SOAP)
  const certDer = Buffer.from(certB64, 'base64');
  const certBuf = forge.util.createBuffer(certDer.toString('binary'));
  const certAsn = forge.asn1.fromDer(certBuf);
  const cert    = forge.pki.certificateFromAsn1(certAsn);
  const certPem = forge.pki.certificateToPem(cert);
  const certSoap = certPem.replace(/-----[A-Z ]+-----\r?\n?/g,'').replace(/\r?\n/g,'');

  // RFC del certificado
  let rfc = '';
  for (const a of cert.subject.attributes) {
    const v = String(a.value||'');
    if ((a.shortName==='serialNumber'||a.name==='serialNumber') && v.length>=12) {
      // SAT pone en serialNumber algo como "XAXX010101AAA / CUSF800827Q30"
      const m = v.match(/([A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3})/i);
      if (m) { rfc=m[1].toUpperCase(); break; }
    }
    if ((a.shortName==='CN'||a.name==='commonName') && !rfc) {
      const m = v.match(/([A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3})/i);
      if (m) rfc=m[1].toUpperCase();
    }
  }
  if (!rfc) throw new Error('No se pudo extraer el RFC del certificado FIEL');

  // Llave privada (DER PKCS#8 cifrada con contraseña)
  const keyDer = Buffer.from(keyB64,'base64');
  const keyBuf = forge.util.createBuffer(keyDer.toString('binary'));
  const keyAsn = forge.asn1.fromDer(keyBuf);

  let pkeyPem;
  try {
    const encKey = forge.pki.encryptedPrivateKeyFromAsn1(keyAsn);
    const decKey = forge.pki.decryptPrivateKeyInfo(encKey, keyPass);
    const pkey   = forge.pki.privateKeyFromAsn1(decKey);
    pkeyPem      = forge.pki.privateKeyToPem(pkey);
  } catch(e) {
    throw new Error('Contraseña incorrecta o archivo .key inválido');
  }

  return { rfc, certSoap, pkeyPem };
}

/* ── CONSTRUCCIÓN DE ENVELOPES SOAP ──────────────────────────────────────── */

/**
 * Autentica: firma el Timestamp con FIEL (WS-Security XML-DSig)
 */
function buildAuthSoap(certSoap, pkeyPem) {
  const created = isoNow();
  const expires = isoPlus(5);

  // Forma canónica del Timestamp (EC14N — solo espacios de nombre utilizados)
  const NS_U = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
  const tsCanon = `<u:Timestamp xmlns:u="${NS_U}" u:Id="_0"><u:Created>${created}</u:Created><u:Expires>${expires}</u:Expires></u:Timestamp>`;
  const digestTs = sha1b64(tsCanon);

  // Forma canónica de SignedInfo (EC14N — empty elements expand to open+close)
  const siCanon = `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod><Reference URI="#_0"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>${digestTs}</DigestValue></Reference></SignedInfo>`;
  const sigValue = rsaSha1b64(siCanon, pkeyPem);

  return `<?xml version="1.0" encoding="utf-8"?>`+
`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="${NS_U}">`+
`<s:Header>`+
`<o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">`+
`<u:Timestamp u:Id="_0"><u:Created>${created}</u:Created><u:Expires>${expires}</u:Expires></u:Timestamp>`+
`<o:BinarySecurityToken u:Id="uuid-cert" `+
  `ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" `+
  `EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">`+
  `${certSoap}`+
`</o:BinarySecurityToken>`+
`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">`+
  `<SignedInfo>`+
    `<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`+
    `<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>`+
    `<Reference URI="#_0">`+
      `<Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>`+
      `<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>`+
      `<DigestValue>${digestTs}</DigestValue>`+
    `</Reference>`+
  `</SignedInfo>`+
  `<SignatureValue>${sigValue}</SignatureValue>`+
  `<KeyInfo>`+
    `<o:SecurityTokenReference>`+
      `<o:Reference URI="#uuid-cert" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>`+
    `</o:SecurityTokenReference>`+
  `</KeyInfo>`+
`</Signature>`+
`</o:Security>`+
`</s:Header>`+
`<s:Body>`+
  `<Autentica xmlns="http://DescargaMasivaTerceros.gob.mx"/>`+
`</s:Body>`+
`</s:Envelope>`;
}

/**
 * Token header reutilizable para llamadas posteriores (WS-Trust)
 */
function tokenHeader(token) {
  return `<h:RequestSecurityTokenResponseCollection `+
    `xmlns:h="http://docs.oasis-open.org/ws-sx/ws-trust/200512" `+
    `xmlns:i="http://www.w3.org/2001/XMLSchema-instance">`+
    `<h:RequestSecurityTokenResponse>`+
      `<h:RequestedSecurityToken>`+
        `<wsse:BinarySecurityToken `+
          `xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">`+
          token+
        `</wsse:BinarySecurityToken>`+
      `</h:RequestedSecurityToken>`+
    `</h:RequestSecurityTokenResponse>`+
  `</h:RequestSecurityTokenResponseCollection>`;
}

function buildSolicitudSoap(token, rfc, fechaInicio, fechaFin, tipoSol, tipoComp) {
  // Atributos de la solicitud — incluir emisor o receptor
  const ei = tipoComp==='E' ? `RfcEmisor="${rfc}"` : `RfcReceptor="${rfc}"`;
  const attrs = `FechaFinal="${fechaFin}T23:59:59" FechaInicial="${fechaInicio}T00:00:00" `+
                `RfcSolicitante="${rfc}" TipoSolicitud="${tipoSol}" ${ei}`;
  return `<?xml version="1.0" encoding="utf-8"?>`+
`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">`+
`<s:Header>${tokenHeader(token)}</s:Header>`+
`<s:Body>`+
  `<SolicitaDescarga xmlns="http://DescargaMasivaTerceros.gob.mx">`+
    `<solicitud ${attrs}/>`+
  `</SolicitaDescarga>`+
`</s:Body>`+
`</s:Envelope>`;
}

function buildVerificaSoap(token, rfc, idSolicitud) {
  return `<?xml version="1.0" encoding="utf-8"?>`+
`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">`+
`<s:Header>${tokenHeader(token)}</s:Header>`+
`<s:Body>`+
  `<VerificaSolicitudDescarga xmlns="http://DescargaMasivaTerceros.gob.mx">`+
    `<solicitud IdSolicitud="${idSolicitud}" RfcSolicitante="${rfc}"/>`+
  `</VerificaSolicitudDescarga>`+
`</s:Body>`+
`</s:Envelope>`;
}

function buildDescargaSoap(token, rfc, idPaquete) {
  return `<?xml version="1.0" encoding="utf-8"?>`+
`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">`+
`<s:Header>${tokenHeader(token)}</s:Header>`+
`<s:Body>`+
  `<PeticionDescargaMasivaTercerosSolicitud xmlns="http://DescargaMasivaTerceros.gob.mx">`+
    `<peticionDescarga IdPaquete="${idPaquete}" RfcSolicitante="${rfc}"/>`+
  `</PeticionDescargaMasivaTercerosSolicitud>`+
`</s:Body>`+
`</s:Envelope>`;
}

/* ── LLAMADA AL SAT ───────────────────────────────────────────────────────── */
async function callSoap(url, action, body) {
  const controller = new AbortController();
  const timer = setTimeout(()=>controller.abort(), 22000);
  try {
    const res = await fetch(url, {
      method:'POST',
      headers:{
        'Content-Type':'text/xml; charset=utf-8',
        'SOAPAction':`"${action}"`,
        'Accept':'text/xml'
      },
      body,
      signal: controller.signal
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`SAT HTTP ${res.status}: ${text.slice(0,300)}`);
    return text;
  } finally {
    clearTimeout(timer);
  }
}

/* ── PARSEO XML RESPUESTAS SAT ────────────────────────────────────────────── */
function tag(xml, ...names) {
  for (const n of names) {
    const rx = new RegExp(`<(?:[\\w]+:)?${n}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/(?:[\\w]+:)?${n}>`, 'i');
    const m = xml.match(rx);
    if (m) return m[1].trim();
  }
  return null;
}
function attr(xml, elem, attrName) {
  const rx = new RegExp(`<(?:[\\w]+:)?${elem}(?:[^>]*?)\\s${attrName}="([^"]*)"`, 'i');
  const m = xml.match(rx);
  return m ? m[1] : null;
}

/* ── HANDLERS POR ACCIÓN ─────────────────────────────────────────────────── */
async function accionAutenticar(body) {
  const { certBase64, keyBase64, keyPass } = body;
  if (!certBase64||!keyBase64||!keyPass) throw new Error('Se requieren certBase64, keyBase64 y keyPass');

  const { rfc, certSoap, pkeyPem } = parseFiel(certBase64, keyBase64, keyPass);
  const soap = buildAuthSoap(certSoap, pkeyPem);
  const xml  = await callSoap(EP.auth, SA.auth, soap);

  // El SAT devuelve el token en AutenticaResult
  const token = tag(xml, 'AutenticaResult');
  if (!token || token.length < 20) {
    // Intentar extraer mensaje de error
    const fault = tag(xml, 'faultstring', 'Reason', 'Text') || xml.slice(0,400);
    throw new Error('SAT no devolvió token. ' + fault);
  }
  return { token, rfc };
}

async function accionSolicitar(body) {
  const { token, rfc, fechaInicio, fechaFin, tipoSol='CFDI', tipoComp='R' } = body;
  if (!token||!rfc||!fechaInicio||!fechaFin) throw new Error('Faltan parámetros');

  const soap = buildSolicitudSoap(token, rfc, fechaInicio, fechaFin, tipoSol, tipoComp);
  const xml  = await callSoap(EP.solicitar, SA.solicitar, soap);

  const codEstatus  = attr(xml,'SolicitaDescargaResult','CodEstatus') || attr(xml,'respuesta','CodEstatus');
  const idSolicitud = attr(xml,'SolicitaDescargaResult','IdSolicitud') || attr(xml,'respuesta','IdSolicitud');
  const msg         = attr(xml,'SolicitaDescargaResult','Mensaje')     || attr(xml,'respuesta','Mensaje') || '';

  if (!idSolicitud) {
    throw new Error(`SAT rechazó la solicitud (código ${codEstatus}): ${msg || xml.slice(0,300)}`);
  }
  return { idSolicitud, codEstatus, mensaje: msg };
}

async function accionVerificar(body) {
  const { token, rfc, idSolicitud } = body;
  if (!token||!rfc||!idSolicitud) throw new Error('Faltan parámetros');

  const soap = buildVerificaSoap(token, rfc, idSolicitud);
  const xml  = await callSoap(EP.verificar, SA.verificar, soap);

  const codEstatus = attr(xml,'VerificaSolicitudDescargaResult','CodEstatus');
  const estado     = attr(xml,'VerificaSolicitudDescargaResult','EstadoSolicitud');
  const numCfdis   = attr(xml,'VerificaSolicitudDescargaResult','NumeroCFDIs') || '0';

  // Extraer IDs de paquetes
  const paquetes = [];
  const mIds = xml.match(/<[^>]*?:?IdsPaquetes[^>]*?>([\s\S]*?)<\/[^>]*?:?IdsPaquetes>/i);
  if (mIds) {
    const ids = mIds[1].match(/<[^>]*?:?string[^>]*?>([^<]+)<\/[^>]*?:?string>/gi)||[];
    ids.forEach(function(s){ const m=s.match(/>([^<]+)</); if(m) paquetes.push(m[1].trim()); });
  }

  return { codEstatus, estado, numCfdis, paquetes };
}

async function accionDescargar(body) {
  const { token, rfc, idPaquete } = body;
  if (!token||!rfc||!idPaquete) throw new Error('Faltan parámetros');

  const soap = buildDescargaSoap(token, rfc, idPaquete);
  const xml  = await callSoap(EP.descargar, SA.descargar, soap);

  const b64zip = tag(xml,'Paquete','paquete');
  if (!b64zip) throw new Error('SAT no devolvió el paquete ' + idPaquete);

  const zipBuf = Buffer.from(b64zip, 'base64');
  const zip    = new AdmZip(zipBuf);
  const xmlFiles = [];

  zip.getEntries().forEach(function(entry){
    if (entry.entryName.toLowerCase().endsWith('.xml')) {
      xmlFiles.push({
        nombre:    entry.entryName,
        contenido: entry.getData().toString('utf8')
      });
    }
  });

  return { xmlFiles, total: xmlFiles.length };
}

/* ── HANDLER PRINCIPAL ────────────────────────────────────────────────────── */
exports.handler = async function(event) {
  // Preflight CORS
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode:200, headers:CORS, body:'' };
  }

  let body;
  try { body = JSON.parse(event.body||'{}'); }
  catch(e) { return { statusCode:400, headers:CORS, body:JSON.stringify({error:'JSON inválido'}) }; }

  const action = body.action;

  try {
    let result;
    switch(action) {
      case 'autenticar': result = await accionAutenticar(body); break;
      case 'solicitar':  result = await accionSolicitar(body);  break;
      case 'verificar':  result = await accionVerificar(body);  break;
      case 'descargar':  result = await accionDescargar(body);  break;
      default: return { statusCode:400, headers:CORS, body:JSON.stringify({error:`Acción desconocida: ${action}`}) };
    }
    return { statusCode:200, headers:CORS, body:JSON.stringify({ok:true, ...result}) };

  } catch(err) {
    console.error('[ContaFlow SAT]', action, err.message);
    return { statusCode:500, headers:CORS, body:JSON.stringify({error: err.message||'Error interno'}) };
  }
};
