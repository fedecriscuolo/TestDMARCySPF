# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

# DMARC-Intelligence-Console

Sistema de monitoreo de autenticación de email (SPF/DKIM/DMARC) para cualquier dominio.  
**Stack**: PostgreSQL + Python + Flask + nginx + dnspython + n8n (opcional)

---

## Comandos de desarrollo

### Setup inicial

```bash
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install psycopg2-binary flask flask-cors python-dotenv requests dnspython

cp .env.example .env
# Editar .env con credenciales de PostgreSQL

createdb dmarc_monitor
python dmarc_monitor.py --init-db
```

### Con Docker

Postgres NO se levanta en este compose — debe existir externamente y ser accesible vía `host.docker.internal:5432`.

```bash
docker-compose up -d --build
docker-compose exec api python dmarc_monitor.py --init-db
# Dashboard: http://localhost  |  API: http://localhost:5000/api/health
```

### Uso diario

```bash
python dmarc_monitor.py --file reporte.xml
python dmarc_monitor.py --folder ./dmarc_reports/
python dmarc_monitor.py --summary tudominio.com --days 7
python dmarc_monitor.py --alerts tudominio.com
python dmarc_api.py
```

---

## Arquitectura

### `dmarc_monitor.py` — Parser + persistencia + alertas (CLI)

1. `parse_dmarc_xml()` lee XML DMARC estándar (RFC 7489) con `xml.etree.ElementTree`.
2. `DMARCDatabase.insert_feedback()` inserta 1 fila en `dmarc_reports` + N en `dmarc_report_records`. Idempotencia: `ON CONFLICT (report_id) DO NOTHING`.
3. `_insert_alerts_for_record()` evalúa por record y escribe en `dmarc_alerts`.
4. CLI: `--init-db`, `--reset-db` (destructivo), `--file`, `--folder`, `--summary`, `--alerts`.

### `dmarc_api.py` — REST API (Flask)

Nueva conexión por request (sin pooling).

| Endpoint | Método | Descripción |
|---|---|---|
| `/api/summary` | GET | Stats SPF/DKIM por dominio y rango de días |
| `/api/alerts` | GET | Alertas no reconocidas. Filtros: domain, severity |
| `/api/reports` | GET | Records individuales. Paginación limit/offset |
| `/api/report-history` | GET | Historial de XMLs: fecha, domain, records, alertas |
| `/api/trends` | GET | Pass rate agrupado por día |
| `/api/health` | GET | Verifica conexión a BD |
| `/api/acknowledge-alert` | POST | Reconoce alerta `{"alert_id": N}` |
| `/api/upload-report` | POST | Multi-file: `.xml`, `.xml.gz`, `.zip` |
| `/api/interpret` | POST | Análisis con IA `{provider, api_key, model?, domain?, days?}` |
| `/api/dns-lookup` | POST | Consulta DNS `{type: spf\|dkim\|dmarc\|mx\|ptr, domain, selector?, ip?}` |
| `/api/dns-setup` | GET/POST | Config del dominio. Upsert por domain |
| `/api/dns-records` | GET/POST | CRUD registros DNS documentados |
| `/api/dns-records/<id>` | PUT/DELETE | Editar o eliminar registro DNS |
| `/api/source-ips-ptr` | GET | IPs únicas + PTR lookup de cada una |
| `/api/dns-analyze` | POST | Análisis DNS con IA |

### Reglas de alerta

| Tipo | Severidad | Trigger |
|---|---|---|
| `spf_failure` | high | `spf_result == 'fail'` |
| `dkim_failure` | high | `dkim_result == 'fail'` |
| `policy_action` | medium | `disposition ∈ {quarantine, reject}` |
| `high_volume_fail` | critical | `spf_result == 'fail' AND count > 10` |

### `dmarc_dashboard.html` — Frontend estático

HTML vanilla + Chart.js + SheetJS. En Docker lo sirve nginx; en local: `python -m http.server`.

**Secciones (de arriba hacia abajo):**
1. Upload zone — drag & drop multi-file
2. 🧠 Interpretación con IA (collapsible ▾)
3. 🔧 DNS Tools (collapsible ▾):
   - 📁 Registros DNS documentados (collapsible ▾) — CRUD + export CSV/Excel
   - ⚙️ Configuración del dominio (collapsible ▾)
   - 🔍 IPs origen + Reverse DNS
   - 🧠 Análisis técnico con IA
   - 🔎 Consultas DNS individuales (collapsible ▾)
4. Controls — filtro dominio, días, Actualizar, 📋 Historial
5. Summary Cards — Total Emails, SPF Pass Rate, DKIM Pass Rate, Alertas
6. Charts — doughnut SPF y DKIM
7. Alerts — con reconocimiento
8. Recent Reports

**Clases CSS:**
- `.ai-section` — panel collapsible principal con ▾
- `.expandable` — agrega ▾ via `details.expandable > summary::after`; aplicada a `#dnsToolsPanel`, `#dnsRecordsPanel`, `#dnsSetupPanel` y Consultas DNS
- `.dns-subsection` — subsección interna (bg-primary, border, border-radius 8px)
- `.dns-subsection-body` — padding 1rem + border-top

**Comportamiento:**
- Toggle `#dnsToolsPanel` → llama `loadDnsSetup()` + `loadDnsRecords()` (datos en DOM aunque subsecciones cerradas)
- Export CSV: Blob con BOM UTF-8
- Export Excel: SheetJS CDN `cdn.sheetjs.com/xlsx-0.20.3`
- Favicon: emoji SVG inline `🛡️` via `data:image/svg+xml`
- API keys IA: `localStorage` key `dmarc_ai_settings` — nunca van a BD

### Esquema de BD (7 tablas)

```
dmarc_reports          — 1 fila por XML. report_id TEXT UNIQUE.
dmarc_report_records   — 1 por <record> (por IP origen).
dmarc_dkim_results     — FK → dmarc_report_records.
dmarc_spf_results      — FK → dmarc_report_records.
dmarc_alerts           — FK → dmarc_report_records.
dns_setup              — config del dominio. UNIQUE por domain.
dns_records            — backup registros DNS: domain, record_type, host, value, ttl, notes.
```

- FKs DMARC: `ON DELETE CASCADE`
- `date_begin`/`date_end`: BIGINT (Unix timestamps)
- `dns_setup`: upsert por domain

---

## Pitfalls conocidos

- **Postgres externo**: si `/api/health` devuelve `database: disconnected`, verificar que Postgres está corriendo y accesible. En Linux Docker: `extra_hosts: ["host.docker.internal:host-gateway"]`.
- **Flask bind Docker**: `app.run(host='0.0.0.0')` necesario para que nginx alcance la API.
- **Fechas BIGINT**: comparar con `EXTRACT(EPOCH FROM NOW() - INTERVAL '%s days')::bigint`.
- **Idempotencia upload**: mismo XML → `status: "duplicate"` sin re-insertar.
- **Schema viejo**: si la BD tiene versión anterior, correr `--reset-db` (destructivo).
- **dnspython en Docker**: requiere `dnspython==2.6.1` en la imagen. Si falta: `docker-compose up -d --build api`.
- **PTR sin respuesta**: IPs de infraestructura compartida (Amazon SES, SendGrid) devuelven `dns.resolver.NoAnswer` — el código captura tanto `NXDOMAIN` como `NoAnswer` y devuelve `ptr_status: 'none'`.
- **n8n_dmarc_flow.json bugs**: (1) filtra solo `.xml` pero Google envía `.xml.gz`; (2) ruta hardcodeada incorrecta; (3) base64 no decodificado. Alternativa: POST a `/api/upload-report`.
- **Botones en `<summary>`**: no poner botones dentro de `<summary>` — el click también togglea el panel. Los botones van en el body.
- **SheetJS CDN**: si hay problemas de red, el export CSV funciona sin dependencias externas.
- **Estadísticas**: agregar sobre `dmarc_report_records`, no `dmarc_reports`.

## Convenciones

- **Documentación y comentarios**: español
- **Variables, funciones y logs**: inglés
- Queries SQL: prepared statements psycopg2 `%s`
- Sin tests automatizados
