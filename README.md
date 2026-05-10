# DMARC Intelligence Console

Sistema de monitoreo y diagnóstico de autenticación de email (SPF / DKIM / DMARC) para cualquier dominio.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## ¿Para qué sirve?

Cuando enviás emails desde tu dominio, los servidores receptores (Google, Yahoo, Microsoft) verifican tres cosas:

| Verificación | Pregunta que responde |
|---|---|
| **SPF** | ¿Este servidor tiene permiso para enviar en nombre de mi dominio? |
| **DKIM** | ¿Este email fue firmado digitalmente por el dominio que dice ser? |
| **DMARC** | ¿Qué hacer si SPF o DKIM fallan? ¿A quién reportar el resultado? |

Los ISPs envían reportes diarios en XML con el resultado de cada email enviado. Sin una herramienta que los procese, esos archivos son ilegibles.

**DMARC Intelligence Console** parsea esos XMLs, los persiste en PostgreSQL y los expone en un dashboard web con visualizaciones, herramientas DNS y análisis con IA.

---

## ¿Qué problemas resuelve?

**1. "No sé si mis emails llegan o van a spam"**  
Los reportes muestran, email por email, si pasó SPF y DKIM. Si fallan con `p=quarantine` o `p=reject`, esos emails nunca llegan.

**2. "Alguien está suplantando mi dominio (phishing)"**  
Si aparecen IPs desconocidas enviando emails "desde" tu dominio, las alertas automáticas lo detectan con severidad `critical`.

**3. "Uso varios servicios de envío y no sé cuál falla"**  
El sistema desagrega por IP origen y selector DKIM para identificar exactamente qué servicio está fallando (Google Workspace, SendGrid, Amazon SES, Resend, etc.).

**4. "Mi configuración DNS está solo en la cabeza"**  
La tabla de registros DNS documentados mantiene un backup estructurado de todos tus registros. Exportable a CSV y Excel.

**5. "No entiendo qué dice el reporte XML"**  
El módulo de análisis con IA (Claude / OpenAI / Gemini) interpreta los datos en lenguaje natural y genera recomendaciones técnicas priorizadas.

---

## Stack

| Capa | Tecnología |
|---|---|
| Backend | Python 3.9+ + Flask |
| Base de datos | PostgreSQL 13+ |
| Frontend | HTML/CSS/JS vanilla + Chart.js + SheetJS |
| DNS | dnspython 2.6+ |
| Web server | nginx (Docker) |
| Contenedores | Docker + Docker Compose |

---

## Funcionalidades

### Upload de reportes
- Zona drag & drop — acepta `.xml`, `.xml.gz` (formato habitual de Google), `.zip`
- **Carga en lote**: múltiples archivos en un solo POST (Ctrl+click o arrastrando varios)
- **Idempotente**: el mismo archivo subido dos veces devuelve `duplicate` sin duplicar datos

### 🧠 Interpretación con IA
Análisis narrativo del estado DMARC del dominio. Soporta **Claude**, **OpenAI** y **Gemini**.  
Las API keys se guardan solo en `localStorage` del browser — nunca van a la base de datos.

### 🔧 DNS Tools
Panel colapsable con cinco subsecciones:

| Subsección | Descripción |
|---|---|
| 📁 **Registros DNS documentados** | Tabla CRUD completa. Backup de tu proveedor DNS. Export CSV / Excel |
| ⚙️ **Configuración del dominio** | Guarda en BD: proveedor DNS, stack de email, selectores DKIM, notas |
| 🔍 **IPs origen + PTR** | Todas las IPs de los reportes con reverse DNS lookup |
| 🧠 **Análisis técnico con IA** | Diagnóstico basado en config de BD + DNS live + PTR + alertas activas |
| 🔎 **Consultas DNS individuales** | SPF · DKIM (por selector) · DMARC · MX · PTR manual |

### Panel de métricas
- Cards: Total Emails · SPF Pass Rate · DKIM Pass Rate · Alertas activas
- Gráficos donut: distribución SPF y DKIM pass/fail
- Tabla de alertas con reconocimiento
- Tabla de reportes recientes
- **📋 Historial**: todos los XMLs procesados con período, registros y alertas

---

## Alertas automáticas

| Tipo | Severidad | Cuándo |
|---|---|---|
| `spf_failure` | 🔴 High | SPF result = `fail` |
| `dkim_failure` | 🔴 High | DKIM result = `fail` |
| `policy_action` | 🟡 Medium | Disposición = `quarantine` o `reject` |
| `high_volume_fail` | 🚨 Critical | SPF fail **y** count > 10 emails |

---

## Instalación local

### 1. Clonar y preparar entorno

```bash
git clone https://github.com/fedecriscuolo/TestDMARCySPF.git
cd TestDMARCySPF

python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install psycopg2-binary flask flask-cors python-dotenv requests dnspython
```

### 2. Configurar variables de entorno

```bash
cp .env.example .env
# Editar .env con tus credenciales de PostgreSQL
```

```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=dmarc_monitor
DB_USER=postgres
DB_PASSWORD=tu_password

# Alertas por email (opcional — dejar vacío para deshabilitar)
ALERT_EMAIL=tu@email.com
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=tu@gmail.com
SMTP_PASS=app_password_gmail     # Google: Cuenta → Seguridad → Contraseñas de aplicación
```

### 3. Crear base de datos e inicializar tablas

```bash
createdb dmarc_monitor
python dmarc_monitor.py --init-db
```

### 4. Iniciar la API

```bash
python dmarc_api.py
# API disponible en http://localhost:5000
```

### 5. Abrir el dashboard

```bash
# En otra terminal:
python -m http.server 8080
# Abrir http://localhost:8080/dmarc_dashboard.html
```

### Comandos CLI

```bash
# Procesar un XML manualmente
python dmarc_monitor.py --file reporte.xml

# Procesar una carpeta completa (carga semanal)
python dmarc_monitor.py --folder ./dmarc_reports/

# Resumen del dominio (últimos 7 días)
python dmarc_monitor.py --summary tudominio.com --days 7

# Alertas activas
python dmarc_monitor.py --alerts tudominio.com

# Resetear la BD — DESTRUCTIVO
python dmarc_monitor.py --reset-db
```

---

## Instalación con Docker

El `docker-compose.yml` **no levanta PostgreSQL propio** — espera uno externo accesible vía `host.docker.internal:5432`.

### Con PostgreSQL local ya corriendo

```bash
# 1. Configurar variables
cp .env.example .env
# Editar .env con DB_PASSWORD

# 2. Build y levantar
docker-compose up -d --build

# 3. Inicializar tablas (solo la primera vez)
docker-compose exec api python dmarc_monitor.py --init-db

# 4. Verificar
curl http://localhost:5000/api/health
# {"status": "ok", "database": "connected"}
```

**Acceso:**
- Dashboard → http://localhost
- API → http://localhost:5000/api/health

### Con `shared-postgres` (múltiples proyectos en el mismo host)

Si usás un Postgres compartido entre varios proyectos (patrón recomendado para desarrollo):

```bash
# 0. Levantar Postgres compartido (otra carpeta, otro compose)
cd ../shared-postgres && docker-compose up -d

# 1. Volver y levantar este stack
cd ../TestDMARCySPF
docker-compose up -d --build
docker-compose exec api python dmarc_monitor.py --init-db
```

### Linux — configuración adicional

En Linux, `host.docker.internal` no existe por defecto. Agregar bajo el servicio `api` en `docker-compose.yml`:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

### Operación diaria (Docker)

```bash
# Ver logs
docker-compose logs -f api

# Reiniciar API después de editar código (bind mount activo)
docker restart dmarc_api

# Rebuild completo (cambios en Dockerfile o nuevas dependencias)
docker-compose up -d --build api

# Copiar y procesar un XML desde el host
docker cp reporte.xml dmarc_api:/app/
docker-compose exec api python dmarc_monitor.py --file /app/reporte.xml

# Detener
docker-compose down
```

---

## Pruebas

### Desde el dashboard

| Prueba | Cómo |
|---|---|
| Subir un reporte | Arrastrar XML / .gz / .zip a la zona de upload |
| Carga en lote | Ctrl+click en varios archivos o arrastrar grupo |
| Verificar idempotencia | Subir el mismo archivo dos veces → debe decir `duplicate` |
| Consulta SPF | DNS Tools → 🔎 Consultas → SPF |
| Consulta DKIM | DNS Tools → 🔎 Consultas → DKIM + selector (ej: `google`, `default`, `mail`) |
| Consulta DMARC | DNS Tools → 🔎 Consultas → DMARC |
| PTR manual | DNS Tools → 🔎 Consultas → PTR + IP |
| IPs origen + PTR | DNS Tools → 🔍 IPs origen → "Analizar IPs" |
| Análisis IA general | Sección "🧠 Interpretación con IA" → pegar API key → Analizar |
| Análisis DNS con IA | DNS Tools → 🧠 Análisis técnico → Generar análisis |
| CRUD registros DNS | DNS Tools → 📁 Registros → agregar / editar / eliminar |
| Export registros DNS | DNS Tools → 📁 Registros → "⬇ Exportar" → CSV o Excel |
| Reconocer alerta | Panel Alertas → "Reconocer" |
| Historial de cargas | Botón "📋 Historial" |

### Desde la API (curl)

```bash
# Health check
curl http://localhost:5000/api/health

# Resumen del dominio
curl "http://localhost:5000/api/summary?domain=tudominio.com&days=7"

# Alertas activas
curl "http://localhost:5000/api/alerts?domain=tudominio.com"

# Historial de XMLs procesados
curl "http://localhost:5000/api/report-history?domain=tudominio.com&limit=10"

# Tendencias diarias
curl "http://localhost:5000/api/trends?domain=tudominio.com&days=30"

# Lookup SPF
curl -X POST http://localhost:5000/api/dns-lookup \
  -H "Content-Type: application/json" \
  -d '{"type": "spf", "domain": "tudominio.com"}'

# Lookup DKIM con selector
curl -X POST http://localhost:5000/api/dns-lookup \
  -H "Content-Type: application/json" \
  -d '{"type": "dkim", "domain": "tudominio.com", "selector": "google"}'

# Lookup PTR
curl -X POST http://localhost:5000/api/dns-lookup \
  -H "Content-Type: application/json" \
  -d '{"type": "ptr", "ip": "209.85.220.41"}'

# IPs únicas + PTR de todas
curl "http://localhost:5000/api/source-ips-ptr?domain=tudominio.com"

# Subir un reporte
curl -X POST http://localhost:5000/api/upload-report \
  -F "files=@./reporte.xml"

# Subir múltiples reportes
curl -X POST http://localhost:5000/api/upload-report \
  -F "files=@./rep1.xml" \
  -F "files=@./rep2.xml.gz"

# Configuración del dominio
curl "http://localhost:5000/api/dns-setup?domain=tudominio.com"
```

---

## API — Endpoints

| Endpoint | Método | Descripción |
|---|---|---|
| `/api/health` | GET | Estado del sistema y conexión a BD |
| `/api/summary` | GET | Stats SPF/DKIM por dominio y rango de días |
| `/api/alerts` | GET | Alertas activas. Filtros: `domain`, `severity` |
| `/api/reports` | GET | Registros individuales. Params: `domain`, `limit`, `offset` |
| `/api/report-history` | GET | Historial de XMLs procesados |
| `/api/trends` | GET | Pass rate diario (sparkline) |
| `/api/acknowledge-alert` | POST | Reconocer alerta: `{"alert_id": N}` |
| `/api/upload-report` | POST | Upload multi-file (`.xml`, `.xml.gz`, `.zip`) |
| `/api/interpret` | POST | Análisis DMARC con IA |
| `/api/dns-lookup` | POST | Consulta DNS: `{type, domain, selector?, ip?}` |
| `/api/dns-setup` | GET/POST | Config del dominio (upsert por dominio) |
| `/api/dns-records` | GET/POST | CRUD de registros DNS documentados |
| `/api/dns-records/<id>` | PUT/DELETE | Editar o eliminar un registro |
| `/api/source-ips-ptr` | GET | IPs únicas de reportes + PTR lookup |
| `/api/dns-analyze` | POST | Análisis DNS técnico con IA |

---

## Variables de entorno

| Variable | Default | Descripción |
|---|---|---|
| `DB_HOST` | `localhost` | Host de PostgreSQL |
| `DB_PORT` | `5432` | Puerto de PostgreSQL |
| `DB_NAME` | `dmarc_monitor` | Nombre de la base de datos |
| `DB_USER` | `postgres` | Usuario de PostgreSQL |
| `DB_PASSWORD` | — | Password de PostgreSQL (**requerido**) |
| `ALERT_EMAIL` | vacío | Email destino para alertas automáticas |
| `SMTP_SERVER` | vacío | Servidor SMTP (ej: `smtp.gmail.com`) |
| `SMTP_PORT` | `587` | Puerto SMTP |
| `SMTP_USER` | vacío | Usuario SMTP |
| `SMTP_PASS` | vacío | Password SMTP |

---

## Esquema de base de datos

```
dmarc_reports          — 1 fila por XML procesado. Metadata + política DMARC.
dmarc_report_records   — 1 fila por <record> del XML (una por IP origen).
dmarc_dkim_results     — Detalle DKIM por record.
dmarc_spf_results      — Detalle SPF por record.
dmarc_alerts           — Alertas generadas automáticamente.
dns_setup              — Config del dominio: proveedor, stack, selectores, notas. UNIQUE por domain.
dns_records            — Backup de registros DNS: type, host, value, ttl, notes.
```

---

## Notas

- **Frecuencia de carga**: los reportes llegan 1 vez por día desde cada ISP en tu `rua=`. Podés acumular la semana y subir todos juntos — el sistema es idempotente.
- **PTR de servicios cloud (Amazon SES, SendGrid)**: muchas IPs de infraestructura compartida no tienen registros PTR. Es comportamiento esperado, no un error de configuración.
- **API keys de IA**: se guardan solo en `localStorage` del browser. Para borrarlas: `localStorage.removeItem('dmarc_ai_settings')` en la consola.
- **Sin pooling de conexiones**: cada request HTTP abre y cierra conexión a Postgres. Suficiente para el volumen de DMARC (máximo algunos cientos de registros por día).

---

## Licencia

MIT — libre para usar, modificar y distribuir.
