#!/usr/bin/env python3
"""
DMARC Dashboard API
===================
Servidor Flask que sirve datos al dashboard HTML y acepta uploads de
reportes DMARC (XML / .gz / .zip).

Uso:
  python dmarc_api.py
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import logging
import gzip
import zipfile
import tempfile
import shutil
import json
import requests
from pathlib import Path
from werkzeug.utils import secure_filename

from dmarc_monitor import DMARCDatabase, parse_dmarc_xml, send_alert_email

# ========== CONFIG ==========
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME', 'dmarc_monitor')
DB_USER = os.getenv('DB_USER', 'postgres')
DB_PASSWORD = os.getenv('DB_PASSWORD', '')

UPLOAD_MAX_BYTES = 20 * 1024 * 1024  # 20 MB por archivo
ALLOWED_EXT = {'.xml', '.gz', '.zip'}

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = UPLOAD_MAX_BYTES
CORS(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ========== DB CONNECTION ==========
def get_db_connection():
    try:
        return psycopg2.connect(
            host=DB_HOST, port=DB_PORT, database=DB_NAME,
            user=DB_USER, password=DB_PASSWORD,
        )
    except psycopg2.Error as e:
        logger.error(f"DB Connection Error: {e}")
        return None


# ========== READ ENDPOINTS ==========

@app.route('/api/summary', methods=['GET'])
def get_summary():
    domain = request.args.get('domain', 'yourdomain.com')
    days = request.args.get('days', 7, type=int)

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        sql = """
        SELECT
            r.domain,
            COUNT(DISTINCT r.id) AS total_reports,
            COUNT(rr.id) AS total_records,
            COALESCE(SUM(rr.count), 0) AS total_emails,
            COALESCE(SUM(CASE WHEN rr.spf_result = 'pass' THEN rr.count ELSE 0 END), 0) AS spf_pass,
            COALESCE(SUM(CASE WHEN rr.spf_result = 'fail' THEN rr.count ELSE 0 END), 0) AS spf_fail,
            COALESCE(SUM(CASE WHEN rr.spf_result = 'neutral' THEN rr.count ELSE 0 END), 0) AS spf_neutral,
            COALESCE(SUM(CASE WHEN rr.dkim_result = 'pass' THEN rr.count ELSE 0 END), 0) AS dkim_pass,
            COALESCE(SUM(CASE WHEN rr.dkim_result = 'fail' THEN rr.count ELSE 0 END), 0) AS dkim_fail,
            COALESCE(SUM(CASE WHEN rr.dkim_result = 'neutral' THEN rr.count ELSE 0 END), 0) AS dkim_neutral,
            MIN(r.date_begin) AS date_from,
            MAX(r.date_end) AS date_to
        FROM dmarc_reports r
        LEFT JOIN dmarc_report_records rr ON rr.report_id = r.id
        WHERE r.domain = %s
            AND r.date_begin > EXTRACT(EPOCH FROM NOW() - INTERVAL '%s days')::bigint
        GROUP BY r.domain;
        """
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, (domain, days))
            result = cur.fetchone()

        if not result:
            return jsonify({'error': f'No reports for {domain}'}), 404

        total = result['total_emails'] or 1
        pct = lambda n: round((n or 0) / total * 100, 2)
        return jsonify({
            'domain': result['domain'],
            'total_reports': result['total_reports'],
            'total_records': result['total_records'],
            'total_emails': result['total_emails'],
            'days': days,
            'date_from': result['date_from'],
            'date_to': result['date_to'],
            'spf': {
                'pass': result['spf_pass'] or 0,
                'fail': result['spf_fail'] or 0,
                'neutral': result['spf_neutral'] or 0,
                'pass_pct': pct(result['spf_pass']),
                'fail_pct': pct(result['spf_fail']),
                'neutral_pct': pct(result['spf_neutral']),
            },
            'dkim': {
                'pass': result['dkim_pass'] or 0,
                'fail': result['dkim_fail'] or 0,
                'neutral': result['dkim_neutral'] or 0,
                'pass_pct': pct(result['dkim_pass']),
                'fail_pct': pct(result['dkim_fail']),
                'neutral_pct': pct(result['dkim_neutral']),
            },
        })
    finally:
        conn.close()


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    domain = request.args.get('domain')
    severity = request.args.get('severity')

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        sql = """
        SELECT
            da.id, da.alert_type, da.severity, da.message,
            da.created_at, da.acknowledged,
            r.domain, r.date_begin AS report_date_begin, r.date_end AS report_date_end,
            rr.source_ip
        FROM dmarc_alerts da
        JOIN dmarc_report_records rr ON da.record_id = rr.id
        JOIN dmarc_reports r ON rr.report_id = r.id
        WHERE da.acknowledged = FALSE
        """
        params = []
        if domain:
            sql += " AND r.domain = %s"
            params.append(domain)
        if severity:
            sql += " AND da.severity = %s"
            params.append(severity)
        sql += " ORDER BY da.severity DESC, da.created_at DESC LIMIT 100;"

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            alerts = cur.fetchall()
        return app.response_class(
            response=_json_dumps([dict(a) for a in alerts]),
            mimetype='application/json',
        )
    finally:
        conn.close()


@app.route('/api/reports', methods=['GET'])
def get_reports():
    """Lista de records (1 fila por <record>) joinado con su reporte parent."""
    domain = request.args.get('domain')
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        sql = """
        SELECT
            rr.id, r.report_id, r.domain, r.date_begin, r.date_end,
            rr.source_ip, rr.count, rr.disposition,
            rr.dkim_result, rr.spf_result, rr.header_from,
            rr.created_at
        FROM dmarc_report_records rr
        JOIN dmarc_reports r ON rr.report_id = r.id
        """
        params = []
        if domain:
            sql += " WHERE r.domain = %s"
            params.append(domain)
        sql += " ORDER BY r.date_begin DESC, rr.id DESC LIMIT %s OFFSET %s;"
        params.extend([limit, offset])

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return app.response_class(
            response=_json_dumps([dict(r) for r in rows]),
            mimetype='application/json',
        )
    finally:
        conn.close()


@app.route('/api/report-history', methods=['GET'])
def get_report_history():
    domain = request.args.get('domain', 'yourdomain.com')
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    r.id,
                    r.domain,
                    r.date_begin,
                    r.date_end,
                    r.created_at,
                    COUNT(DISTINCT rr.id) AS records_count,
                    COUNT(DISTINCT da.id) AS alerts_count
                FROM dmarc_reports r
                LEFT JOIN dmarc_report_records rr ON rr.report_id = r.id
                LEFT JOIN dmarc_alerts da ON da.record_id = rr.id
                WHERE r.domain = %s
                GROUP BY r.id
                ORDER BY r.created_at DESC
                LIMIT %s OFFSET %s
            """, (domain, limit, offset))
            rows = cur.fetchall()

        history = []
        for row in rows:
            history.append({
                'id': row[0],
                'domain': row[1],
                'date_begin': row[2],
                'date_end': row[3],
                'created_at': row[4].isoformat() if row[4] else None,
                'records_count': row[5],
                'alerts_count': row[6],
            })
        return jsonify(history)
    finally:
        conn.close()


@app.route('/api/trends', methods=['GET'])
def get_trends():
    domain = request.args.get('domain', 'yourdomain.com')
    days = request.args.get('days', 30, type=int)

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        sql = """
        SELECT
            to_timestamp(r.date_begin)::date AS date,
            COUNT(DISTINCT r.id) AS reports,
            SUM(rr.count) AS total_emails,
            SUM(CASE WHEN rr.spf_result = 'pass' THEN rr.count ELSE 0 END)::float /
            NULLIF(SUM(rr.count), 0) * 100 AS spf_pass_pct,
            SUM(CASE WHEN rr.dkim_result = 'pass' THEN rr.count ELSE 0 END)::float /
            NULLIF(SUM(rr.count), 0) * 100 AS dkim_pass_pct
        FROM dmarc_reports r
        JOIN dmarc_report_records rr ON rr.report_id = r.id
        WHERE r.domain = %s
            AND r.date_begin > EXTRACT(EPOCH FROM NOW() - INTERVAL '%s days')::bigint
        GROUP BY to_timestamp(r.date_begin)::date
        ORDER BY date DESC;
        """
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, (domain, days))
            results = cur.fetchall()
        return app.response_class(
            response=_json_dumps([dict(r) for r in results]),
            mimetype='application/json',
        )
    finally:
        conn.close()


@app.route('/api/health', methods=['GET'])
def health_check():
    conn = get_db_connection()
    if conn:
        conn.close()
        return jsonify({'status': 'ok', 'database': 'connected'})
    return jsonify({'status': 'error', 'database': 'disconnected'}), 500


@app.route('/api/acknowledge-alert', methods=['POST'])
def acknowledge_alert():
    data = request.get_json() or {}
    alert_id = data.get('alert_id')
    if not alert_id:
        return jsonify({'error': 'alert_id required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE dmarc_alerts SET acknowledged = TRUE WHERE id = %s;",
                (alert_id,),
            )
        conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()


# ========== UPLOAD ENDPOINT ==========

def _extract_xml_files(uploaded_path: Path, work_dir: Path) -> list[Path]:
    """
    A partir de un archivo subido (.xml | .xml.gz | .zip), devuelve la lista
    de archivos .xml planos extraídos en work_dir. No modifica el original.
    """
    name = uploaded_path.name.lower()
    extracted: list[Path] = []

    if name.endswith('.xml'):
        extracted.append(uploaded_path)
        return extracted

    if name.endswith('.gz'):
        # Asume xml.gz (formato Google "...xml.gz")
        target = work_dir / (uploaded_path.stem if uploaded_path.stem.endswith('.xml')
                             else uploaded_path.stem + '.xml')
        with gzip.open(uploaded_path, 'rb') as fin, open(target, 'wb') as fout:
            shutil.copyfileobj(fin, fout)
        extracted.append(target)
        return extracted

    if name.endswith('.zip'):
        with zipfile.ZipFile(uploaded_path) as zf:
            for member in zf.namelist():
                low = member.lower()
                # Solo extraer xml o xml.gz dentro del zip
                if not (low.endswith('.xml') or low.endswith('.xml.gz')):
                    continue
                # path traversal guard
                safe_name = secure_filename(Path(member).name) or 'extracted.xml'
                out_path = work_dir / safe_name
                with zf.open(member) as src, open(out_path, 'wb') as dst:
                    shutil.copyfileobj(src, dst)
                # Si era xml.gz dentro del zip, descomprimir
                if low.endswith('.xml.gz'):
                    xml_path = out_path.with_suffix('')  # quita .gz
                    if not str(xml_path).endswith('.xml'):
                        xml_path = xml_path.with_suffix('.xml')
                    with gzip.open(out_path, 'rb') as fin, open(xml_path, 'wb') as fout:
                        shutil.copyfileobj(fin, fout)
                    out_path.unlink(missing_ok=True)
                    extracted.append(xml_path)
                else:
                    extracted.append(out_path)
        return extracted

    raise ValueError(f"Extensión no soportada: {uploaded_path.suffix}")


@app.route('/api/upload-report', methods=['POST'])
def upload_report():
    """
    Recibe uno o más reportes DMARC y los procesa.

    Form-data:
      files: lista de archivos .xml / .xml.gz / .zip

    Returns:
      { results: [
          { filename, status: 'inserted' | 'duplicate' | 'error',
            report_id, records_inserted, alerts_generated, error? }
        ],
        summary: { processed, inserted, duplicates, errors } }
    """
    files = request.files.getlist('files')
    if not files:
        return jsonify({'error': 'No files in request (campo "files")'}), 400

    db = DMARCDatabase()
    results = []
    counters = {'processed': 0, 'inserted': 0, 'duplicates': 0, 'errors': 0}

    try:
        with tempfile.TemporaryDirectory(prefix='dmarc_upload_') as tmpdir:
            tmp = Path(tmpdir)

            for fs in files:
                original_name = fs.filename or 'unnamed'
                safe = secure_filename(original_name) or 'unnamed'
                ext = ''.join(Path(safe).suffixes).lower()  # .xml | .gz | .zip | .xml.gz

                # Acepta cualquier sufijo terminal en ALLOWED_EXT
                if not (safe.lower().endswith('.xml') or
                        safe.lower().endswith('.gz') or
                        safe.lower().endswith('.zip')):
                    counters['processed'] += 1
                    counters['errors'] += 1
                    results.append({
                        'filename': original_name, 'status': 'error',
                        'error': f'Extensión no soportada: {ext or "(none)"}',
                    })
                    continue

                # Guardar el upload a disco temporal
                saved = tmp / safe
                fs.save(str(saved))

                # Extraer XMLs dentro de un sub-tmpdir por archivo
                inner_dir = tmp / f"_x_{saved.stem}"
                inner_dir.mkdir(exist_ok=True)

                try:
                    xml_paths = _extract_xml_files(saved, inner_dir)
                except Exception as e:
                    counters['processed'] += 1
                    counters['errors'] += 1
                    results.append({
                        'filename': original_name, 'status': 'error',
                        'error': f'No se pudo extraer: {e}',
                    })
                    continue

                if not xml_paths:
                    counters['processed'] += 1
                    counters['errors'] += 1
                    results.append({
                        'filename': original_name, 'status': 'error',
                        'error': 'Sin XMLs adentro',
                    })
                    continue

                # Procesar cada XML extraído como un resultado por XML lógico.
                # Si el upload era un .zip con varios XML, cada uno se reporta.
                for xml_path in xml_paths:
                    counters['processed'] += 1
                    label = (
                        original_name
                        if xml_path.name == saved.name
                        else f"{original_name} → {xml_path.name}"
                    )
                    try:
                        feedback = parse_dmarc_xml(str(xml_path))
                        db_id, was_new, recs, alerts = db.insert_feedback(feedback)
                        if was_new:
                            counters['inserted'] += 1
                            send_alert_email(alerts, feedback.domain)
                            results.append({
                                'filename': label,
                                'status': 'inserted',
                                'report_id': db_id,
                                'records_inserted': recs,
                                'alerts_generated': alerts,
                                'domain': feedback.domain,
                            })
                        else:
                            counters['duplicates'] += 1
                            results.append({
                                'filename': label,
                                'status': 'duplicate',
                                'report_id': db_id,
                                'domain': feedback.domain,
                            })
                    except Exception as e:
                        counters['errors'] += 1
                        results.append({
                            'filename': label, 'status': 'error',
                            'error': str(e),
                        })
        return jsonify({'results': results, 'summary': counters})
    finally:
        db.close()


# ========== AI INTERPRETATION ==========

AI_DEFAULT_MODELS = {
    'claude': 'claude-sonnet-4-6',
    'openai': 'gpt-4o',
    'gemini': 'gemini-2.0-flash',
}
AI_TIMEOUT_SEC = 60


def _build_interpretation_context(conn, domain: str, days: int) -> dict:
    """Arma el dict de contexto que se le pasa a la IA."""
    ctx = {'domain': domain, 'days': days}

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Resumen agregado
        cur.execute("""
            SELECT
                COUNT(DISTINCT r.id) AS total_reports,
                COUNT(rr.id) AS total_records,
                COALESCE(SUM(rr.count), 0) AS total_emails,
                COALESCE(SUM(CASE WHEN rr.spf_result = 'pass' THEN rr.count ELSE 0 END), 0) AS spf_pass,
                COALESCE(SUM(CASE WHEN rr.spf_result = 'fail' THEN rr.count ELSE 0 END), 0) AS spf_fail,
                COALESCE(SUM(CASE WHEN rr.dkim_result = 'pass' THEN rr.count ELSE 0 END), 0) AS dkim_pass,
                COALESCE(SUM(CASE WHEN rr.dkim_result = 'fail' THEN rr.count ELSE 0 END), 0) AS dkim_fail
            FROM dmarc_reports r
            LEFT JOIN dmarc_report_records rr ON rr.report_id = r.id
            WHERE r.domain = %s
              AND r.date_begin > EXTRACT(EPOCH FROM NOW() - INTERVAL '%s days')::bigint;
        """, (domain, days))
        ctx['summary'] = dict(cur.fetchone() or {})

        # Top IPs por volumen, agrupando spf/dkim/disposition
        cur.execute("""
            SELECT
                rr.source_ip::text AS source_ip,
                SUM(rr.count) AS emails,
                BOOL_OR(rr.spf_result = 'fail') AS any_spf_fail,
                BOOL_OR(rr.dkim_result = 'fail') AS any_dkim_fail,
                ARRAY_AGG(DISTINCT rr.disposition) AS dispositions,
                ARRAY_AGG(DISTINCT rr.header_from) FILTER (WHERE rr.header_from IS NOT NULL) AS header_froms
            FROM dmarc_report_records rr
            JOIN dmarc_reports r ON rr.report_id = r.id
            WHERE r.domain = %s
              AND r.date_begin > EXTRACT(EPOCH FROM NOW() - INTERVAL '%s days')::bigint
            GROUP BY rr.source_ip
            ORDER BY emails DESC
            LIMIT 20;
        """, (domain, days))
        ctx['top_source_ips'] = [dict(r) for r in cur.fetchall()]

        # Política DMARC publicada (del reporte más reciente)
        cur.execute("""
            SELECT policy_p, policy_sp, policy_pct, policy_adkim, policy_aspf
            FROM dmarc_reports
            WHERE domain = %s
            ORDER BY date_begin DESC
            LIMIT 1;
        """, (domain,))
        row = cur.fetchone()
        ctx['policy'] = dict(row) if row else {}

        # Alertas activas agrupadas por tipo+severidad
        cur.execute("""
            SELECT da.alert_type, da.severity, COUNT(*) AS n
            FROM dmarc_alerts da
            JOIN dmarc_report_records rr ON da.record_id = rr.id
            JOIN dmarc_reports r ON rr.report_id = r.id
            WHERE da.acknowledged = FALSE AND r.domain = %s
            GROUP BY da.alert_type, da.severity
            ORDER BY da.severity DESC;
        """, (domain,))
        ctx['open_alerts'] = [dict(r) for r in cur.fetchall()]

    return ctx


def _build_prompt(ctx: dict) -> str:
    """Estructura el prompt para la IA en español."""
    return f"""Sos un experto en autenticación de email (SPF, DKIM, DMARC, RFC 7489). Te paso un resumen agregado de los reportes DMARC del dominio **{ctx['domain']}** durante los últimos **{ctx['days']} días**. Analizá los datos y respondé en español, formato markdown, con esta estructura:

## Resumen ejecutivo
1-2 párrafos sobre qué tan saludable está la autenticación del dominio.

## Hallazgos clave
Lista de problemas detectados, agrupando IPs cuando sean del mismo proveedor. Si reconocés un proveedor por su PTR/rango (ej. SES, SendGrid, Mailchimp, Resend, Google Workspace), identificalo.

## Acciones recomendadas
Pasos concretos y priorizados (high/medium/low). Si hay que cambiar SPF, dame el record exacto sugerido.

## Riesgos no obvios
Cosas que un ojo no entrenado pasaría por alto.

---

**Datos:**

```json
{json.dumps(ctx, default=str, indent=2)}
```

Sé directo, concreto y accionable. No hagas preámbulos."""


def _call_claude(api_key: str, model: str, prompt: str) -> dict:
    res = requests.post(
        'https://api.anthropic.com/v1/messages',
        headers={
            'x-api-key': api_key,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json',
        },
        json={
            'model': model,
            'max_tokens': 2048,
            'messages': [{'role': 'user', 'content': prompt}],
        },
        timeout=AI_TIMEOUT_SEC,
    )
    if res.status_code != 200:
        raise RuntimeError(f"Claude {res.status_code}: {res.text[:500]}")
    data = res.json()
    text = ''.join(b.get('text', '') for b in data.get('content', [])
                   if b.get('type') == 'text')
    usage = data.get('usage', {})
    tokens = (usage.get('input_tokens', 0) or 0) + (usage.get('output_tokens', 0) or 0)
    return {'response': text, 'tokens_used': tokens}


def _call_openai(api_key: str, model: str, prompt: str) -> dict:
    res = requests.post(
        'https://api.openai.com/v1/chat/completions',
        headers={
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        },
        json={
            'model': model,
            'messages': [{'role': 'user', 'content': prompt}],
        },
        timeout=AI_TIMEOUT_SEC,
    )
    if res.status_code != 200:
        raise RuntimeError(f"OpenAI {res.status_code}: {res.text[:500]}")
    data = res.json()
    text = data['choices'][0]['message']['content']
    tokens = data.get('usage', {}).get('total_tokens', 0)
    return {'response': text, 'tokens_used': tokens}


def _call_gemini(api_key: str, model: str, prompt: str) -> dict:
    url = f'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent'
    res = requests.post(
        url,
        params={'key': api_key},
        headers={'Content-Type': 'application/json'},
        json={'contents': [{'parts': [{'text': prompt}]}]},
        timeout=AI_TIMEOUT_SEC,
    )
    if res.status_code != 200:
        raise RuntimeError(f"Gemini {res.status_code}: {res.text[:500]}")
    data = res.json()
    parts = data.get('candidates', [{}])[0].get('content', {}).get('parts', [])
    text = ''.join(p.get('text', '') for p in parts)
    tokens = data.get('usageMetadata', {}).get('totalTokenCount', 0)
    return {'response': text, 'tokens_used': tokens}


@app.route('/api/models', methods=['POST'])
def get_ai_models():
    """
    Body: { provider, api_key }
    Devuelve la lista de modelos disponibles consultando la API del provider.
    La api_key NO se persiste.
    """
    data = request.get_json(silent=True) or {}
    provider = (data.get('provider') or '').lower()
    api_key = (data.get('api_key') or '').strip()

    if not provider or not api_key:
        return jsonify({'error': 'provider y api_key requeridos'}), 400

    try:
        if provider == 'claude':
            resp = requests.get(
                'https://api.anthropic.com/v1/models',
                headers={'x-api-key': api_key, 'anthropic-version': '2023-06-01'},
                timeout=10
            )
            if not resp.ok:
                return jsonify({'error': f'Anthropic {resp.status_code}: {resp.text}'}), 502
            models = [
                {'id': m['id'], 'label': m['id']}
                for m in resp.json().get('data', [])
                if m['id'].startswith('claude-')
            ]

        elif provider == 'openai':
            resp = requests.get(
                'https://api.openai.com/v1/models',
                headers={'Authorization': f'Bearer {api_key}'},
                timeout=10
            )
            if not resp.ok:
                return jsonify({'error': f'OpenAI {resp.status_code}: {resp.text}'}), 502
            models = sorted(
                [
                    {'id': m['id'], 'label': m['id']}
                    for m in resp.json().get('data', [])
                    if m['id'].startswith('gpt-')
                ],
                key=lambda m: m['id']
            )

        elif provider == 'gemini':
            resp = requests.get(
                f'https://generativelanguage.googleapis.com/v1beta/models?key={api_key}',
                timeout=10
            )
            if not resp.ok:
                return jsonify({'error': f'Gemini {resp.status_code}: {resp.text}'}), 502
            models = [
                {
                    'id': m['name'].replace('models/', ''),
                    'label': m.get('displayName', m['name'].replace('models/', ''))
                }
                for m in resp.json().get('models', [])
                if 'generateContent' in m.get('supportedGenerationMethods', [])
            ]

        else:
            return jsonify({'error': f'Provider desconocido: {provider}'}), 400

    except requests.Timeout:
        return jsonify({'error': f'Timeout consultando modelos de {provider}'}), 504
    except requests.ConnectionError as e:
        return jsonify({'error': f'Error de conexión con {provider}: {e}'}), 502

    return jsonify({'models': models})


@app.route('/api/interpret', methods=['POST'])
def interpret():
    """
    Body: { provider, api_key, model?, domain?, days? }
    La api_key NO se persiste — solo se usa para la llamada outbound.
    """
    data = request.get_json(silent=True) or {}
    provider = (data.get('provider') or '').lower()
    api_key = data.get('api_key') or ''
    model = data.get('model') or AI_DEFAULT_MODELS.get(provider)
    domain = data.get('domain') or 'yourdomain.com'
    days = int(data.get('days') or 30)

    if provider not in AI_DEFAULT_MODELS:
        return jsonify({'error': f'Provider inválido: {provider}'}), 400
    if not api_key:
        return jsonify({'error': 'api_key requerido'}), 400
    if not model:
        return jsonify({'error': 'model requerido'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        ctx = _build_interpretation_context(conn, domain, days)
    finally:
        conn.close()

    if not ctx.get('summary') or ctx['summary'].get('total_records', 0) == 0:
        return jsonify({
            'error': f'Sin data para {domain} en los últimos {days} días. Subí reportes primero.'
        }), 404

    prompt = _build_prompt(ctx)
    dispatcher = {
        'claude': _call_claude,
        'openai': _call_openai,
        'gemini': _call_gemini,
    }[provider]

    try:
        out = dispatcher(api_key, model, prompt)
    except requests.Timeout:
        return jsonify({'error': f'Timeout llamando a {provider}'}), 504
    except requests.ConnectionError as e:
        return jsonify({'error': f'No se pudo conectar a {provider}: {e}'}), 502
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 502
    except Exception as e:
        logger.exception('Error en /api/interpret')
        return jsonify({'error': f'Error inesperado: {e}'}), 500

    return jsonify({
        'provider': provider,
        'model': model,
        'response': out['response'],
        'tokens_used': out.get('tokens_used', 0),
    })


# ========== HELPERS ==========

def _json_dumps(obj):
    """JSON dump que serializa datetimes como ISO string."""
    import json
    from datetime import datetime, date
    def default(o):
        if isinstance(o, (datetime, date)):
            return o.isoformat()
        return str(o)
    return json.dumps(obj, default=default)


# ========== ERROR HANDLERS ==========

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(413)
def too_large(error):
    return jsonify({
        'error': f'Archivo demasiado grande (límite {UPLOAD_MAX_BYTES // (1024*1024)} MB)'
    }), 413


@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Internal server error'}), 500


# ========== DNS RECORDS (backup/documentacion) ==========

def _row_to_record(row):
    return {'id': row[0], 'domain': row[1], 'record_type': row[2], 'host': row[3],
            'value': row[4], 'ttl': row[5], 'notes': row[6],
            'created_at': row[7].isoformat() if row[7] else None,
            'updated_at': row[8].isoformat() if row[8] else None}

@app.route('/api/dns-records', methods=['GET'])
def get_dns_records():
    domain = request.args.get('domain', 'yourdomain.com')
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, domain, record_type, host, value, ttl, notes, created_at, updated_at
                FROM dns_records WHERE domain = %s
                ORDER BY record_type, host
            """, (domain,))
            return jsonify([_row_to_record(r) for r in cur.fetchall()])
    finally:
        conn.close()

@app.route('/api/dns-records', methods=['POST'])
def create_dns_record():
    data = request.get_json() or {}
    required = ['domain', 'record_type', 'host', 'value']
    if not all(data.get(f) for f in required):
        return jsonify({'error': f'Campos requeridos: {required}'}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO dns_records (domain, record_type, host, value, ttl, notes)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id, domain, record_type, host, value, ttl, notes, created_at, updated_at
            """, (data['domain'], data['record_type'].upper(), data['host'],
                  data['value'], data.get('ttl', 'Automatic'), data.get('notes', '')))
            row = cur.fetchone()
        conn.commit()
        return jsonify(_row_to_record(row)), 201
    finally:
        conn.close()

@app.route('/api/dns-records/<int:record_id>', methods=['PUT'])
def update_dns_record(record_id):
    data = request.get_json() or {}
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE dns_records SET
                    record_type = COALESCE(%s, record_type),
                    host        = COALESCE(%s, host),
                    value       = COALESCE(%s, value),
                    ttl         = COALESCE(%s, ttl),
                    notes       = COALESCE(%s, notes),
                    updated_at  = NOW()
                WHERE id = %s
                RETURNING id, domain, record_type, host, value, ttl, notes, created_at, updated_at
            """, (data.get('record_type', '').upper() or None, data.get('host') or None,
                  data.get('value') or None, data.get('ttl') or None,
                  data.get('notes'), record_id))
            row = cur.fetchone()
        conn.commit()
        if not row:
            return jsonify({'error': 'Registro no encontrado'}), 404
        return jsonify(_row_to_record(row))
    finally:
        conn.close()

@app.route('/api/dns-records/<int:record_id>', methods=['DELETE'])
def delete_dns_record(record_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM dns_records WHERE id = %s RETURNING id", (record_id,))
            deleted = cur.fetchone()
        conn.commit()
        if not deleted:
            return jsonify({'error': 'Registro no encontrado'}), 404
        return jsonify({'deleted': record_id})
    finally:
        conn.close()


# ========== DNS SETUP ==========

@app.route('/api/dns-setup', methods=['GET'])
def get_dns_setup():
    domain = request.args.get('domain', 'yourdomain.com')
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT domain, dns_provider, email_stack, spf_record, dmarc_record, dkim_selectors, extra_notes, updated_at FROM dns_setup WHERE domain = %s", (domain,))
            row = cur.fetchone()
        if not row:
            return jsonify({})
        return jsonify({
            'domain': row[0], 'dns_provider': row[1], 'email_stack': row[2],
            'spf_record': row[3], 'dmarc_record': row[4],
            'dkim_selectors': row[5] or [],
            'extra_notes': row[6],
            'updated_at': row[7].isoformat() if row[7] else None,
        })
    finally:
        conn.close()


@app.route('/api/dns-setup', methods=['POST'])
def save_dns_setup():
    data = request.get_json() or {}
    domain = (data.get('domain') or '').strip()
    if not domain:
        return jsonify({'error': 'domain requerido'}), 400

    selectors_raw = data.get('dkim_selectors', [])
    if isinstance(selectors_raw, str):
        selectors_raw = [s.strip() for s in selectors_raw.split(',') if s.strip()]

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO dns_setup (domain, dns_provider, email_stack, spf_record, dmarc_record, dkim_selectors, extra_notes, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (domain) DO UPDATE SET
                    dns_provider   = EXCLUDED.dns_provider,
                    email_stack    = EXCLUDED.email_stack,
                    spf_record     = EXCLUDED.spf_record,
                    dmarc_record   = EXCLUDED.dmarc_record,
                    dkim_selectors = EXCLUDED.dkim_selectors,
                    extra_notes    = EXCLUDED.extra_notes,
                    updated_at     = NOW()
                RETURNING domain, dns_provider, email_stack, spf_record, dmarc_record, dkim_selectors, extra_notes, updated_at
            """, (domain, data.get('dns_provider'), data.get('email_stack'),
                  data.get('spf_record'), data.get('dmarc_record'),
                  selectors_raw, data.get('extra_notes')))
            row = cur.fetchone()
        conn.commit()
        return jsonify({
            'domain': row[0], 'dns_provider': row[1], 'email_stack': row[2],
            'spf_record': row[3], 'dmarc_record': row[4],
            'dkim_selectors': row[5] or [], 'extra_notes': row[6],
            'updated_at': row[7].isoformat() if row[7] else None,
        })
    finally:
        conn.close()


@app.route('/api/source-ips-ptr', methods=['GET'])
def source_ips_ptr():
    domain = request.args.get('domain', 'yourdomain.com')
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT rr.source_ip, SUM(rr.count) AS email_count
                FROM dmarc_report_records rr
                JOIN dmarc_reports r ON r.id = rr.report_id
                WHERE r.domain = %s
                GROUP BY rr.source_ip
                ORDER BY email_count DESC
            """, (domain,))
            rows = cur.fetchall()
    finally:
        conn.close()

    results = []
    for source_ip, email_count in rows:
        ptr = None
        status = 'none'
        if DNS_AVAILABLE:
            try:
                rev = dns.reversename.from_address(source_ip)
                answers = dns.resolver.resolve(str(rev), 'PTR', lifetime=3)
                ptr = answers[0].to_text().rstrip('.')
                status = 'ok'
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                status = 'none'
            except Exception:
                status = 'error'
        results.append({'ip': source_ip, 'email_count': int(email_count), 'ptr': ptr, 'ptr_status': status})

    return jsonify(results)


@app.route('/api/dns-analyze', methods=['POST'])
def dns_analyze():
    data = request.get_json() or {}
    domain = (data.get('domain') or 'yourdomain.com').strip()
    provider = data.get('provider', 'gemini')
    api_key = data.get('api_key', '')
    model = data.get('model')

    if not api_key:
        return jsonify({'error': 'api_key requerida'}), 400

    # 1. Cargar setup de la BD
    conn = get_db_connection()
    setup = {}
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT dns_provider, email_stack, spf_record, dmarc_record, dkim_selectors, extra_notes FROM dns_setup WHERE domain = %s", (domain,))
                row = cur.fetchone()
            if row:
                setup = {'dns_provider': row[0], 'email_stack': row[1], 'spf_record': row[2],
                         'dmarc_record': row[3], 'dkim_selectors': row[4] or [], 'extra_notes': row[5]}
        finally:
            conn.close()

    # 2. Resolver DNS live
    live_dns = {}
    if DNS_AVAILABLE:
        def safe_txt(qname):
            try:
                r = dns.resolver.Resolver(); r.lifetime = 5
                return [a.to_text().strip('"') for a in r.resolve(qname, 'TXT')]
            except Exception as e:
                return [f'ERROR: {e}']

        live_dns['spf'] = safe_txt(domain)
        live_dns['dmarc'] = safe_txt(f'_dmarc.{domain}')
        live_dns['dkim'] = {}
        for sel in (setup.get('dkim_selectors') or []):
            live_dns['dkim'][sel] = safe_txt(f'{sel}._domainkey.{domain}')

    # 3. IPs origen recientes + PTR
    conn2 = get_db_connection()
    ip_ptr_summary = []
    if conn2:
        try:
            with conn2.cursor() as cur:
                cur.execute("""
                    SELECT rr.source_ip, SUM(rr.count) AS cnt,
                           rr.spf_result, rr.dkim_result
                    FROM dmarc_report_records rr
                    JOIN dmarc_reports r ON r.id = rr.report_id
                    WHERE r.domain = %s
                    GROUP BY rr.source_ip, rr.spf_result, rr.dkim_result
                    ORDER BY cnt DESC LIMIT 10
                """, (domain,))
                for ip, cnt, spf_r, dkim_r in cur.fetchall():
                    ptr = '?'
                    if DNS_AVAILABLE:
                        try:
                            rev = dns.reversename.from_address(ip)
                            ptr = dns.resolver.resolve(str(rev), 'PTR', lifetime=3)[0].to_text().rstrip('.')
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                            ptr = 'sin PTR'
                        except Exception:
                            ptr = 'error DNS'
                    ip_ptr_summary.append(f'  {ip} ({int(cnt)} emails) SPF:{spf_r} DKIM:{dkim_r} → PTR:{ptr}')
        finally:
            conn2.close()

    # 4. Alertas activas
    conn3 = get_db_connection()
    alerts_summary = []
    if conn3:
        try:
            with conn3.cursor() as cur:
                cur.execute("""
                    SELECT a.alert_type, a.severity, a.message
                    FROM dmarc_alerts a
                    JOIN dmarc_report_records rr ON rr.id = a.record_id
                    JOIN dmarc_reports r ON r.id = rr.report_id
                    WHERE r.domain = %s AND a.acknowledged = FALSE
                    ORDER BY a.created_at DESC LIMIT 10
                """, (domain,))
                for atype, sev, msg in cur.fetchall():
                    alerts_summary.append(f'  [{sev.upper()}] {atype}: {msg}')
        finally:
            conn3.close()

    # 5. Construir prompt
    setup_block = f"""
CONFIGURACIÓN REGISTRADA:
- Proveedor DNS: {setup.get('dns_provider', 'no especificado')}
- Stack de email: {setup.get('email_stack', 'no especificado')}
- Selectores DKIM conocidos: {', '.join(setup.get('dkim_selectors') or []) or 'ninguno'}
- Notas adicionales: {setup.get('extra_notes') or 'ninguna'}
""" if setup else "CONFIGURACIÓN: no registrada aún (usar el formulario Setup en DNS Tools).\n"

    dns_block = f"""
REGISTROS DNS ACTUALES (consultados en tiempo real):
- SPF ({domain}): {'; '.join(live_dns.get('spf', ['no consultado']))}
- DMARC (_dmarc.{domain}): {'; '.join(live_dns.get('dmarc', ['no consultado']))}
""" if live_dns else ""
    for sel, vals in (live_dns.get('dkim') or {}).items():
        dns_block += f"- DKIM ({sel}._domainkey.{domain}): {'; '.join(vals)}\n"

    ips_block = "IPS ORIGEN Y PTR (últimos reportes):\n" + ('\n'.join(ip_ptr_summary) or '  ninguna') + "\n"
    alerts_block = "ALERTAS ACTIVAS NO RECONOCIDAS:\n" + ('\n'.join(alerts_summary) or '  ninguna') + "\n"

    prompt = f"""Eres un experto en email authentication (SPF, DKIM, DMARC, DNS).
Analiza la siguiente configuración del dominio "{domain}" y proporciona:
1. Diagnóstico del estado actual (qué está bien, qué está mal o incompleto)
2. Riesgos identificados (phishing, deliverability, configuraciones débiles)
3. Recomendaciones técnicas concretas y priorizadas
4. Próximos pasos ordenados por impacto

{setup_block}
{dns_block}
{ips_block}
{alerts_block}
Responde en español con formato markdown. Sé técnico y concreto. No repitas información obvia."""

    # 6. Llamar al proveedor de IA (mismo patrón que /api/interpret)
    try:
        import requests as req_lib
        tokens_used = None

        if provider == 'claude':
            mdl = model or 'claude-sonnet-4-6'
            resp = req_lib.post('https://api.anthropic.com/v1/messages',
                headers={'x-api-key': api_key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
                json={'model': mdl, 'max_tokens': 2048, 'messages': [{'role': 'user', 'content': prompt}]},
                timeout=60)
            resp.raise_for_status()
            body = resp.json()
            analysis = body['content'][0]['text']
            tokens_used = body.get('usage', {})

        elif provider == 'openai':
            mdl = model or 'gpt-4o'
            resp = req_lib.post('https://api.openai.com/v1/chat/completions',
                headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
                json={'model': mdl, 'messages': [{'role': 'user', 'content': prompt}], 'max_tokens': 2048},
                timeout=60)
            resp.raise_for_status()
            body = resp.json()
            analysis = body['choices'][0]['message']['content']
            tokens_used = body.get('usage', {})

        elif provider == 'gemini':
            mdl = model or 'gemini-2.0-flash'
            resp = req_lib.post(
                f'https://generativelanguage.googleapis.com/v1beta/models/{mdl}:generateContent?key={api_key}',
                json={'contents': [{'parts': [{'text': prompt}]}],
                      'generationConfig': {'maxOutputTokens': 2048}},
                timeout=60)
            resp.raise_for_status()
            body = resp.json()
            analysis = body['candidates'][0]['content']['parts'][0]['text']
            tokens_used = body.get('usageMetadata', {})
        else:
            return jsonify({'error': f'Provider desconocido: {provider}'}), 400

        return jsonify({'provider': provider, 'model': mdl, 'analysis': analysis, 'tokens_used': tokens_used})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ========== DNS TOOLS ==========

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def _dns_query(qname, record_type, timeout=5):
    """Ejecuta una query DNS y devuelve lista de strings con los resultados."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    answers = resolver.resolve(qname, record_type)
    return [rdata.to_text().strip('"') for rdata in answers]


@app.route('/api/dns-lookup', methods=['POST'])
def dns_lookup():
    if not DNS_AVAILABLE:
        return jsonify({'error': 'dnspython no instalado en este servidor'}), 503

    data = request.get_json() or {}
    lookup_type = data.get('type', '').lower()
    domain = (data.get('domain') or '').strip().lower().rstrip('.')
    selector = (data.get('selector') or '').strip().lower()
    ip = (data.get('ip') or '').strip()

    if not lookup_type:
        return jsonify({'error': 'type requerido'}), 400

    result = {'type': lookup_type, 'records': [], 'analysis': ''}

    try:
        if lookup_type == 'spf':
            if not domain:
                return jsonify({'error': 'domain requerido'}), 400
            result['query'] = f'TXT {domain}'
            txts = _dns_query(domain, 'TXT')
            spf = [t for t in txts if t.startswith('v=spf1')]
            result['records'] = spf if spf else txts
            if spf:
                r = spf[0]
                issues = []
                if '~all' in r:
                    issues.append('⚠️ ~all (softfail): los fallos no se rechazan, solo se marcan')
                elif '-all' in r:
                    issues.append('✅ -all (hardfail): correcto para producción')
                elif '?all' in r or '+all' in r:
                    issues.append('❌ +all o ?all: permite cualquier IP, inseguro')
                result['analysis'] = '\n'.join(issues) if issues else '✅ Registro encontrado'
            else:
                result['analysis'] = '❌ No se encontró registro SPF (v=spf1)'

        elif lookup_type == 'dkim':
            if not domain or not selector:
                return jsonify({'error': 'domain y selector requeridos'}), 400
            qname = f'{selector}._domainkey.{domain}'
            result['query'] = f'TXT {qname}'
            txts = _dns_query(qname, 'TXT')
            result['records'] = txts
            dkim = ' '.join(txts)
            if 'p=' in dkim:
                has_key = bool([t for t in dkim.split(';') if t.strip().startswith('p=') and len(t.strip()) > 2])
                result['analysis'] = '✅ Registro DKIM válido con clave pública' if has_key else '❌ Registro presente pero sin clave pública (p= vacío)'
            else:
                result['analysis'] = '❌ No parece un registro DKIM válido'

        elif lookup_type == 'dmarc':
            if not domain:
                return jsonify({'error': 'domain requerido'}), 400
            qname = f'_dmarc.{domain}'
            result['query'] = f'TXT {qname}'
            txts = _dns_query(qname, 'TXT')
            dmarc = [t for t in txts if t.startswith('v=DMARC1')]
            result['records'] = dmarc if dmarc else txts
            if dmarc:
                r = dmarc[0]
                parts = {kv.split('=')[0].strip(): kv.split('=')[1].strip()
                         for kv in r.split(';') if '=' in kv}
                p = parts.get('p', '?')
                pct = parts.get('pct', '100')
                rua = parts.get('rua', 'no configurado')
                lines = [
                    f'Política: {p}',
                    f'Porcentaje aplicado: {pct}%',
                    f'Reportes agregados (rua): {rua}',
                ]
                if p == 'none':
                    lines.append('⚠️ p=none: solo monitoreo, no se aplica acción sobre fallos')
                elif p == 'quarantine':
                    lines.append('⚠️ p=quarantine: los fallos van a spam')
                elif p == 'reject':
                    lines.append('✅ p=reject: los fallos se rechazan (máxima protección)')
                result['analysis'] = '\n'.join(lines)
            else:
                result['analysis'] = '❌ No se encontró registro DMARC'

        elif lookup_type == 'mx':
            if not domain:
                return jsonify({'error': 'domain requerido'}), 400
            result['query'] = f'MX {domain}'
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5
            answers = resolver.resolve(domain, 'MX')
            mx_list = sorted([(r.preference, r.exchange.to_text().rstrip('.')) for r in answers])
            result['records'] = [f'{pref} {exch}' for pref, exch in mx_list]
            result['analysis'] = f'✅ {len(mx_list)} servidor(es) MX encontrado(s)'

        elif lookup_type == 'ptr':
            if not ip:
                return jsonify({'error': 'ip requerida'}), 400
            rev = dns.reversename.from_address(ip)
            result['query'] = f'PTR {str(rev)}'
            ptrs = _dns_query(str(rev), 'PTR')
            result['records'] = [p.rstrip('.') for p in ptrs]
            result['analysis'] = f'✅ PTR: {result["records"][0]}' if result['records'] else '⚠️ Sin registro PTR'

        else:
            return jsonify({'error': f'Tipo desconocido: {lookup_type}'}), 400

    except dns.resolver.NXDOMAIN:
        result['records'] = []
        result['analysis'] = '❌ Dominio/registro no encontrado (NXDOMAIN)'
    except dns.resolver.NoAnswer:
        result['records'] = []
        result['analysis'] = f'❌ No hay registros {lookup_type.upper()} para este dominio'
    except dns.resolver.Timeout:
        result['records'] = []
        result['analysis'] = '❌ Timeout: el servidor DNS no respondió a tiempo'
    except Exception as e:
        result['records'] = []
        result['analysis'] = f'❌ Error: {str(e)}'

    return jsonify(result)


# ========== MAIN ==========

if __name__ == '__main__':
    logger.info(f"Conectando a {DB_HOST}:{DB_PORT}/{DB_NAME}")
    test_conn = get_db_connection()
    if not test_conn:
        logger.error("No se pudo conectar a la BD. Verifica variables de entorno.")
        exit(1)
    test_conn.close()

    logger.info("✅ Servidor iniciado en http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
