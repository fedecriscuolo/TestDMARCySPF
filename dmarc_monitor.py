#!/usr/bin/env python3
"""
DMARC Report Monitor
=====================
Parsea reportes DMARC en XML y almacena análisis en PostgreSQL.
Soporta múltiples <record> por XML (uno por IP origen). El schema separa
metadata del reporte (dmarc_reports) de los registros individuales
(dmarc_report_records) para permitir análisis estadístico fino.

Uso:
  python dmarc_monitor.py --file reporte.xml
  python dmarc_monitor.py --folder ./dmarc_reports/
  python dmarc_monitor.py --init-db        # crea tablas si no existen
  python dmarc_monitor.py --reset-db       # destructivo: dropea y recrea
"""

import xml.etree.ElementTree as ET
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import sys
import json
import logging
from datetime import datetime
from pathlib import Path
import argparse
from typing import Dict, List, Optional, Tuple
import smtplib
from email.mime.text import MIMEText

# ========== CONFIGURACIÓN ==========

DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME', 'dmarc_monitor')
DB_USER = os.getenv('DB_USER', 'postgres')
DB_PASSWORD = os.getenv('DB_PASSWORD', '')

ALERT_EMAIL = os.getenv('ALERT_EMAIL', '')
SMTP_SERVER = os.getenv('SMTP_SERVER', '')
SMTP_PORT = os.getenv('SMTP_PORT', '587')
SMTP_USER = os.getenv('SMTP_USER', '')
SMTP_PASS = os.getenv('SMTP_PASS', '')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ========== CLASES DE DATOS ==========

class DMARCReportRecord:
    """Un <record> dentro de un feedback DMARC: stats por IP origen."""

    def __init__(self):
        self.source_ip: str = ""
        self.count: int = 0
        self.disposition: str = ""
        self.dkim_result: str = ""
        self.spf_result: str = ""
        self.header_from: str = ""
        # auth_results detallado
        self.dkim_domains: List[Dict] = []
        self.spf_domains: List[Dict] = []


class DMARCFeedback:
    """Un XML DMARC completo: metadata + policy + N records."""

    def __init__(self):
        self.report_id: str = ""
        self.org_name: str = ""
        self.domain: str = ""
        self.date_begin: int = 0
        self.date_end: int = 0
        self.policy_adkim: str = ""
        self.policy_aspf: str = ""
        self.policy_p: str = ""
        self.policy_sp: str = ""
        self.policy_pct: int = 0
        self.records: List[DMARCReportRecord] = []


# ========== FUNCIONES DE PARSEO ==========

def parse_dmarc_xml(file_path: str) -> DMARCFeedback:
    """
    Parsea un archivo XML DMARC y retorna DMARCFeedback con TODOS los <record>.

    Estructura esperada (RFC 7489):
    <feedback>
      <report_metadata>...</report_metadata>
      <policy_published>...</policy_published>
      <record>...</record>
      <record>...</record>   ← puede haber N
      ...
    </feedback>
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error(f"Error parseando XML {file_path}: {e}")
        raise

    feedback = DMARCFeedback()

    # === METADATA ===
    metadata = root.find('report_metadata')
    if metadata is not None:
        feedback.org_name = metadata.findtext('org_name', '')
        feedback.report_id = metadata.findtext('report_id', '')
        date_range = metadata.find('date_range')
        if date_range is not None:
            feedback.date_begin = int(date_range.findtext('begin', '0'))
            feedback.date_end = int(date_range.findtext('end', '0'))

    # === POLICY ===
    policy = root.find('policy_published')
    if policy is not None:
        feedback.domain = policy.findtext('domain', '')
        feedback.policy_adkim = policy.findtext('adkim', '')
        feedback.policy_aspf = policy.findtext('aspf', '')
        feedback.policy_p = policy.findtext('p', '')
        feedback.policy_sp = policy.findtext('sp', '')
        feedback.policy_pct = int(policy.findtext('pct', '0') or '0')

    # === RECORDS (uno por IP origen) ===
    for record_elem in root.findall('record'):
        rec = DMARCReportRecord()

        row = record_elem.find('row')
        if row is not None:
            rec.source_ip = row.findtext('source_ip', '')
            rec.count = int(row.findtext('count', '0') or '0')
            policy_eval = row.find('policy_evaluated')
            if policy_eval is not None:
                rec.disposition = policy_eval.findtext('disposition', '')
                rec.dkim_result = policy_eval.findtext('dkim', '')
                rec.spf_result = policy_eval.findtext('spf', '')

        identifiers = record_elem.find('identifiers')
        if identifiers is not None:
            rec.header_from = identifiers.findtext('header_from', '')

        auth_results = record_elem.find('auth_results')
        if auth_results is not None:
            for dkim in auth_results.findall('dkim'):
                rec.dkim_domains.append({
                    'domain': dkim.findtext('domain', ''),
                    'result': dkim.findtext('result', ''),
                    'selector': dkim.findtext('selector', ''),
                })
            for spf in auth_results.findall('spf'):
                rec.spf_domains.append({
                    'domain': spf.findtext('domain', ''),
                    'result': spf.findtext('result', ''),
                })

        feedback.records.append(rec)

    logger.info(
        f"Parseado: {feedback.domain} (report_id={feedback.report_id}, "
        f"records={len(feedback.records)})"
    )
    return feedback


# ========== BASE DE DATOS ==========

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS dmarc_reports (
    id SERIAL PRIMARY KEY,
    report_id VARCHAR(255) UNIQUE NOT NULL,
    org_name VARCHAR(255),
    domain VARCHAR(255) NOT NULL,
    date_begin BIGINT,
    date_end BIGINT,
    policy_adkim VARCHAR(10),
    policy_aspf VARCHAR(10),
    policy_p VARCHAR(20),
    policy_sp VARCHAR(20),
    policy_pct INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dmarc_report_records (
    id SERIAL PRIMARY KEY,
    report_id INT NOT NULL REFERENCES dmarc_reports(id) ON DELETE CASCADE,
    source_ip INET,
    count INT,
    disposition VARCHAR(20),
    dkim_result VARCHAR(20),
    spf_result VARCHAR(20),
    header_from VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dmarc_dkim_results (
    id SERIAL PRIMARY KEY,
    record_id INT NOT NULL REFERENCES dmarc_report_records(id) ON DELETE CASCADE,
    domain VARCHAR(255),
    result VARCHAR(20),
    selector VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dmarc_spf_results (
    id SERIAL PRIMARY KEY,
    record_id INT NOT NULL REFERENCES dmarc_report_records(id) ON DELETE CASCADE,
    domain VARCHAR(255),
    result VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dmarc_alerts (
    id SERIAL PRIMARY KEY,
    record_id INT NOT NULL REFERENCES dmarc_report_records(id) ON DELETE CASCADE,
    alert_type VARCHAR(50),
    severity VARCHAR(20),
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_reports_domain ON dmarc_reports(domain);
CREATE INDEX IF NOT EXISTS idx_reports_date_begin ON dmarc_reports(date_begin);
CREATE INDEX IF NOT EXISTS idx_records_report ON dmarc_report_records(report_id);
CREATE INDEX IF NOT EXISTS idx_records_source_ip ON dmarc_report_records(source_ip);
CREATE INDEX IF NOT EXISTS idx_records_spf ON dmarc_report_records(spf_result);
CREATE INDEX IF NOT EXISTS idx_records_dkim ON dmarc_report_records(dkim_result);
CREATE INDEX IF NOT EXISTS idx_alerts_record ON dmarc_alerts(record_id);
CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON dmarc_alerts(acknowledged);

CREATE TABLE IF NOT EXISTS dns_records (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL,
    record_type VARCHAR(10) NOT NULL,   -- TXT, MX, A, CNAME, etc.
    host TEXT NOT NULL,                  -- @ _dmarc send resend._domainkey etc.
    value TEXT NOT NULL,
    ttl TEXT DEFAULT 'Automatic',
    notes TEXT,                          -- descripcion/proposito del registro
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_dns_records_domain ON dns_records(domain);

CREATE TABLE IF NOT EXISTS dns_setup (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    dns_provider TEXT,
    email_stack TEXT,
    spf_record TEXT,
    dmarc_record TEXT,
    dkim_selectors TEXT[],
    extra_notes TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

DROP_SQL = """
DROP TABLE IF EXISTS dmarc_alerts CASCADE;
DROP TABLE IF EXISTS dmarc_dkim_results CASCADE;
DROP TABLE IF EXISTS dmarc_spf_results CASCADE;
DROP TABLE IF EXISTS dmarc_report_records CASCADE;
DROP TABLE IF EXISTS dmarc_reports CASCADE;
DROP TABLE IF EXISTS dns_records CASCADE;
DROP TABLE IF EXISTS dns_setup CASCADE;
"""


class DMARCDatabase:
    """Gestor de conexión y operaciones en PostgreSQL."""

    def __init__(self):
        self.conn = None
        self.connect()

    def connect(self):
        try:
            self.conn = psycopg2.connect(
                host=DB_HOST, port=DB_PORT, database=DB_NAME,
                user=DB_USER, password=DB_PASSWORD,
            )
            logger.info(f"Conectado a {DB_HOST}:{DB_PORT}/{DB_NAME}")
        except psycopg2.Error as e:
            logger.error(f"Error conectando a BD: {e}")
            raise

    def create_tables(self):
        with self.conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
        self.conn.commit()
        logger.info("Tablas creadas/verificadas")

    def reset_tables(self):
        """Destructivo: dropea todas las tablas DMARC y las recrea."""
        with self.conn.cursor() as cur:
            cur.execute(DROP_SQL)
            cur.execute(SCHEMA_SQL)
        self.conn.commit()
        logger.warning("Tablas DMARC dropeadas y recreadas")

    def insert_feedback(self, feedback: DMARCFeedback) -> Tuple[int, bool, int, int]:
        """
        Inserta un feedback DMARC.

        Returns:
            (db_report_id, was_new, records_inserted, alerts_generated)

        Idempotencia: si el report_id ya existe, no inserta records (evita
        duplicar). Devuelve was_new=False y conteos en cero.
        """
        # Insertar reporte (head)
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO dmarc_reports (
                    report_id, org_name, domain, date_begin, date_end,
                    policy_adkim, policy_aspf, policy_p, policy_sp, policy_pct
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (report_id) DO NOTHING
                RETURNING id;
                """,
                (
                    feedback.report_id, feedback.org_name, feedback.domain,
                    feedback.date_begin, feedback.date_end,
                    feedback.policy_adkim, feedback.policy_aspf,
                    feedback.policy_p, feedback.policy_sp, feedback.policy_pct,
                ),
            )
            row = cur.fetchone()

            if row is None:
                # Ya existía → no re-insertamos records ni alerts
                cur.execute(
                    "SELECT id FROM dmarc_reports WHERE report_id = %s",
                    (feedback.report_id,),
                )
                existing_id = cur.fetchone()[0]
                self.conn.commit()
                logger.info(
                    f"Report ya existente (id={existing_id}, report_id="
                    f"{feedback.report_id}). Skipping records."
                )
                return existing_id, False, 0, 0

            db_report_id = row[0]

        # Insertar records + auth_results + alerts
        records_inserted = 0
        alerts_generated = 0

        for rec in feedback.records:
            with self.conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO dmarc_report_records (
                        report_id, source_ip, count, disposition,
                        dkim_result, spf_result, header_from
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id;
                    """,
                    (
                        db_report_id, rec.source_ip or None, rec.count,
                        rec.disposition, rec.dkim_result, rec.spf_result,
                        rec.header_from,
                    ),
                )
                db_record_id = cur.fetchone()[0]
            records_inserted += 1

            for dkim in rec.dkim_domains:
                with self.conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO dmarc_dkim_results
                            (record_id, domain, result, selector)
                        VALUES (%s, %s, %s, %s);
                        """,
                        (db_record_id, dkim['domain'], dkim['result'],
                         dkim['selector']),
                    )

            for spf in rec.spf_domains:
                with self.conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO dmarc_spf_results
                            (record_id, domain, result)
                        VALUES (%s, %s, %s);
                        """,
                        (db_record_id, spf['domain'], spf['result']),
                    )

            alerts_generated += self._insert_alerts_for_record(
                rec, db_record_id, feedback.domain,
            )

        self.conn.commit()
        logger.info(
            f"Reporte insertado (db_id={db_report_id}, records="
            f"{records_inserted}, alerts={alerts_generated})"
        )
        return db_report_id, True, records_inserted, alerts_generated

    def _insert_alerts_for_record(
        self, rec: DMARCReportRecord, record_id: int, domain: str,
    ) -> int:
        """Aplica las 4 reglas de alerta y retorna cuántas insertó."""
        alerts: List[Dict] = []

        if rec.spf_result == 'fail':
            alerts.append({
                'type': 'spf_failure',
                'severity': 'high',
                'message': (
                    f"SPF failed para {rec.header_from or domain} desde "
                    f"{rec.source_ip} ({rec.count} emails)"
                ),
            })
        if rec.dkim_result == 'fail':
            alerts.append({
                'type': 'dkim_failure',
                'severity': 'high',
                'message': (
                    f"DKIM failed para {rec.header_from or domain} desde "
                    f"{rec.source_ip} ({rec.count} emails)"
                ),
            })
        if rec.disposition in ('quarantine', 'reject'):
            alerts.append({
                'type': 'policy_action',
                'severity': 'medium',
                'message': (
                    f"Emails en {rec.disposition} desde {rec.source_ip} "
                    f"({rec.count} emails)"
                ),
            })
        if rec.spf_result == 'fail' and rec.count > 10:
            alerts.append({
                'type': 'high_volume_fail',
                'severity': 'critical',
                'message': (
                    f"Alto volumen de SPF failures ({rec.count} emails) "
                    f"desde {rec.source_ip}"
                ),
            })

        for alert in alerts:
            with self.conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO dmarc_alerts
                        (record_id, alert_type, severity, message)
                    VALUES (%s, %s, %s, %s);
                    """,
                    (record_id, alert['type'], alert['severity'],
                     alert['message']),
                )
        return len(alerts)

    def get_summary(self, domain: str, days: int = 7) -> Dict:
        """Resumen agregado (SPF/DKIM por dominio en últimos N días)."""
        sql = """
        SELECT
            r.domain,
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
            AND r.date_begin > EXTRACT(EPOCH FROM NOW() - INTERVAL '%s days')::bigint
        GROUP BY r.domain;
        """
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, (domain, days))
            result = cur.fetchone()

        if not result:
            return {'error': 'Sin reportes para este período'}

        total = result['total_emails'] or 0
        pct = lambda n: round(n / total * 100, 2) if total > 0 else 0
        return {
            'domain': result['domain'],
            'total_reports': result['total_reports'],
            'total_records': result['total_records'],
            'total_emails': total,
            'spf': {
                'pass': result['spf_pass'], 'fail': result['spf_fail'],
                'pass_pct': pct(result['spf_pass']),
                'fail_pct': pct(result['spf_fail']),
            },
            'dkim': {
                'pass': result['dkim_pass'], 'fail': result['dkim_fail'],
                'pass_pct': pct(result['dkim_pass']),
                'fail_pct': pct(result['dkim_fail']),
            },
        }

    def get_active_alerts(self, domain: Optional[str] = None) -> List[Dict]:
        sql = """
        SELECT
            da.id, da.alert_type, da.severity, da.message,
            da.created_at, r.domain, rr.source_ip
        FROM dmarc_alerts da
        JOIN dmarc_report_records rr ON da.record_id = rr.id
        JOIN dmarc_reports r ON rr.report_id = r.id
        WHERE da.acknowledged = FALSE
        """
        params = []
        if domain:
            sql += " AND r.domain = %s"
            params.append(domain)
        sql += " ORDER BY da.created_at DESC LIMIT 50;"
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]

    def close(self):
        if self.conn:
            self.conn.close()
            logger.info("Conexión cerrada")


# ========== EMAIL ALERTS ==========

def send_alert_email(alerts_count: int, domain: str):
    if not ALERT_EMAIL or not SMTP_SERVER or alerts_count == 0:
        return
    body = (
        f"DMARC Alert Summary para {domain}\n"
        f"==================================\n\n"
        f"{alerts_count} alertas detectadas. Ver dashboard.\n"
    )
    msg = MIMEText(body)
    msg['Subject'] = f"[DMARC] Alertas para {domain}"
    msg['From'] = SMTP_USER
    msg['To'] = ALERT_EMAIL
    try:
        with smtplib.SMTP(SMTP_SERVER, int(SMTP_PORT)) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        logger.info(f"Email de alerta enviado a {ALERT_EMAIL}")
    except Exception as e:
        logger.error(f"Error enviando email: {e}")


# ========== CLI ==========

def _process_file(db: DMARCDatabase, path: str):
    feedback = parse_dmarc_xml(path)
    _, was_new, records, alerts = db.insert_feedback(feedback)
    if alerts > 0:
        send_alert_email(alerts, feedback.domain)
    return was_new, records, alerts


def main():
    parser = argparse.ArgumentParser(
        description='Monitor DMARC Reports',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  python dmarc_monitor.py --file reporte.xml\n"
            "  python dmarc_monitor.py --folder ./dmarc_reports/\n"
            "  python dmarc_monitor.py --summary yourdomain.com --days 30\n"
            "  python dmarc_monitor.py --reset-db   # destructivo\n"
        ),
    )
    parser.add_argument('--file', help='Parsear un archivo XML DMARC')
    parser.add_argument('--folder', help='Parsear todos los XMLs en una carpeta')
    parser.add_argument('--summary', help='Ver resumen para un dominio')
    parser.add_argument('--days', type=int, default=7,
                        help='Días para resumen (default: 7)')
    parser.add_argument('--init-db', action='store_true',
                        help='Inicializar tablas (CREATE IF NOT EXISTS)')
    parser.add_argument('--reset-db', action='store_true',
                        help='Destructivo: dropea y recrea todas las tablas')
    parser.add_argument('--alerts', help='Ver alertas activas para un dominio')

    args = parser.parse_args()
    db = DMARCDatabase()

    try:
        if args.reset_db:
            db.reset_tables()
            return
        if args.init_db:
            db.create_tables()
            return
        if args.file:
            if not os.path.exists(args.file):
                logger.error(f"Archivo no encontrado: {args.file}")
                return
            _process_file(db, args.file)
        elif args.folder:
            if not os.path.isdir(args.folder):
                logger.error(f"Carpeta no encontrada: {args.folder}")
                return
            xml_files = list(Path(args.folder).glob('*.xml'))
            logger.info(f"Encontrados {len(xml_files)} archivos XML")
            for xml_file in xml_files:
                try:
                    _process_file(db, str(xml_file))
                except Exception as e:
                    logger.error(f"Error procesando {xml_file}: {e}")
        elif args.summary:
            print(json.dumps(db.get_summary(args.summary, args.days), indent=2))
        elif args.alerts:
            print(json.dumps(db.get_active_alerts(args.alerts),
                             indent=2, default=str))
    finally:
        db.close()


if __name__ == '__main__':
    main()
