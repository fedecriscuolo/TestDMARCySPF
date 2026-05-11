-- ============================================================
-- DMARC Monitor — Queries para exploración directa en BD
-- ============================================================
-- Conectar: psql -h localhost -U postgres -d dmarc_monitor
-- O desde Docker: docker-compose exec api psql -U postgres dmarc_monitor
--
-- Schema (7 tablas):
--   dmarc_reports          — 1 fila por XML procesado
--   dmarc_report_records   — 1 fila por <record> (por IP origen)
--   dmarc_dkim_results     — detalle DKIM por record
--   dmarc_spf_results      — detalle SPF por record
--   dmarc_alerts           — alertas automáticas por record
--   dns_setup              — config del dominio (proveedor, stack, selectores)
--   dns_records            — backup/doc de registros DNS
-- ============================================================


-- ========== 1. ESTADO GENERAL ==========

-- Cuántos registros hay en cada tabla
SELECT 'dmarc_reports'        AS tabla, COUNT(*) AS filas FROM dmarc_reports
UNION ALL
SELECT 'dmarc_report_records',          COUNT(*) FROM dmarc_report_records
UNION ALL
SELECT 'dmarc_dkim_results',            COUNT(*) FROM dmarc_dkim_results
UNION ALL
SELECT 'dmarc_spf_results',             COUNT(*) FROM dmarc_spf_results
UNION ALL
SELECT 'dmarc_alerts',                  COUNT(*) FROM dmarc_alerts
UNION ALL
SELECT 'dns_records',                   COUNT(*) FROM dns_records
UNION ALL
SELECT 'dns_setup',                     COUNT(*) FROM dns_setup;

-- Reportes procesados por dominio
SELECT domain, COUNT(*) AS xmls_procesados
FROM dmarc_reports
GROUP BY domain
ORDER BY xmls_procesados DESC;

-- Últimos 10 XMLs cargados
SELECT
    r.domain,
    to_timestamp(r.date_begin)::date AS periodo_inicio,
    to_timestamp(r.date_end)::date   AS periodo_fin,
    r.org_name                        AS enviado_por,
    r.created_at                      AS cargado_el,
    COUNT(rr.id)                      AS registros
FROM dmarc_reports r
LEFT JOIN dmarc_report_records rr ON rr.report_id = r.id
GROUP BY r.id
ORDER BY r.created_at DESC
LIMIT 10;


-- ========== 2. SPF / DKIM — RESULTADOS ==========

-- Resumen SPF y DKIM por dominio (todos los datos)
SELECT
    r.domain,
    SUM(rr.count)                                                          AS total_emails,
    SUM(CASE WHEN rr.spf_result  = 'pass' THEN rr.count ELSE 0 END)       AS spf_pass,
    SUM(CASE WHEN rr.spf_result  = 'fail' THEN rr.count ELSE 0 END)       AS spf_fail,
    SUM(CASE WHEN rr.spf_result  = 'none' THEN rr.count ELSE 0 END)       AS spf_none,
    SUM(CASE WHEN rr.dkim_result = 'pass' THEN rr.count ELSE 0 END)       AS dkim_pass,
    SUM(CASE WHEN rr.dkim_result = 'fail' THEN rr.count ELSE 0 END)       AS dkim_fail,
    ROUND(100.0 * SUM(CASE WHEN rr.spf_result  = 'pass' THEN rr.count ELSE 0 END)
        / NULLIF(SUM(rr.count), 0), 1)                                     AS spf_pass_pct,
    ROUND(100.0 * SUM(CASE WHEN rr.dkim_result = 'pass' THEN rr.count ELSE 0 END)
        / NULLIF(SUM(rr.count), 0), 1)                                     AS dkim_pass_pct
FROM dmarc_reports r
JOIN dmarc_report_records rr ON rr.report_id = r.id
GROUP BY r.domain
ORDER BY total_emails DESC;

-- Detalle de DKIM por selector (qué selectores están pasando o fallando)
SELECT
    d.domain      AS dkim_domain,
    d.selector,
    d.result,
    COUNT(*)      AS ocurrencias
FROM dmarc_dkim_results d
GROUP BY d.domain, d.selector, d.result
ORDER BY d.domain, ocurrencias DESC;

-- Dominios SPF que fallan (qué envelope sender está rompiendo)
SELECT
    r.domain                       AS dominio_dmarc,
    s.domain                       AS envelope_sender,
    s.result,
    COUNT(*)                       AS ocurrencias,
    SUM(rr.count)                  AS emails_afectados
FROM dmarc_report_records rr
JOIN dmarc_reports r          ON r.id  = rr.report_id
JOIN dmarc_spf_results s      ON s.record_id = rr.id
WHERE s.result IN ('fail', 'none', 'softfail')
GROUP BY r.domain, s.domain, s.result
ORDER BY emails_afectados DESC;

-- Tendencia diaria SPF/DKIM (últimos 30 días)
SELECT
    to_timestamp(r.date_begin)::date AS dia,
    r.domain,
    SUM(rr.count)                    AS total_emails,
    ROUND(100.0 * SUM(CASE WHEN rr.spf_result  = 'pass' THEN rr.count ELSE 0 END)
        / NULLIF(SUM(rr.count), 0), 1) AS spf_pass_pct,
    ROUND(100.0 * SUM(CASE WHEN rr.dkim_result = 'pass' THEN rr.count ELSE 0 END)
        / NULLIF(SUM(rr.count), 0), 1) AS dkim_pass_pct
FROM dmarc_reports r
JOIN dmarc_report_records rr ON rr.report_id = r.id
WHERE r.date_begin > EXTRACT(EPOCH FROM NOW() - INTERVAL '30 days')::bigint
GROUP BY dia, r.domain
ORDER BY dia DESC, r.domain;


-- ========== 3. IPs ORIGEN ==========

-- Todas las IPs únicas con su resultado SPF/DKIM
SELECT
    rr.source_ip::text,
    r.domain,
    SUM(rr.count)                    AS emails,
    rr.spf_result,
    rr.dkim_result,
    rr.disposition,
    MAX(to_timestamp(r.date_begin))  AS ultimo_reporte
FROM dmarc_report_records rr
JOIN dmarc_reports r ON r.id = rr.report_id
GROUP BY rr.source_ip, r.domain, rr.spf_result, rr.dkim_result, rr.disposition
ORDER BY emails DESC;

-- IPs con fallos SPF (posibles problemas de configuración o spoofing)
SELECT
    rr.source_ip::text,
    r.domain,
    SUM(rr.count) AS emails_fallidos,
    COUNT(DISTINCT r.id) AS en_cuantos_reportes
FROM dmarc_report_records rr
JOIN dmarc_reports r ON r.id = rr.report_id
WHERE rr.spf_result = 'fail'
GROUP BY rr.source_ip, r.domain
ORDER BY emails_fallidos DESC;

-- IPs en quarantine o reject
SELECT
    rr.source_ip::text,
    rr.disposition,
    SUM(rr.count) AS emails_bloqueados,
    r.domain
FROM dmarc_report_records rr
JOIN dmarc_reports r ON r.id = rr.report_id
WHERE rr.disposition IN ('quarantine', 'reject')
GROUP BY rr.source_ip, rr.disposition, r.domain
ORDER BY emails_bloqueados DESC;


-- ========== 4. ALERTAS ==========

-- Alertas activas (sin reconocer)
SELECT
    a.id,
    a.severity,
    a.alert_type,
    a.message,
    rr.source_ip::text,
    r.domain,
    a.created_at
FROM dmarc_alerts a
JOIN dmarc_report_records rr ON rr.id = a.record_id
JOIN dmarc_reports r          ON r.id = rr.report_id
WHERE a.acknowledged = FALSE
ORDER BY
    CASE a.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
    a.created_at DESC;

-- Resumen de alertas por tipo y severidad
SELECT
    alert_type,
    severity,
    COUNT(*)                                              AS total,
    COUNT(*) FILTER (WHERE acknowledged = FALSE)          AS sin_reconocer
FROM dmarc_alerts
GROUP BY alert_type, severity
ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END;

-- Reconocer una alerta manualmente (reemplazar N por el id)
-- UPDATE dmarc_alerts SET acknowledged = TRUE WHERE id = N;

-- Reconocer todas las alertas de un dominio
-- UPDATE dmarc_alerts a
-- SET acknowledged = TRUE
-- FROM dmarc_report_records rr
-- JOIN dmarc_reports r ON r.id = rr.report_id
-- WHERE a.record_id = rr.id AND r.domain = 'tudominio.com';


-- ========== 5. POLÍTICA DMARC ==========

-- Historial de políticas vistas (detecta si alguien cambió p= o pct=)
SELECT DISTINCT
    domain,
    policy_p,
    policy_adkim,
    policy_aspf,
    policy_pct,
    MIN(to_timestamp(date_begin)) AS primera_vez,
    MAX(to_timestamp(date_begin)) AS ultima_vez
FROM dmarc_reports
GROUP BY domain, policy_p, policy_adkim, policy_aspf, policy_pct
ORDER BY domain, ultima_vez DESC;


-- ========== 6. DNS CONFIG (tablas nuevas) ==========

-- Ver configuración guardada del dominio
SELECT
    domain,
    dns_provider,
    email_stack,
    dkim_selectors,
    spf_record,
    dmarc_record,
    extra_notes,
    updated_at
FROM dns_setup
ORDER BY domain;

-- Ver todos los registros DNS documentados
SELECT
    record_type,
    host,
    value,
    ttl,
    notes
FROM dns_records
WHERE domain = 'tudominio.com'   -- cambiar por tu dominio
ORDER BY record_type, host;

-- Registros TXT (SPF, DMARC, DKIM, verificaciones)
SELECT host, value, notes
FROM dns_records
WHERE domain = 'tudominio.com' AND record_type = 'TXT'
ORDER BY host;

-- Registros MX
SELECT host, value, ttl, notes
FROM dns_records
WHERE domain = 'tudominio.com' AND record_type = 'MX'
ORDER BY host;


-- ========== 7. AUDITORÍA Y MANTENIMIENTO ==========

-- Reportes cargados hoy
SELECT
    domain,
    COUNT(*)         AS xmls,
    MIN(created_at)  AS primer_upload,
    MAX(created_at)  AS ultimo_upload
FROM dmarc_reports
WHERE created_at::date = CURRENT_DATE
GROUP BY domain;

-- Detectar duplicados (no debería haber — el ON CONFLICT los bloquea)
SELECT report_id, COUNT(*) AS veces
FROM dmarc_reports
GROUP BY report_id
HAVING COUNT(*) > 1;

-- Tamaño de cada tabla
SELECT
    tablename,
    pg_size_pretty(pg_total_relation_size('public.' || tablename)) AS tamaño
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size('public.' || tablename) DESC;

-- Limpiar alertas reconocidas con más de 90 días
-- DELETE FROM dmarc_alerts
-- WHERE acknowledged = TRUE AND created_at < NOW() - INTERVAL '90 days';

-- Exportar records a CSV (desde psql)
-- \COPY (
--   SELECT r.domain, to_timestamp(r.date_begin)::date, rr.source_ip, rr.count, rr.spf_result, rr.dkim_result
--   FROM dmarc_report_records rr JOIN dmarc_reports r ON r.id = rr.report_id
--   WHERE r.domain = 'tudominio.com'
-- ) TO '/tmp/dmarc_export.csv' WITH CSV HEADER;
