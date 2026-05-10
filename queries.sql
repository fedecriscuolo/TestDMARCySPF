-- ========================================
-- DMARC Monitor - Useful SQL Queries
-- ========================================
-- Copiar y ejecutar en psql o DB client
-- psql -h localhost -U postgres -d dmarc_monitor

-- ========== DIAGNÓSTICO BÁSICO ==========

-- Ver todas las tablas creadas
\dt

-- Contar reportes por dominio
SELECT domain, COUNT(*) as total
FROM dmarc_reports
GROUP BY domain
ORDER BY total DESC;

-- Últimos 10 reportes
SELECT 
    domain,
    to_timestamp(date_begin)::date as date,
    source_ip,
    count,
    spf_result,
    dkim_result,
    disposition
FROM dmarc_reports
ORDER BY date_begin DESC
LIMIT 10;

-- ========== ANÁLISIS SPF/DKIM ==========

-- Resumen de SPF últimos 7 días
SELECT 
    domain,
    spf_result,
    COUNT(*) as reports,
    SUM(count) as total_emails,
    ROUND(100.0 * SUM(count) / 
        SUM(SUM(count)) OVER (PARTITION BY domain), 2) as percentage
FROM dmarc_reports
WHERE date_begin > EXTRACT(EPOCH FROM NOW() - INTERVAL '7 days')::bigint
GROUP BY domain, spf_result
ORDER BY domain, spf_result;

-- DKIM detailed results por selector
SELECT 
    domain,
    selector,
    result,
    COUNT(*) as occurrences
FROM dmarc_dkim_results
GROUP BY domain, selector, result
ORDER BY domain, occurrences DESC;

-- SPF domains que fallan
SELECT DISTINCT
    dr.domain,
    dsr.domain as spf_domain,
    dsr.result,
    COUNT(*) as failures
FROM dmarc_reports dr
JOIN dmarc_spf_results dsr ON dr.id = dsr.report_id
WHERE dsr.result = 'fail'
GROUP BY dr.domain, dsr.domain, dsr.result
ORDER BY failures DESC;

-- ========== ALERTAS ==========

-- Todas las alertas sin reconocer
SELECT 
    id,
    alert_type,
    severity,
    message,
    created_at,
    (SELECT COUNT(*) FROM dmarc_alerts WHERE severity = 'critical' AND acknowledged = FALSE) as critical_count
FROM dmarc_alerts
WHERE acknowledged = FALSE
ORDER BY severity DESC, created_at DESC;

-- Distribuci'on de alertas por tipo
SELECT 
    alert_type,
    severity,
    COUNT(*) as total,
    COUNT(CASE WHEN acknowledged = FALSE THEN 1 END) as unacknowledged
FROM dmarc_alerts
GROUP BY alert_type, severity
ORDER BY total DESC;

-- Alertas por dominio
SELECT 
    dr.domain,
    da.severity,
    COUNT(*) as alert_count
FROM dmarc_alerts da
JOIN dmarc_reports dr ON da.report_id = dr.id
WHERE da.acknowledged = FALSE
GROUP BY dr.domain, da.severity
ORDER BY dr.domain, 
    CASE da.severity 
        WHEN 'critical' THEN 1 
        WHEN 'high' THEN 2 
        WHEN 'medium' THEN 3 
        ELSE 4 
    END;

-- ========== IPs PROBLEMÁTICAS ==========

-- IPs con más SPF failures
SELECT 
    source_ip,
    domain,
    COUNT(*) as fail_count,
    SUM(count) as total_emails
FROM dmarc_reports
WHERE spf_result = 'fail'
GROUP BY source_ip, domain
ORDER BY fail_count DESC
LIMIT 20;

-- IPs bloqueadas por policy
SELECT 
    source_ip,
    disposition,
    COUNT(*) as occurrences,
    SUM(count) as total_emails,
    STRING_AGG(DISTINCT domain, ', ') as domains
FROM dmarc_reports
WHERE disposition IN ('quarantine', 'reject')
GROUP BY source_ip, disposition
ORDER BY occurrences DESC;

-- ========== TRENDS TEMPORALES ==========

-- SPF/DKIM trends últimos 30 días
SELECT 
    to_timestamp(date_begin)::date as date,
    domain,
    COUNT(*) as reports,
    SUM(count) as total_emails,
    ROUND(100.0 * SUM(CASE WHEN spf_result = 'pass' THEN count ELSE 0 END) / 
        NULLIF(SUM(count), 0), 2) as spf_pass_pct,
    ROUND(100.0 * SUM(CASE WHEN dkim_result = 'pass' THEN count ELSE 0 END) / 
        NULLIF(SUM(count), 0), 2) as dkim_pass_pct
FROM dmarc_reports
WHERE date_begin > EXTRACT(EPOCH FROM NOW() - INTERVAL '30 days')::bigint
GROUP BY to_timestamp(date_begin)::date, domain
ORDER BY date DESC, domain;

-- Emails procesados por hora (últimas 24h)
SELECT 
    to_timestamp(date_begin)::date || ' ' || 
    LPAD(EXTRACT(HOUR FROM to_timestamp(date_begin))::text, 2, '0') || ':00' as hour,
    domain,
    SUM(count) as emails,
    SUM(CASE WHEN spf_result = 'fail' THEN count ELSE 0 END) as spf_fails,
    SUM(CASE WHEN dkim_result = 'fail' THEN count ELSE 0 END) as dkim_fails
FROM dmarc_reports
WHERE date_begin > EXTRACT(EPOCH FROM NOW() - INTERVAL '1 day')::bigint
GROUP BY hour, domain
ORDER BY hour DESC;

-- ========== AUDITORÍA ==========

-- Reportes duplicados (mismo report_id)
SELECT 
    report_id,
    COUNT(*) as occurrences,
    STRING_AGG(id::text, ', ') as ids
FROM dmarc_reports
GROUP BY report_id
HAVING COUNT(*) > 1;

-- Reportes insertados hoy
SELECT 
    domain,
    COUNT(*) as report_count,
    MIN(created_at) as first_inserted,
    MAX(created_at) as last_inserted
FROM dmarc_reports
WHERE created_at::date = CURRENT_DATE
GROUP BY domain
ORDER BY last_inserted DESC;

-- Historial de cambios de policy
SELECT DISTINCT
    domain,
    policy_p,
    policy_adkim,
    policy_aspf,
    policy_pct,
    MIN(to_timestamp(date_begin)) as first_seen,
    MAX(to_timestamp(date_begin)) as last_seen
FROM dmarc_reports
GROUP BY domain, policy_p, policy_adkim, policy_aspf, policy_pct
ORDER BY domain, last_seen DESC;

-- ========== PERFORMANCE ==========

-- Tabla más grande
SELECT 
    schemaname,
    tablename,
    ROUND(pg_total_relation_size(schemaname||'.'||tablename) / 1024 / 1024, 2) as size_mb
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Índices no usados
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_scan as index_scans,
    idx_tup_read as tuples_read,
    idx_tup_fetch as tuples_fetched
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY idx_scan ASC;

-- ========== MANTENIMIENTO ==========

-- Vacuum analyze (liberar espacio)
VACUUM ANALYZE;

-- Contar registros
SELECT 
    'dmarc_reports' as table_name,
    COUNT(*) as rows
FROM dmarc_reports
UNION ALL
SELECT 'dmarc_alerts', COUNT(*) FROM dmarc_alerts
UNION ALL
SELECT 'dmarc_dkim_results', COUNT(*) FROM dmarc_dkim_results
UNION ALL
SELECT 'dmarc_spf_results', COUNT(*) FROM dmarc_spf_results;

-- ========== EXPORTAR DATOS ==========

-- Exportar a CSV (ejecutar desde bash)
-- COPY (
--   SELECT * FROM dmarc_reports WHERE domain = 'yourdomain.com'
-- ) TO '/tmp/dmarc_export.csv' WITH CSV HEADER;

-- Limpiar alertas antiguas (>90 días)
DELETE FROM dmarc_alerts
WHERE created_at < NOW() - INTERVAL '90 days';

-- Limpiar reportes muy antiguos (>180 días)
-- DELETE FROM dmarc_reports
-- WHERE date_begin < EXTRACT(EPOCH FROM NOW() - INTERVAL '180 days')::bigint;

-- ========== DASHBOARD DATA ==========

-- Query lista para dashboards
SELECT 
    domain,
    COUNT(*) as total_reports,
    SUM(count) as total_emails,
    ROUND(100.0 * SUM(CASE WHEN spf_result = 'pass' THEN count ELSE 0 END) / 
        NULLIF(SUM(count), 0), 2) as spf_pass_pct,
    ROUND(100.0 * SUM(CASE WHEN dkim_result = 'pass' THEN count ELSE 0 END) / 
        NULLIF(SUM(count), 0), 2) as dkim_pass_pct,
    SUM(CASE WHEN disposition = 'none' THEN count ELSE 0 END) as accepted_emails,
    SUM(CASE WHEN disposition = 'quarantine' THEN count ELSE 0 END) as quarantined_emails,
    SUM(CASE WHEN disposition = 'reject' THEN count ELSE 0 END) as rejected_emails
FROM dmarc_reports
WHERE date_begin > EXTRACT(EPOCH FROM NOW() - INTERVAL '7 days')::bigint
GROUP BY domain
ORDER BY total_emails DESC;
