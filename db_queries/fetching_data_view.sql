CREATE OR REPLACE VIEW cve_data_view AS
SELECT cve.id, 
       cve.source_identifier, 
       cve.published, 
       cve.last_modified, 
       cve.vuln_status,
       array_agg(DISTINCT description.*) AS descriptions,
       array_agg(DISTINCT cvss_metric.*) AS cvss_metrics,
       array_agg(DISTINCT weakness.*) AS weaknesses,
       array_agg(DISTINCT configuration.*) AS configurations,
       array_agg(DISTINCT reference.*) AS references
FROM cve
LEFT JOIN description ON cve.id = description.cve_id
LEFT JOIN cvss_metric ON cve.id = cvss_metric.cve_id
LEFT JOIN weakness ON cve.id = weakness.cve_id
LEFT JOIN configuration ON cve.id = configuration.cve_id
LEFT JOIN reference ON cve.id = reference.cve_id
GROUP BY cve.id, 
         cve.source_identifier, 
         cve.published, 
         cve.last_modified, 
         cve.vuln_status;
