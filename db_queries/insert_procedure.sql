CREATE OR REPLACE FUNCTION insert_cve_data(json_data JSONB) RETURNS VOID AS $$
DECLARE
    cve_id VARCHAR(20);
    cve_data JSONB;
    cve_records JSONB;
    cve_record JSONB;
    description_record JSONB;
    metric_record JSONB;
    weakness_record JSONB;
    config_record JSONB;
    node_record JSONB;
    cpe_record JSONB;
    reference_record JSONB;
BEGIN
    -- Extract vulnerabilities array
    cve_records := json_data->'vulnerabilities';

    -- Loop through each CVE entry
    FOR cve_record IN SELECT * FROM jsonb_array_elements(cve_records) LOOP
        cve_data := cve_record->'cve';

        -- Extract CVE ID
        cve_id := cve_data->>'id';

       -- Insert into cve table
INSERT INTO cve (id, source_identifier, published, last_modified, vuln_status)
VALUES (cve_id, cve_data->>'sourceIdentifier', (cve_data->>'published')::timestamp, (cve_data->>'lastModified')::timestamp, cve_data->>'vulnStatus');


        -- Insert descriptions
        FOR description_record IN SELECT * FROM jsonb_array_elements(cve_data->'descriptions') LOOP
            INSERT INTO description (cve_id, lang, value)
            VALUES (cve_id, description_record->>'lang', description_record->>'value');
        END LOOP;

        -- Insert metrics
        FOR metric_record IN SELECT * FROM jsonb_array_elements(cve_data->'metrics'->'cvssMetricV2') LOOP
            INSERT INTO cvss_metric (cve_id, source, type, version, vector_string, access_vector, access_complexity, authentication, confidentiality_impact, integrity_impact, availability_impact, base_score, base_severity, exploitability_score, impact_score, ac_insuf_info, obtain_all_privilege, obtain_user_privilege, obtain_other_privilege, user_interaction_required)
            VALUES (cve_id, metric_record->>'source', metric_record->>'type', (metric_record->'cvssData'->>'version')::VARCHAR, metric_record->'cvssData'->>'vectorString', metric_record->'cvssData'->>'accessVector', metric_record->'cvssData'->>'accessComplexity', metric_record->'cvssData'->>'authentication', metric_record->'cvssData'->>'confidentialityImpact', metric_record->'cvssData'->>'integrityImpact', metric_record->'cvssData'->>'availabilityImpact', (metric_record->'cvssData'->>'baseScore')::NUMERIC, metric_record->>'baseSeverity', (metric_record->>'exploitabilityScore')::NUMERIC, (metric_record->>'impactScore')::NUMERIC, metric_record->>'acInsufInfo', metric_record->>'obtainAllPrivilege', metric_record->>'obtainUserPrivilege', metric_record->>'obtainOtherPrivilege', metric_record->>'userInteractionRequired');
        END LOOP;

        -- Insert weaknesses
        FOR weakness_record IN SELECT * FROM jsonb_array_elements(cve_data->'weaknesses') LOOP
            INSERT INTO weakness (cve_id, source, type, description)
            VALUES (cve_id, weakness_record->>'source', weakness_record->>'type', (weakness_record->'description'->0->>'value')::TEXT);
        END LOOP;

        -- Insert configurations
        FOR config_record IN SELECT * FROM jsonb_array_elements(cve_data->'configurations') LOOP
            FOR node_record IN SELECT * FROM jsonb_array_elements(config_record->'nodes') LOOP
                FOR cpe_record IN SELECT * FROM jsonb_array_elements(node_record->'cpeMatch') LOOP
                    INSERT INTO configuration (cve_id, operator, negate, cpe_match_criteria_id, vulnerable, criteria)
                    VALUES (cve_id, node_record->>'operator', (node_record->>'negate')::BOOLEAN, cpe_record->>'matchCriteriaId', (cpe_record->>'vulnerable')::BOOLEAN, cpe_record->>'criteria');
                END LOOP;
            END LOOP;
        END LOOP;

        -- Insert references
        FOR reference_record IN SELECT * FROM jsonb_array_elements(cve_data->'references') LOOP
            INSERT INTO reference (cve_id, url, source)
            VALUES (cve_id, reference_record->>'url', reference_record->>'source');
        END LOOP;
    END LOOP;
END;
$$ LANGUAGE plpgsql;
