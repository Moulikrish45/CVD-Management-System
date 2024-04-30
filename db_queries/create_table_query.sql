CREATE TABLE IF NOT EXISTS cve (
        id VARCHAR(20) PRIMARY KEY,
        source_identifier VARCHAR(100),
        published TIMESTAMP,
        last_modified TIMESTAMP,
        vuln_status VARCHAR(50)
    );

    CREATE TABLE IF NOT EXISTS description (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(20) REFERENCES cve(id),
        lang VARCHAR(5),
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS cvss_metric (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(20) REFERENCES cve(id),
        source VARCHAR(100),
        type VARCHAR(50),
        version VARCHAR(10),
        vector_string VARCHAR(100),
        access_vector VARCHAR(20),
        access_complexity VARCHAR(20),
        authentication VARCHAR(20),
        confidentiality_impact VARCHAR(20),
        integrity_impact VARCHAR(20),
        availability_impact VARCHAR(20),
        base_score NUMERIC(5, 2),
        base_severity VARCHAR(20),
        exploitability_score NUMERIC(5, 2),
        impact_score NUMERIC(5, 2),
        ac_insuf_info TEXT,
        obtain_all_privilege TEXT,
        obtain_user_privilege TEXT,
        obtain_other_privilege TEXT,
        user_interaction_required TEXT
    );

    CREATE TABLE IF NOT EXISTS weakness (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(20) REFERENCES cve(id),
        source VARCHAR(100),
        type VARCHAR(50),
        description TEXT
    );

    CREATE TABLE IF NOT EXISTS configuration (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(20) REFERENCES cve(id),
        operator VARCHAR(5),
        negate TEXT,
        cpe_match_criteria_id VARCHAR(50),
        vulnerable TEXT,
        criteria TEXT
    );

    CREATE TABLE IF NOT EXISTS reference (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(20) REFERENCES cve(id),
        url TEXT,
        source VARCHAR(100)
    );
