CREATE TABLE IF NOT EXISTS domains (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    organization VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    last_scan TIMESTAMP,
    scan_interval_hours INTEGER NOT NULL DEFAULT 24,
    include_subdomains BOOLEAN NOT NULL DEFAULT TRUE,
    max_live_hosts INTEGER,
    max_wayback_urls INTEGER,
    max_js_assets INTEGER,
    enable_gau BOOLEAN,
    enable_katana BOOLEAN DEFAULT TRUE,
    enable_hakrawler BOOLEAN DEFAULT TRUE,
    enable_js_analysis BOOLEAN,
    enable_ffuf BOOLEAN,
    enable_nuclei BOOLEAN,
    enable_screenshots BOOLEAN DEFAULT TRUE,
    enable_port_scan BOOLEAN,
    enable_search_intelligence BOOLEAN
);

CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE domains ADD COLUMN IF NOT EXISTS include_subdomains BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS max_live_hosts INTEGER;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS max_wayback_urls INTEGER;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS max_js_assets INTEGER;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_gau BOOLEAN;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_katana BOOLEAN DEFAULT TRUE;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_hakrawler BOOLEAN DEFAULT TRUE;
ALTER TABLE domains ALTER COLUMN enable_katana SET DEFAULT TRUE;
ALTER TABLE domains ALTER COLUMN enable_hakrawler SET DEFAULT TRUE;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_js_analysis BOOLEAN;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_ffuf BOOLEAN;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_nuclei BOOLEAN;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_screenshots BOOLEAN DEFAULT TRUE;
ALTER TABLE domains ALTER COLUMN enable_screenshots SET DEFAULT TRUE;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_port_scan BOOLEAN;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_search_intelligence BOOLEAN;

CREATE TABLE IF NOT EXISTS subdomains (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    subdomain VARCHAR(255) NOT NULL,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_resolved BOOLEAN NOT NULL DEFAULT FALSE,
    ip_addresses TEXT[] NOT NULL DEFAULT '{}',
    UNIQUE(domain_id, subdomain)
);

CREATE TABLE IF NOT EXISTS subdomain_sources (
    id SERIAL PRIMARY KEY,
    subdomain_id INTEGER NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
    source VARCHAR(80) NOT NULL,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE(subdomain_id, source)
);

CREATE TABLE IF NOT EXISTS infrastructure_ips (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    ip_version SMALLINT NOT NULL,
    ptr_name TEXT,
    asn TEXT,
    asn_org TEXT,
    provider TEXT,
    classification VARCHAR(30) NOT NULL DEFAULT 'unknown',
    scan_eligible BOOLEAN NOT NULL DEFAULT TRUE,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, ip_address)
);

CREATE TABLE IF NOT EXISTS infrastructure_ip_subdomains (
    ip_asset_id BIGINT NOT NULL REFERENCES infrastructure_ips(id) ON DELETE CASCADE,
    subdomain_id INTEGER NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(ip_asset_id, subdomain_id)
);

CREATE TABLE IF NOT EXISTS dns_records (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    subdomain_id INTEGER NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
    record_type VARCHAR(12) NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER,
    is_current BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(subdomain_id, record_type, value)
);

CREATE TABLE IF NOT EXISTS port_scan_jobs (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    ip_asset_id BIGINT NOT NULL REFERENCES infrastructure_ips(id) ON DELETE CASCADE,
    profile VARCHAR(30) NOT NULL,
    schedule_bucket DATE NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'queued',
    priority INTEGER NOT NULL DEFAULT 50,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 2,
    available_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lease_owner TEXT,
    lease_expires_at TIMESTAMP,
    heartbeat_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error TEXT,
    result_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip_asset_id, profile, schedule_bucket)
);

CREATE TABLE IF NOT EXISTS network_services (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    ip_asset_id BIGINT NOT NULL REFERENCES infrastructure_ips(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol VARCHAR(8) NOT NULL DEFAULT 'tcp',
    state VARCHAR(20) NOT NULL DEFAULT 'open',
    service TEXT,
    product TEXT,
    version TEXT,
    extra_info TEXT,
    banner TEXT,
    tls JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_scanned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP,
    UNIQUE(ip_asset_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS shodan_jobs (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    ip_asset_id BIGINT REFERENCES infrastructure_ips(id) ON DELETE CASCADE,
    job_type VARCHAR(20) NOT NULL CHECK (job_type IN ('domain', 'host')),
    dedupe_key TEXT NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'queued',
    priority INTEGER NOT NULL DEFAULT 50,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    available_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lease_owner TEXT,
    lease_expires_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error TEXT,
    result_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS search_intel_jobs (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    dedupe_key TEXT NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'queued',
    priority INTEGER NOT NULL DEFAULT 50,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    available_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lease_owner TEXT,
    lease_expires_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error TEXT,
    result_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS search_intel_runs (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    provider VARCHAR(30) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'running',
    query_count INTEGER NOT NULL DEFAULT 0,
    result_count INTEGER NOT NULL DEFAULT 0,
    new_result_count INTEGER NOT NULL DEFAULT 0,
    in_scope_count INTEGER NOT NULL DEFAULT 0,
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    error TEXT,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS shodan_domain_snapshots (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    fetched_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    response_hash VARCHAR(64) NOT NULL,
    record_count INTEGER NOT NULL DEFAULT 0,
    subdomain_count INTEGER NOT NULL DEFAULT 0,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS shodan_host_snapshots (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    ip_asset_id BIGINT NOT NULL REFERENCES infrastructure_ips(id) ON DELETE CASCADE,
    fetched_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    shodan_last_update TIMESTAMP,
    fingerprint_hash VARCHAR(64) NOT NULL,
    ports INTEGER[] NOT NULL DEFAULT '{}',
    hostnames TEXT[] NOT NULL DEFAULT '{}',
    tags TEXT[] NOT NULL DEFAULT '{}',
    vulnerabilities TEXT[] NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS live_hosts (
    id SERIAL PRIMARY KEY,
    subdomain_id INTEGER NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
    url VARCHAR(500) NOT NULL UNIQUE,
    port INTEGER,
    protocol VARCHAR(10),
    status_code INTEGER,
    title TEXT,
    webserver TEXT,
    content_length BIGINT,
    fingerprint_hash VARCHAR(64),
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_new BOOLEAN NOT NULL DEFAULT TRUE
);

ALTER TABLE live_hosts ADD COLUMN IF NOT EXISTS webserver TEXT;
ALTER TABLE live_hosts ADD COLUMN IF NOT EXISTS content_length BIGINT;
ALTER TABLE live_hosts ADD COLUMN IF NOT EXISTS fingerprint_hash VARCHAR(64);

DROP VIEW IF EXISTS ai_review_endpoint_queue;

CREATE TABLE IF NOT EXISTS live_host_fingerprints (
    id SERIAL PRIMARY KEY,
    live_host_id INTEGER NOT NULL REFERENCES live_hosts(id) ON DELETE CASCADE,
    fingerprint_hash VARCHAR(64) NOT NULL,
    status_code INTEGER,
    title TEXT,
    webserver TEXT,
    content_length BIGINT,
    technologies JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_current BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(live_host_id, fingerprint_hash)
);

CREATE TABLE IF NOT EXISTS endpoints (
    id SERIAL PRIMARY KEY,
    live_host_id INTEGER NOT NULL REFERENCES live_hosts(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    path_hash VARCHAR(64) NOT NULL,
    method VARCHAR(10) NOT NULL DEFAULT 'GET',
    status_code INTEGER,
    probed_at TIMESTAMP,
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    risk_tags TEXT[] NOT NULL DEFAULT '{}',
    source VARCHAR(50) NOT NULL DEFAULT 'unknown',
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_new BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(live_host_id, path_hash, method, source)
);

ALTER TABLE endpoints ALTER COLUMN path TYPE TEXT;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS path_hash VARCHAR(64);
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS status_code INTEGER;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS probed_at TIMESTAMP;
UPDATE endpoints SET path_hash = encode(digest(path, 'sha256'), 'hex') WHERE path_hash IS NULL OR length(path_hash) <> 64;
ALTER TABLE endpoints ALTER COLUMN path_hash SET NOT NULL;
ALTER TABLE endpoints DROP CONSTRAINT IF EXISTS endpoints_live_host_id_path_method_source_key;
CREATE UNIQUE INDEX IF NOT EXISTS endpoints_live_host_path_hash_method_source_idx
    ON endpoints(live_host_id, path_hash, method, source);

CREATE TABLE IF NOT EXISTS search_intel_results (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    first_run_id BIGINT REFERENCES search_intel_runs(id) ON DELETE SET NULL,
    last_run_id BIGINT REFERENCES search_intel_runs(id) ON DELETE SET NULL,
    endpoint_id INTEGER REFERENCES endpoints(id) ON DELETE SET NULL,
    provider VARCHAR(30) NOT NULL,
    category VARCHAR(40) NOT NULL,
    query TEXT NOT NULL,
    query_hash VARCHAR(64) NOT NULL,
    url TEXT NOT NULL,
    url_hash VARCHAR(64) NOT NULL,
    hostname VARCHAR(255),
    title TEXT,
    snippet TEXT,
    display_link TEXT,
    is_in_scope BOOLEAN NOT NULL DEFAULT FALSE,
    status_code INTEGER,
    risk_tags TEXT[] NOT NULL DEFAULT '{}',
    raw_result JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, query_hash, url_hash)
);

CREATE TABLE IF NOT EXISTS search_intel_run_results (
    run_id BIGINT NOT NULL REFERENCES search_intel_runs(id) ON DELETE CASCADE,
    result_id BIGINT NOT NULL REFERENCES search_intel_results(id) ON DELETE CASCADE,
    rank INTEGER,
    PRIMARY KEY(run_id, result_id)
);

CREATE TABLE IF NOT EXISTS url_parameters (
    id SERIAL PRIMARY KEY,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    param_name TEXT NOT NULL,
    example_value TEXT,
    risk_tags TEXT[] NOT NULL DEFAULT '{}',
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_new BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(endpoint_id, param_name)
);

CREATE TABLE IF NOT EXISTS js_assets (
    id SERIAL PRIMARY KEY,
    live_host_id INTEGER NOT NULL REFERENCES live_hosts(id) ON DELETE CASCADE,
    asset_url TEXT NOT NULL,
    source VARCHAR(50) NOT NULL DEFAULT 'unknown',
    sha256 VARCHAR(64),
    size_bytes BIGINT,
    http_status INTEGER,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_new BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(live_host_id, asset_url)
);

CREATE TABLE IF NOT EXISTS js_analysis_results (
    id SERIAL PRIMARY KEY,
    js_asset_id INTEGER NOT NULL REFERENCES js_assets(id) ON DELETE CASCADE,
    extraction JSONB NOT NULL DEFAULT '{}'::jsonb,
    risk_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    analyzed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(js_asset_id)
);

CREATE TABLE IF NOT EXISTS endpoint_js_references (
    id SERIAL PRIMARY KEY,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    js_asset_id INTEGER NOT NULL REFERENCES js_assets(id) ON DELETE CASCADE,
    found_value TEXT,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(endpoint_id, js_asset_id)
);

CREATE TABLE IF NOT EXISTS credential_leaks (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    live_host_id INTEGER REFERENCES live_hosts(id) ON DELETE SET NULL,
    js_asset_id INTEGER REFERENCES js_assets(id) ON DELETE SET NULL,
    detector_name TEXT NOT NULL,
    detector_type TEXT,
    decoder_name TEXT,
    source_type TEXT NOT NULL DEFAULT 'js_asset',
    source_url TEXT NOT NULL,
    source_file TEXT,
    line_number INTEGER,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    redacted_secret TEXT,
    fingerprint VARCHAR(64) NOT NULL,
    raw_sha256 VARCHAR(64),
    result JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_new BOOLEAN NOT NULL DEFAULT TRUE,
    is_resolved BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE(domain_id, source_url, detector_name, fingerprint)
);

CREATE TABLE IF NOT EXISTS credential_leak_scan_status (
    js_asset_id INTEGER PRIMARY KEY REFERENCES js_assets(id) ON DELETE CASCADE,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    live_host_id INTEGER REFERENCES live_hosts(id) ON DELETE SET NULL,
    asset_url TEXT NOT NULL,
    sha256 VARCHAR(64),
    status VARCHAR(30) NOT NULL DEFAULT 'queued',
    http_status INTEGER,
    findings_count INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    started_at TIMESTAMP,
    scanned_at TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS monitor_targets (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    name VARCHAR(160) NOT NULL,
    start_url TEXT NOT NULL,
    auth_type VARCHAR(30) NOT NULL DEFAULT 'none',
    cookie_secret_ref TEXT,
    login_url TEXT,
    login_email TEXT,
    password_secret_ref TEXT,
    username_selector TEXT,
    password_selector TEXT,
    submit_selector TEXT,
    auth_check_url TEXT,
    auth_check_selector TEXT,
    auth_check_text TEXT,
    auth_failure_text TEXT,
    auth_status VARCHAR(30),
    auth_last_checked_at TIMESTAMP,
    auth_last_error TEXT,
    extra_routes JSONB NOT NULL DEFAULT '[]'::jsonb,
    interval_hours INTEGER NOT NULL DEFAULT 24,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    alert_min_risk VARCHAR(20) NOT NULL DEFAULT 'medium',
    last_run_at TIMESTAMP,
    last_error TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, start_url)
);

CREATE TABLE IF NOT EXISTS monitor_runs (
    id SERIAL PRIMARY KEY,
    monitor_id INTEGER NOT NULL REFERENCES monitor_targets(id) ON DELETE CASCADE,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    status VARCHAR(30) NOT NULL DEFAULT 'running',
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP,
    duration_seconds DOUBLE PRECISION,
    auth_status VARCHAR(30),
    new_items_count INTEGER NOT NULL DEFAULT 0,
    new_events_count INTEGER NOT NULL DEFAULT 0,
    scripts_count INTEGER NOT NULL DEFAULT 0,
    requests_count INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS monitor_intel_items (
    id SERIAL PRIMARY KEY,
    monitor_id INTEGER NOT NULL REFERENCES monitor_targets(id) ON DELETE CASCADE,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    item_type VARCHAR(80) NOT NULL,
    item_key VARCHAR(128) NOT NULL,
    value TEXT NOT NULL,
    risk VARCHAR(20) NOT NULL DEFAULT 'info',
    source_url TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(monitor_id, item_type, item_key)
);

CREATE TABLE IF NOT EXISTS monitor_events (
    id SERIAL PRIMARY KEY,
    run_id INTEGER REFERENCES monitor_runs(id) ON DELETE SET NULL,
    monitor_id INTEGER NOT NULL REFERENCES monitor_targets(id) ON DELETE CASCADE,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    event_type VARCHAR(80) NOT NULL,
    item_type VARCHAR(80) NOT NULL,
    item_key VARCHAR(128) NOT NULL,
    value TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    summary TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    alerted_at TIMESTAMP,
    UNIQUE(monitor_id, event_type, item_key)
);

CREATE TABLE IF NOT EXISTS screenshots (
    id SERIAL PRIMARY KEY,
    live_host_id INTEGER NOT NULL REFERENCES live_hosts(id) ON DELETE CASCADE,
    screenshot_path TEXT NOT NULL,
    sha256 VARCHAR(64),
    file_size BIGINT,
    capture_reason VARCHAR(50) NOT NULL DEFAULT 'new_live_host',
    captured_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(live_host_id, screenshot_path)
);

CREATE TABLE IF NOT EXISTS scan_snapshots (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    scan_started_at TIMESTAMP NOT NULL,
    scan_finished_at TIMESTAMP NOT NULL,
    duration_seconds DOUBLE PRECISION NOT NULL,
    first_run BOOLEAN NOT NULL DEFAULT FALSE,
    totals JSONB NOT NULL DEFAULT '{}'::jsonb,
    new_counts JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS technologies (
    id SERIAL PRIMARY KEY,
    live_host_id INTEGER NOT NULL REFERENCES live_hosts(id) ON DELETE CASCADE,
    technology VARCHAR(100) NOT NULL,
    version VARCHAR(50),
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(live_host_id, technology, version)
);

CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    finding_key VARCHAR(64) NOT NULL UNIQUE,
    finding_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    location TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_new BOOLEAN NOT NULL DEFAULT TRUE,
    is_resolved BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS ffuf_runs (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    live_host_id INTEGER REFERENCES live_hosts(id) ON DELETE CASCADE,
    host_url TEXT NOT NULL,
    scan_lane VARCHAR(50) NOT NULL,
    wordlist_path TEXT NOT NULL,
    wordlist_sha256 VARCHAR(64) NOT NULL,
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'running',
    hits_count INTEGER NOT NULL DEFAULT 0,
    options JSONB NOT NULL DEFAULT '{}'::jsonb,
    error TEXT,
    UNIQUE(live_host_id, scan_lane, wordlist_sha256)
);

CREATE TABLE IF NOT EXISTS ffuf_run_hits (
    id SERIAL PRIMARY KEY,
    ffuf_run_id INTEGER NOT NULL REFERENCES ffuf_runs(id) ON DELETE CASCADE,
    endpoint_id INTEGER REFERENCES endpoints(id) ON DELETE SET NULL,
    url TEXT NOT NULL,
    path TEXT,
    status_code INTEGER,
    content_length INTEGER,
    words INTEGER,
    lines INTEGER,
    redirect_location TEXT,
    result JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ffuf_run_id, url)
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    alert_type VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    sent_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS ai_triage_items (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    source_table VARCHAR(50) NOT NULL,
    source_id INTEGER NOT NULL,
    item_key VARCHAR(64) NOT NULL UNIQUE,
    item_type VARCHAR(80) NOT NULL,
    title TEXT NOT NULL,
    location TEXT NOT NULL,
    priority VARCHAR(20) NOT NULL DEFAULT 'low',
    score INTEGER NOT NULL DEFAULT 0,
    reasons TEXT[] NOT NULL DEFAULT '{}',
    recommended_actions TEXT[] NOT NULL DEFAULT '{}',
    run_profiles TEXT[] NOT NULL DEFAULT '{}',
    alert BOOLEAN NOT NULL DEFAULT FALSE,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS analyst_annotations (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    entity_type VARCHAR(60) NOT NULL,
    entity_id INTEGER,
    entity_key VARCHAR(128) NOT NULL,
    location TEXT,
    status VARCHAR(40) NOT NULL DEFAULT 'new',
    severity_override VARCHAR(20),
    tags TEXT[] NOT NULL DEFAULT '{}',
    bookmarked BOOLEAN NOT NULL DEFAULT FALSE,
    notes TEXT,
    assigned_to VARCHAR(120),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(entity_type, entity_key)
);

CREATE TABLE IF NOT EXISTS asset_events (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    event_key VARCHAR(128) NOT NULL UNIQUE,
    event_type VARCHAR(80) NOT NULL,
    entity_type VARCHAR(60) NOT NULL,
    entity_id INTEGER,
    location TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS asset_risk_scores (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    entity_type VARCHAR(60) NOT NULL,
    entity_id INTEGER,
    entity_key VARCHAR(128) NOT NULL,
    location TEXT NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    priority VARCHAR(20) NOT NULL DEFAULT 'low',
    reasons TEXT[] NOT NULL DEFAULT '{}',
    recommended_actions TEXT[] NOT NULL DEFAULT '{}',
    run_profiles TEXT[] NOT NULL DEFAULT '{}',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(entity_type, entity_key)
);

CREATE TABLE IF NOT EXISTS cloud_assets (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    provider VARCHAR(80) NOT NULL,
    asset_type VARCHAR(80) NOT NULL,
    identifier TEXT NOT NULL,
    location TEXT NOT NULL,
    source VARCHAR(80) NOT NULL DEFAULT 'recon',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, provider, asset_type, identifier)
);

CREATE TABLE IF NOT EXISTS scope_rules (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    rule_type VARCHAR(30) NOT NULL DEFAULT 'exclude',
    pattern TEXT NOT NULL,
    reason TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, rule_type, pattern)
);

CREATE TABLE IF NOT EXISTS auth_profiles (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    name VARCHAR(120) NOT NULL,
    profile_type VARCHAR(40) NOT NULL DEFAULT 'cookie',
    host_pattern TEXT NOT NULL DEFAULT '*',
    header_name VARCHAR(120),
    secret_ref TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, name)
);

CREATE TABLE IF NOT EXISTS evidence_packs (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    source_table VARCHAR(60) NOT NULL,
    source_id INTEGER,
    evidence_key VARCHAR(128) NOT NULL UNIQUE,
    title TEXT NOT NULL,
    location TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    summary TEXT,
    request JSONB NOT NULL DEFAULT '{}'::jsonb,
    response JSONB NOT NULL DEFAULT '{}'::jsonb,
    artifacts JSONB NOT NULL DEFAULT '[]'::jsonb,
    raw JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS validation_queue (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    evidence_pack_id INTEGER REFERENCES evidence_packs(id) ON DELETE SET NULL,
    source_table VARCHAR(60) NOT NULL,
    source_id INTEGER,
    queue_key VARCHAR(128) UNIQUE,
    status VARCHAR(40) NOT NULL DEFAULT 'needs_validation',
    priority VARCHAR(20) NOT NULL DEFAULT 'medium',
    location TEXT NOT NULL,
    validation_steps TEXT[] NOT NULL DEFAULT '{}',
    notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attack_playbooks (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    source_table VARCHAR(60) NOT NULL,
    source_id INTEGER,
    playbook_key VARCHAR(128) NOT NULL UNIQUE,
    target_url TEXT NOT NULL,
    owasp_category VARCHAR(100) NOT NULL,
    check_type VARCHAR(80) NOT NULL,
    priority VARCHAR(20) NOT NULL DEFAULT 'medium',
    confidence VARCHAR(30) NOT NULL DEFAULT 'candidate',
    reasons TEXT[] NOT NULL DEFAULT '{}',
    validation_steps TEXT[] NOT NULL DEFAULT '{}',
    stop_conditions TEXT[] NOT NULL DEFAULT '{}',
    safety_notes TEXT[] NOT NULL DEFAULT '{}',
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(40) NOT NULL DEFAULT 'queued',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS bug_jobs (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    asset_type VARCHAR(60) NOT NULL,
    asset_value TEXT NOT NULL,
    job_type VARCHAR(80) NOT NULL,
    job_category VARCHAR(50) NOT NULL DEFAULT 'input_workflow',
    priority INTEGER NOT NULL DEFAULT 50,
    status VARCHAR(30) NOT NULL DEFAULT 'queued',
    scope_ok BOOLEAN NOT NULL DEFAULT TRUE,
    source_table VARCHAR(60),
    source_id INTEGER,
    source_observed_at TIMESTAMP,
    job_key VARCHAR(128) NOT NULL UNIQUE,
    hypothesis TEXT,
    safety_notes TEXT[] NOT NULL DEFAULT '{}',
    required_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    prompt_path TEXT,
    codex_output_path TEXT,
    result_summary TEXT,
    finding_status VARCHAR(30),
    confidence INTEGER,
    outcome_class VARCHAR(40),
    vulnerability_class VARCHAR(160),
    manual_review_priority VARCHAR(20),
    alert_signals TEXT[] NOT NULL DEFAULT '{}',
    codex_alerted_at TIMESTAMP,
    codex_alert_kind VARCHAR(30),
    codex_alert_key VARCHAR(64),
    codex_alert_suppressed_reason TEXT,
    vpn_failover_attempted BOOLEAN NOT NULL DEFAULT FALSE,
    vpn_failover_succeeded BOOLEAN NOT NULL DEFAULT FALSE,
    vpn_failover_reason TEXT,
    vpn_egress_before VARCHAR(64),
    vpn_egress_after VARCHAR(64),
    vpn_retry_output_path TEXT,
    vpn_failover_at TIMESTAMP,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 2,
    error TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hunt_runs (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    mode VARCHAR(20) NOT NULL CHECK (mode IN ('one_time', 'continuous')),
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused')),
    scope_confirmed_at TIMESTAMP NOT NULL,
    source_window_days INTEGER NOT NULL DEFAULT 30 CHECK (source_window_days BETWEEN 1 AND 30),
    max_jobs_per_cycle INTEGER NOT NULL DEFAULT 24 CHECK (max_jobs_per_cycle BETWEEN 1 AND 60),
    application_context TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_refresh_at TIMESTAMP,
    last_snapshot_id INTEGER,
    signal_summary JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_error TEXT
);

CREATE TABLE IF NOT EXISTS hunt_run_jobs (
    run_id BIGINT NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
    job_id BIGINT NOT NULL REFERENCES bug_jobs(id) ON DELETE CASCADE,
    family VARCHAR(8) NOT NULL,
    linked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (run_id, job_id)
);

CREATE TABLE IF NOT EXISTS hunt_credentials (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    alias VARCHAR(80) NOT NULL,
    role VARCHAR(100) NOT NULL DEFAULT '',
    tenant VARCHAR(100) NOT NULL DEFAULT '',
    host VARCHAR(255) NOT NULL,
    credential_type VARCHAR(12) NOT NULL CHECK (credential_type IN ('cookie', 'bearer', 'header')),
    header_name VARCHAR(80) NOT NULL,
    secret_file VARCHAR(40) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, alias)
);

CREATE TABLE IF NOT EXISTS hunt_run_credentials (
    run_id BIGINT NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
    credential_id BIGINT NOT NULL REFERENCES hunt_credentials(id) ON DELETE CASCADE,
    PRIMARY KEY (run_id, credential_id)
);

CREATE INDEX IF NOT EXISTS idx_bug_jobs_hunt_recent
    ON bug_jobs(domain_id, source_observed_at DESC, priority DESC)
    WHERE scope_ok = TRUE AND priority >= 90
      AND status IN ('queued', 'curation_pending', 'running', 'done');
CREATE INDEX IF NOT EXISTS idx_bug_jobs_hunt_type_recent
    ON bug_jobs(domain_id, job_type, source_observed_at DESC, priority DESC)
    WHERE scope_ok = TRUE AND priority >= 90
      AND status IN ('queued', 'curation_pending', 'running', 'done');
CREATE INDEX IF NOT EXISTS idx_hunt_runs_active ON hunt_runs(status, mode, last_refresh_at) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_hunt_runs_domain ON hunt_runs(domain_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_run_jobs_family ON hunt_run_jobs(run_id, family);
CREATE INDEX IF NOT EXISTS idx_hunt_run_jobs_job ON hunt_run_jobs(job_id);

CREATE TABLE IF NOT EXISTS bug_job_curation_runs (
    id BIGSERIAL PRIMARY KEY,
    status VARCHAR(30) NOT NULL DEFAULT 'running',
    dry_run BOOLEAN NOT NULL DEFAULT FALSE,
    candidates_considered INTEGER NOT NULL DEFAULT 0,
    jobs_approved INTEGER NOT NULL DEFAULT 0,
    jobs_deferred INTEGER NOT NULL DEFAULT 0,
    jobs_pending_ai INTEGER NOT NULL DEFAULT 0,
    ai_candidates_reviewed INTEGER NOT NULL DEFAULT 0,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    error TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS bug_job_curation_decisions (
    bug_job_id BIGINT PRIMARY KEY REFERENCES bug_jobs(id) ON DELETE CASCADE,
    run_id BIGINT REFERENCES bug_job_curation_runs(id) ON DELETE SET NULL,
    decision VARCHAR(30) NOT NULL,
    score INTEGER NOT NULL,
    reason TEXT NOT NULL,
    decided_by VARCHAR(30) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    decided_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS delta_intelligence_runs (
    id BIGSERIAL PRIMARY KEY,
    window_started_at TIMESTAMP NOT NULL,
    window_finished_at TIMESTAMP NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'running',
    domains_considered INTEGER NOT NULL DEFAULT 0,
    jobs_enqueued INTEGER NOT NULL DEFAULT 0,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    error TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_delta_intelligence_runs_window
    ON delta_intelligence_runs(status, window_finished_at DESC);

CREATE TABLE IF NOT EXISTS ai_assistant_queries (
    id BIGSERIAL PRIMARY KEY,
    thread_id UUID NOT NULL,
    domain_id INTEGER REFERENCES domains(id) ON DELETE SET NULL,
    mode VARCHAR(30) NOT NULL DEFAULT 'tab_assistant',
    section VARCHAR(40) NOT NULL DEFAULT 'overview',
    question TEXT NOT NULL,
    selected_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(30) NOT NULL DEFAULT 'queued',
    answer JSONB NOT NULL DEFAULT '{}'::jsonb,
    model VARCHAR(120),
    prompt_path TEXT,
    output_path TEXT,
    error TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 2,
    available_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS authz_observations (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    bug_job_id BIGINT REFERENCES bug_jobs(id) ON DELETE SET NULL,
    endpoint TEXT NOT NULL,
    method VARCHAR(12) NOT NULL DEFAULT 'GET',
    actor TEXT NOT NULL,
    object_owner TEXT,
    status_code INTEGER,
    response_hash VARCHAR(64),
    content_length INTEGER,
    sensitive_keywords TEXT[] NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS active_hunt_results (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    run_id VARCHAR(120) NOT NULL,
    scope TEXT NOT NULL,
    check_type VARCHAR(80) NOT NULL,
    target_url TEXT NOT NULL,
    source_url TEXT,
    parameter_name TEXT,
    http_status INTEGER,
    finding VARCHAR(120),
    confidence VARCHAR(30) NOT NULL DEFAULT 'info',
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    request JSONB NOT NULL DEFAULT '{}'::jsonb,
    response JSONB NOT NULL DEFAULT '{}'::jsonb,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, run_id, check_type, target_url)
);

CREATE TABLE IF NOT EXISTS api_surfaces (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    live_host_id INTEGER REFERENCES live_hosts(id) ON DELETE CASCADE,
    surface_type VARCHAR(40) NOT NULL,
    location TEXT NOT NULL,
    source VARCHAR(80) NOT NULL DEFAULT 'recon',
    status_code INTEGER,
    auth_required BOOLEAN,
    schema_url TEXT,
    methods TEXT[] NOT NULL DEFAULT '{}',
    operations_count INTEGER NOT NULL DEFAULT 0,
    risk_flags TEXT[] NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, surface_type, location)
);

CREATE INDEX IF NOT EXISTS idx_domains_active ON domains(active);
CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_last_seen ON subdomains(last_seen);
CREATE INDEX IF NOT EXISTS idx_subdomains_first_seen ON subdomains(first_seen);
CREATE INDEX IF NOT EXISTS idx_subdomain_sources_subdomain ON subdomain_sources(subdomain_id);
CREATE INDEX IF NOT EXISTS idx_subdomain_sources_source ON subdomain_sources(source);
CREATE INDEX IF NOT EXISTS idx_infrastructure_ips_domain ON infrastructure_ips(domain_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_infrastructure_ips_classification ON infrastructure_ips(classification, scan_eligible);
CREATE INDEX IF NOT EXISTS idx_infrastructure_ip_subdomains_subdomain ON infrastructure_ip_subdomains(subdomain_id);
CREATE INDEX IF NOT EXISTS idx_dns_records_domain_current ON dns_records(domain_id, is_current, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_dns_records_subdomain_type ON dns_records(subdomain_id, record_type, is_current);
CREATE INDEX IF NOT EXISTS idx_port_scan_jobs_claim ON port_scan_jobs(status, available_at, priority DESC, created_at);
CREATE INDEX IF NOT EXISTS idx_port_scan_jobs_lease ON port_scan_jobs(status, lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_port_scan_jobs_domain ON port_scan_jobs(domain_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_network_services_domain_state ON network_services(domain_id, state, port);
CREATE INDEX IF NOT EXISTS idx_network_services_ip_state ON network_services(ip_asset_id, state, port);
CREATE INDEX IF NOT EXISTS idx_shodan_jobs_claim ON shodan_jobs(status, available_at, priority DESC, created_at);
CREATE INDEX IF NOT EXISTS idx_shodan_jobs_domain ON shodan_jobs(domain_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_search_intel_jobs_claim ON search_intel_jobs(status, available_at, priority DESC, created_at);
CREATE INDEX IF NOT EXISTS idx_search_intel_runs_domain ON search_intel_runs(domain_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_search_intel_results_domain_seen ON search_intel_results(domain_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_search_intel_results_category ON search_intel_results(category, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_search_intel_results_scope ON search_intel_results(is_in_scope, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_search_intel_run_results_run ON search_intel_run_results(run_id, rank);
CREATE INDEX IF NOT EXISTS idx_shodan_domain_snapshots_domain ON shodan_domain_snapshots(domain_id, fetched_at DESC);
CREATE INDEX IF NOT EXISTS idx_shodan_host_snapshots_ip ON shodan_host_snapshots(ip_asset_id, fetched_at DESC);
CREATE INDEX IF NOT EXISTS idx_live_hosts_subdomain ON live_hosts(subdomain_id);
CREATE INDEX IF NOT EXISTS idx_live_hosts_last_seen ON live_hosts(last_seen);
CREATE INDEX IF NOT EXISTS idx_live_hosts_first_seen ON live_hosts(first_seen);
CREATE INDEX IF NOT EXISTS idx_live_hosts_status_code ON live_hosts(status_code);
CREATE INDEX IF NOT EXISTS idx_live_hosts_fingerprint_hash ON live_hosts(fingerprint_hash);
CREATE INDEX IF NOT EXISTS idx_fingerprints_live_host_current ON live_host_fingerprints(live_host_id, is_current);
CREATE INDEX IF NOT EXISTS idx_fingerprints_last_seen ON live_host_fingerprints(last_seen);
CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(live_host_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_first_seen ON endpoints(first_seen);
CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints(last_seen);
CREATE INDEX IF NOT EXISTS idx_endpoints_status_code ON endpoints(status_code);
CREATE INDEX IF NOT EXISTS idx_endpoints_source ON endpoints(source);
CREATE INDEX IF NOT EXISTS idx_url_parameters_endpoint ON url_parameters(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_url_parameters_last_seen_desc ON url_parameters(last_seen DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_url_parameters_risk_tags ON url_parameters USING GIN (risk_tags);
CREATE INDEX IF NOT EXISTS idx_endpoints_risk_tags ON endpoints USING GIN (risk_tags);
CREATE INDEX IF NOT EXISTS idx_js_assets_host ON js_assets(live_host_id);
CREATE INDEX IF NOT EXISTS idx_js_assets_first_seen ON js_assets(first_seen);
CREATE INDEX IF NOT EXISTS idx_js_assets_last_seen ON js_assets(last_seen);
CREATE INDEX IF NOT EXISTS idx_endpoint_js_references_endpoint ON endpoint_js_references(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_js_references_asset ON endpoint_js_references(js_asset_id);
CREATE INDEX IF NOT EXISTS idx_credential_leaks_domain_seen ON credential_leaks(domain_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_credential_leaks_detector_seen ON credential_leaks(detector_name, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_credential_leaks_verified_seen ON credential_leaks(verified, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_credential_leak_scan_status_domain_status ON credential_leak_scan_status(domain_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_credential_leak_scan_status_scanned ON credential_leak_scan_status(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_monitor_targets_due ON monitor_targets(enabled, last_run_at, interval_hours);
CREATE INDEX IF NOT EXISTS idx_monitor_targets_domain ON monitor_targets(domain_id, enabled);
CREATE INDEX IF NOT EXISTS idx_monitor_runs_monitor_started ON monitor_runs(monitor_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_monitor_runs_domain_started ON monitor_runs(domain_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_monitor_intel_domain_type ON monitor_intel_items(domain_id, item_type, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_monitor_events_domain_seen ON monitor_events(domain_id, severity, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_monitor_events_run_seen ON monitor_events(run_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_monitor_events_monitor_seen ON monitor_events(monitor_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_screenshots_live_host ON screenshots(live_host_id);
CREATE INDEX IF NOT EXISTS idx_screenshots_captured_at ON screenshots(captured_at);
CREATE INDEX IF NOT EXISTS idx_scan_snapshots_domain ON scan_snapshots(domain_id, scan_finished_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_is_new ON findings(is_new);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen);
CREATE INDEX IF NOT EXISTS idx_findings_domain_severity_seen ON findings(domain_id, severity, last_seen DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_findings_review_leads ON findings(domain_id, last_seen DESC) WHERE is_resolved = FALSE AND finding_type IN ('interesting_exposed_path','interesting_open_port','js_dom_xss_candidate','js_secret_like_strings');
CREATE INDEX IF NOT EXISTS idx_validation_queue_finding_lookup ON validation_queue(finding_id, updated_at DESC) WHERE finding_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_validation_queue_promoted_finding ON validation_queue(finding_id, updated_at DESC) WHERE status IN ('confirmed', 'validated') AND finding_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ffuf_runs_domain ON ffuf_runs(domain_id);
CREATE INDEX IF NOT EXISTS idx_ffuf_runs_live_host ON ffuf_runs(live_host_id);
CREATE INDEX IF NOT EXISTS idx_ffuf_runs_status ON ffuf_runs(status);
CREATE INDEX IF NOT EXISTS idx_ffuf_runs_queue_worker_status ON ffuf_runs(status, (options->>'queue_worker'), started_at);
CREATE INDEX IF NOT EXISTS idx_ffuf_run_hits_run ON ffuf_run_hits(ffuf_run_id);
CREATE INDEX IF NOT EXISTS idx_ffuf_run_hits_endpoint ON ffuf_run_hits(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_ffuf_run_hits_status ON ffuf_run_hits(status_code);
CREATE INDEX IF NOT EXISTS idx_ffuf_run_hits_run_status ON ffuf_run_hits(ffuf_run_id, status_code);
CREATE INDEX IF NOT EXISTS idx_ffuf_run_hits_run_size ON ffuf_run_hits(ffuf_run_id, content_length);
CREATE INDEX IF NOT EXISTS idx_ffuf_run_hits_run_words ON ffuf_run_hits(ffuf_run_id, words);
CREATE INDEX IF NOT EXISTS idx_ai_triage_domain_priority ON ai_triage_items(domain_id, priority, score DESC, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_ai_triage_alert ON ai_triage_items(alert, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_annotations_domain_status ON analyst_annotations(domain_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_annotations_tags ON analyst_annotations USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_asset_events_domain_seen ON asset_events(domain_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_asset_events_type ON asset_events(event_type, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_risk_scores_domain_priority ON asset_risk_scores(domain_id, priority, score DESC, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_cloud_assets_domain_provider ON cloud_assets(domain_id, provider, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_scope_rules_domain ON scope_rules(domain_id, enabled);
CREATE INDEX IF NOT EXISTS idx_auth_profiles_domain ON auth_profiles(domain_id, enabled);
CREATE INDEX IF NOT EXISTS idx_evidence_packs_domain ON evidence_packs(domain_id, severity, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_packs_source_lookup ON evidence_packs(domain_id, source_table, source_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_validation_queue_domain_status ON validation_queue(domain_id, status, priority, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_validation_queue_source_lookup ON validation_queue(domain_id, source_table, source_id, updated_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS validation_queue_queue_key_uq ON validation_queue(queue_key);
CREATE INDEX IF NOT EXISTS idx_attack_playbooks_domain_priority ON attack_playbooks(domain_id, status, priority, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_playbooks_check_type ON attack_playbooks(check_type, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_bug_jobs_claim ON bug_jobs(status, scope_ok, priority DESC, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_bug_jobs_domain_status ON bug_jobs(domain_id, status, priority DESC, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_bug_jobs_type_status ON bug_jobs(job_type, status, priority DESC, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_bug_jobs_category_claim ON bug_jobs(job_category, status, source_observed_at DESC, priority DESC);
CREATE INDEX IF NOT EXISTS idx_bug_jobs_roi ON bug_jobs(finished_at DESC, job_category, outcome_class) WHERE status = 'done';
CREATE INDEX IF NOT EXISTS idx_bug_jobs_worker_recent ON bug_jobs(started_at DESC, job_category, job_type) WHERE started_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_bug_jobs_worker_analytics_v1
    ON bug_jobs(started_at DESC, job_category, job_type, domain_id)
    INCLUDE (status, outcome_class, finding_status, finished_at, codex_alert_kind,
             vpn_failover_attempted, vpn_failover_succeeded, manual_review_priority)
    WHERE started_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_bug_jobs_codex_alert_key ON bug_jobs(codex_alert_key, codex_alerted_at DESC) WHERE codex_alert_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_bug_jobs_vpn_failover_at ON bug_jobs(vpn_failover_at DESC) WHERE vpn_failover_attempted;
CREATE INDEX IF NOT EXISTS idx_bug_job_curation_decision ON bug_job_curation_decisions(decision, score DESC, decided_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_assistant_queries_claim ON ai_assistant_queries(status, available_at, created_at);
CREATE INDEX IF NOT EXISTS idx_ai_assistant_queries_thread ON ai_assistant_queries(thread_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ai_assistant_queries_domain ON ai_assistant_queries(domain_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_authz_observations_domain_endpoint ON authz_observations(domain_id, endpoint, method, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_authz_observations_job ON authz_observations(bug_job_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_active_hunt_domain_created ON active_hunt_results(domain_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_active_hunt_finding ON active_hunt_results(finding, confidence, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_active_hunt_check_type ON active_hunt_results(check_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_surfaces_domain_type ON api_surfaces(domain_id, surface_type, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_api_surfaces_risk_flags ON api_surfaces USING GIN (risk_flags);
CREATE INDEX IF NOT EXISTS idx_api_surfaces_confidence ON api_surfaces((metadata->>'confidence'), last_seen DESC);

CREATE OR REPLACE VIEW parameter_risk_clusters AS
SELECT
    up.param_name,
    ARRAY_REMOVE(ARRAY_AGG(DISTINCT tag), NULL) AS risk_tags,
    COUNT(*) AS occurrence_count,
    COUNT(DISTINCT d.id) AS domain_count,
    ARRAY_AGG(DISTINCT d.domain) AS domains,
    MAX(up.last_seen) AS last_seen
FROM url_parameters up
JOIN endpoints e ON e.id = up.endpoint_id
JOIN live_hosts lh ON lh.id = e.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
LEFT JOIN LATERAL UNNEST(up.risk_tags) AS tag ON TRUE
GROUP BY up.param_name
HAVING COUNT(*) > 0;

CREATE OR REPLACE VIEW ai_review_endpoint_queue AS
SELECT
    e.id AS endpoint_id,
    d.domain,
    lh.url AS base_url,
    e.path,
    e.source,
    e.status_code,
    e.probed_at,
    e.risk_tags,
    e.parameters,
    e.first_seen,
    e.last_seen,
    jsonb_build_object(
        'domain', d.domain,
        'base_url', lh.url,
        'path', e.path,
        'source', e.source,
        'status_code', e.status_code,
        'probed_at', e.probed_at,
        'risk_tags', e.risk_tags,
        'parameters', e.parameters,
        'first_seen', e.first_seen,
        'last_seen', e.last_seen
    ) AS review_item
FROM endpoints e
JOIN live_hosts lh ON lh.id = e.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE cardinality(e.risk_tags) > 0
   OR e.first_seen > NOW() - INTERVAL '24 hours';

CREATE OR REPLACE VIEW ai_review_js_queue AS
SELECT
    ja.id AS js_asset_id,
    d.domain,
    ja.asset_url,
    ja.source,
    ja.http_status,
    ja.size_bytes,
    jar.analyzed_at,
    jar.extraction,
    jar.risk_summary,
    jsonb_build_object(
        'domain', d.domain,
        'asset_url', ja.asset_url,
        'source', ja.source,
        'http_status', ja.http_status,
        'size_bytes', ja.size_bytes,
        'analyzed_at', jar.analyzed_at,
        'analysis', jar.extraction,
        'risk_summary', jar.risk_summary
    ) AS review_item
FROM js_analysis_results jar
JOIN js_assets ja ON ja.id = jar.js_asset_id
JOIN live_hosts lh ON lh.id = ja.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE COALESCE(jsonb_array_length(jar.extraction->'tokens_or_secret_like_strings'), 0) > 0
   OR COALESCE(jsonb_array_length(jar.extraction->'dangerous_dom_sinks'), 0) > 0
   OR COALESCE(jsonb_array_length(jar.extraction->'graphql_hints'), 0) > 0
   OR (jar.risk_summary->>'api_url_count')::int > 0;

CREATE OR REPLACE VIEW ai_review_findings_queue AS
SELECT
    f.id AS finding_id,
    d.domain,
    f.finding_type,
    f.severity,
    f.location,
    f.details,
    f.first_seen,
    f.last_seen,
    jsonb_build_object(
        'domain', d.domain,
        'finding_type', f.finding_type,
        'severity', f.severity,
        'location', f.location,
        'details', f.details,
        'first_seen', f.first_seen,
        'last_seen', f.last_seen
    ) AS review_item
FROM findings f
LEFT JOIN domains d ON d.id = f.domain_id
WHERE f.severity IN ('critical', 'high', 'medium')
   OR f.last_seen > NOW() - INTERVAL '24 hours';

CREATE OR REPLACE VIEW ai_triage_queue AS
SELECT
    ati.id,
    d.domain,
    ati.item_type,
    ati.title,
    ati.location,
    ati.priority,
    ati.score,
    ati.reasons,
    ati.recommended_actions,
    ati.run_profiles,
    ati.alert,
    ati.payload,
    ati.first_seen,
    ati.last_seen,
    jsonb_build_object(
        'domain', d.domain,
        'item_type', ati.item_type,
        'title', ati.title,
        'location', ati.location,
        'priority', ati.priority,
        'score', ati.score,
        'reasons', ati.reasons,
        'recommended_actions', ati.recommended_actions,
        'run_profiles', ati.run_profiles,
        'alert', ati.alert,
        'payload', ati.payload,
        'first_seen', ati.first_seen,
        'last_seen', ati.last_seen
    ) AS review_item
FROM ai_triage_items ati
LEFT JOIN domains d ON d.id = ati.domain_id
WHERE ati.resolved = FALSE
ORDER BY
    CASE ati.priority
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END,
    ati.score DESC,
    ati.last_seen DESC;
