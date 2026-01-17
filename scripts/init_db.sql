-- =====================================================
-- Analytical-Intelligence v1 - Database Schema
-- =====================================================

-- Devices table - registered sensor devices
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    hostname TEXT,
    ip TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    -- Optional metadata
    os TEXT,
    role TEXT,
    tags TEXT
);

-- Raw events table - all incoming events stored as-is
CREATE TABLE IF NOT EXISTS raw_events (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    device_id TEXT REFERENCES devices(device_id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,  -- 'auth', 'flow'
    payload JSONB NOT NULL
);

-- Detections table - alerts and classifications
CREATE TABLE IF NOT EXISTS detections (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    device_id TEXT REFERENCES devices(device_id) ON DELETE SET NULL,
    raw_event_id BIGINT REFERENCES raw_events(id) ON DELETE SET NULL,
    model_name TEXT NOT NULL,  -- 'ssh_lstm', 'network_rf'
    label TEXT NOT NULL,        -- predicted class / attack type
    score DOUBLE PRECISION NOT NULL,
    severity TEXT NOT NULL,     -- LOW, MEDIUM, HIGH, CRITICAL
    details JSONB NOT NULL,
    -- Deduplication & Traceability
    occurrences BIGINT NOT NULL DEFAULT 1,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    -- Network fields (for dedup optimization and queries)
    src_ip TEXT,
    dst_ip TEXT,
    src_port INT,
    dst_port INT,
    proto TEXT
);

-- =====================================================
-- Indexes for raw_events
-- =====================================================
CREATE INDEX IF NOT EXISTS idx_raw_events_ts ON raw_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_raw_events_event_type ON raw_events(event_type);
CREATE INDEX IF NOT EXISTS idx_raw_events_device_id ON raw_events(device_id);
CREATE INDEX IF NOT EXISTS idx_raw_events_device_ts ON raw_events(device_id, ts DESC);

-- =====================================================
-- Indexes for detections
-- =====================================================
CREATE INDEX IF NOT EXISTS idx_detections_ts ON detections(ts DESC);
CREATE INDEX IF NOT EXISTS idx_detections_label ON detections(label);
CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity);
CREATE INDEX IF NOT EXISTS idx_detections_model_name ON detections(model_name);
CREATE INDEX IF NOT EXISTS idx_detections_device_id ON detections(device_id);
CREATE INDEX IF NOT EXISTS idx_detections_device_ts ON detections(device_id, ts DESC);

-- Composite index for network deduplication queries
CREATE INDEX IF NOT EXISTS idx_detections_network_dedup 
    ON detections(model_name, src_ip, dst_ip, dst_port, label);

-- =====================================================
-- Indexes for devices
-- =====================================================
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);

-- Note: Devices are registered dynamically when sensors first connect.
-- The `ensure_device()` function in db.py handles device registration and last_seen updates.
