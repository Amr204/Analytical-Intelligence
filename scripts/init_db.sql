-- =====================================================
-- Analytical-Intelligence v1 - Database Schema
-- =====================================================

-- Devices table - registered sensor devices
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    hostname TEXT,
    ip INET,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Raw events table - all incoming events stored as-is
CREATE TABLE IF NOT EXISTS raw_events (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    device_id TEXT REFERENCES devices(device_id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,  -- 'auth', 'flow', 'suricata'
    payload JSONB NOT NULL
);

-- Detections table - alerts and classifications
CREATE TABLE IF NOT EXISTS detections (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    device_id TEXT REFERENCES devices(device_id) ON DELETE SET NULL,
    raw_event_id BIGINT REFERENCES raw_events(id) ON DELETE SET NULL,
    model_name TEXT NOT NULL,  -- 'ssh_lstm', 'network_ml', 'suricata'
    label TEXT NOT NULL,        -- predicted class / signature
    score DOUBLE PRECISION NOT NULL,
    severity TEXT NOT NULL,     -- LOW, MEDIUM, HIGH, CRITICAL
    details JSONB NOT NULL
);

-- Indexes for raw_events
CREATE INDEX IF NOT EXISTS idx_raw_events_ts ON raw_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_raw_events_event_type ON raw_events(event_type);
CREATE INDEX IF NOT EXISTS idx_raw_events_device_id ON raw_events(device_id);

-- Indexes for detections
CREATE INDEX IF NOT EXISTS idx_detections_ts ON detections(ts DESC);
CREATE INDEX IF NOT EXISTS idx_detections_label ON detections(label);
CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity);
CREATE INDEX IF NOT EXISTS idx_detections_model_name ON detections(model_name);
CREATE INDEX IF NOT EXISTS idx_detections_device_id ON detections(device_id);

-- Note: Devices are registered dynamically when sensors first connect.
-- The `ensure_device()` function in db.py handles device registration.
