DROP INDEX idx_keys_iteration;
DROP INDEX idx_keys_spec;
DROP INDEX idx_keys_usage;

CREATE INDEX idx_keys_iteration ON keys USING hash (iteration);
