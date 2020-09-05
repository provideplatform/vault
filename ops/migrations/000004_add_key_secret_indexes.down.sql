DROP INDEX idx_keys_iteration;
DROP INDEX idx_keys_spec;
DROP INDEX idx_keys_type;
DROP INDEX idx_keys_usage;
DROP INDEX idx_secrets_type;

CREATE INDEX idx_keys_iteration ON keys USING hash (iteration);
