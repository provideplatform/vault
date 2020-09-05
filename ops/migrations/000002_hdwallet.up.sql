ALTER TABLE keys ADD COLUMN iteration BIGINT;
CREATE INDEX idx_keys_iteration ON keys USING hash (iteration);
