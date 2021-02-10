ALTER TABLE keys DROP COLUMN iterative_hd_derivation_path;

ALTER TABLE keys ADD COLUMN iteration BIGINT;
CREATE INDEX idx_keys_iteration ON keys USING btree (iteration);
