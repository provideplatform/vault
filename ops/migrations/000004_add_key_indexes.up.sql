DROP INDEX idx_keys_iteration;
CREATE INDEX idx_keys_iteration ON keys USING btree (iteration);

CREATE INDEX idx_keys_spec ON keys USING btree (spec);
CREATE INDEX idx_keys_usage ON keys USING btree (usage);
