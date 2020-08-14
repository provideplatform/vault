ALTER TABLE keys ADD COLUMN iteration BIGINT;
CREATE INDEX idx_keys_iteration ON public.keys USING hash (iteration);
