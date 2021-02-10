DROP INDEX idx_keys_iteration;
ALTER TABLE keys DROP COLUMN iteration;

ALTER TABLE keys ADD COLUMN iterative_hd_derivation_path varchar(32);
