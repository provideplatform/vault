--
-- PostgreSQL database dump
--

-- Dumped from database version 10.6
-- Dumped by pg_dump version 10.11 (Ubuntu 10.11-1.pgdg16.04+1)

-- The following portion of the pg_dump output should not run during migrations:
-- SET statement_timeout = 0;
-- SET lock_timeout = 0;
-- SET idle_in_transaction_session_timeout = 0;
-- SET client_encoding = 'UTF8';
-- SET standard_conforming_strings = on;
-- SELECT pg_catalog.set_config('search_path', '', false);
-- SET check_function_bodies = false;
-- SET xmloption = content;
-- SET client_min_messages = warning;
-- SET row_security = off;

-- DO
-- $do$
-- BEGIN
--    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE  rolname = 'vault') THEN
--       CREATE ROLE vault WITH SUPERUSER LOGIN PASSWORD 'prvdvault';
--    END IF;
-- END
-- $do$;

-- SET ROLE vault;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner:
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner:
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner:
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


ALTER USER current_user WITH NOSUPERUSER;

SET default_tablespace = '';

SET default_with_oids = false;


--
-- Name: keys; Type: TABLE; Schema: public; Owner: vault
--

CREATE TABLE public.keys (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    vault_id uuid,
    name text NOT NULL,
    description text,
    type character varying(32),
    spec character varying(32),
    usage character varying(32),
    seed bytea,
    public_key bytea,
    private_key bytea
);


ALTER TABLE public.keys OWNER TO current_user;


--
-- Name: secrets; Type: TABLE; Schema: public; Owner: vault
--

CREATE TABLE public.secrets (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    vault_id uuid,
    name text NOT NULL,
    description text,
    type character varying(32),
    data bytea
);


ALTER TABLE public.secrets OWNER TO current_user;

--
-- Name: vaults; Type: TABLE; Schema: public; Owner: vault
--

CREATE TABLE public.vaults (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    application_id uuid,
    organization_id uuid,
    user_id uuid,
    master_key_id uuid,
    name text NOT NULL,
    description text
);


ALTER TABLE public.vaults OWNER TO current_user;


--
-- Name: keys keys_pkey; Type: CONSTRAINT; Schema: public; Owner: vault
--

ALTER TABLE ONLY public.keys
    ADD CONSTRAINT keys_pkey PRIMARY KEY (id);


--
-- Name: secrets secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: vault
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_pkey PRIMARY KEY (id);


--
-- Name: vaults vaults_pkey; Type: CONSTRAINT; Schema: public; Owner: vault
--

ALTER TABLE ONLY public.vaults
    ADD CONSTRAINT vaults_pkey PRIMARY KEY (id);


--
-- Name: idx_keys_type; Type: INDEX; Schema: public; Owner: vault
--

CREATE INDEX idx_keys_type ON public.keys USING btree (type);


--
-- Name: idx_keys_vault_id; Type: INDEX; Schema: public; Owner: vault
--

CREATE INDEX idx_keys_vault_id ON public.keys USING btree (vault_id);


--
-- Name: idx_secrets_type; Type: INDEX; Schema: public; Owner: vault
--

CREATE INDEX idx_secrets_type ON public.secrets USING btree (type);


--
-- Name: idx_secrets_vault_id; Type: INDEX; Schema: public; Owner: vault
--

CREATE INDEX idx_secrets_vault_id ON public.secrets USING btree (vault_id);


--
-- Name: idx_vaults_application_id; Type: INDEX; Schema: public; Owner: vault
--

CREATE INDEX idx_vaults_application_id ON public.vaults USING btree (application_id);


--
-- Name: idx_vaults_organization_id; Type: INDEX; Schema: public; Owner: vault
--

CREATE INDEX idx_vaults_organization_id ON public.vaults USING btree (organization_id);


--
-- Name: idx_vaults_user_id; Type: INDEX; Schema: public; Owner: vault
--

CREATE INDEX idx_vaults_user_id ON public.vaults USING btree (user_id);


--
-- Name: keys keys_vault_id_vaults_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: vault
--

ALTER TABLE ONLY public.keys
    ADD CONSTRAINT keys_vault_id_vaults_id_foreign FOREIGN KEY (vault_id) REFERENCES public.vaults(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: secrets secrets_vault_id_vaults_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: vault
--


ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_vault_id_vaults_id_foreign FOREIGN KEY (vault_id) REFERENCES public.vaults(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- PostgreSQL database dump complete
--
