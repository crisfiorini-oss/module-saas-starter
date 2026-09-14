-- Routing an App-level webhook to the sources it affects (issue #691). GitHub
-- delivers `installation` and `installation_repositories` only to the App's own
-- webhook, and those payloads name an installation — never a source. The
-- installation a source is bound to lives inside its encrypted credential
-- envelope, which cannot be selected on, so a delivery had no way to resolve
-- the sources it concerns. This denormalizes the binding into an indexed column
-- so one read answers that.
--
-- The column is a routing index, never an authority. The envelope stays the
-- only thing an installation token is minted from, and the receiver re-verifies
-- every candidate source's access against GitHub rather than trusting the
-- column or the delivery — so a stale column can cost a redundant check, never
-- a wrong revocation.
--
-- Classification (DATABASE_AUTHORITY.md): datasource_sources stays a TENANT
-- relation with the same RLS policy and grants (migration 104) — a new nullable
-- column on an existing table is covered by the table-level GRANTs. The leased
-- reconciler reads and writes it through app_control_plane, which already holds
-- SELECT and UPDATE (migration 104). The column is deliberately outside the
-- source-read revision trigger's UPDATE OF list (migration 138): rebinding an
-- installation changes no readable-source attribute a consumer's cursor tracks.

ALTER TABLE public.datasource_sources
    ADD COLUMN github_installation_id TEXT;

-- Partial: only App-backed sources carry a binding, and the lookup is always
-- for a concrete installation, so PAT-backed rows stay out of the index.
CREATE INDEX datasource_sources_github_installation
    ON public.datasource_sources (github_installation_id)
    WHERE github_installation_id IS NOT NULL;
