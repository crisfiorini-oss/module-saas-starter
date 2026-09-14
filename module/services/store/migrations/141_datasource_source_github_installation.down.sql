-- Dropping the routing index loses no authority: the installation binding each
-- source authenticates with is in its credential envelope, which this migration
-- never touched. An App-level delivery simply stops resolving to sources again.

DROP INDEX IF EXISTS public.datasource_sources_github_installation;

ALTER TABLE public.datasource_sources
    DROP COLUMN github_installation_id;
