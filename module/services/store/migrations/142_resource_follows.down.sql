DROP POLICY IF EXISTS app_control_plane_explicit_rows ON public.resource_follows;
DROP POLICY IF EXISTS resource_follows_user ON public.resource_follows;
ALTER TABLE IF EXISTS public.resource_follows NO FORCE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.resource_follows DISABLE ROW LEVEL SECURITY;
DROP INDEX IF EXISTS public.idx_resource_follows_live;
DROP TABLE IF EXISTS public.resource_follows;
