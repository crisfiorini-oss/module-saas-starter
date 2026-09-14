-- GitHub App onboarding (issue #687): the one-time, tenant-bound setup state a
-- browser install round-trips through, and the verified installation claim that
-- redeeming it produces.
--
-- Two tables rather than one because they have different lifetimes and different
-- invariants: a setup row is short-lived and single-use, while a claim is durable
-- and must be unique across the whole deployment.
CREATE TABLE public.github_app_setups (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
 -- The setup is redeemable only by the user who began it, so a leaked redirect
 -- cannot be completed by another member of the same organization.
 initiated_by UUID NOT NULL REFERENCES public.users(uuid) ON DELETE CASCADE,
 -- hex(sha256(state)). The plaintext exists only in the redirect URL, so a
 -- database read never yields a redeemable state.
 state_hash TEXT NOT NULL UNIQUE CHECK (length(state_hash) = 64),
 expires_at TIMESTAMPTZ NOT NULL,
 consumed_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX github_app_setups_open ON public.github_app_setups(org_id) WHERE consumed_at IS NULL;
ALTER TABLE public.github_app_setups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.github_app_setups FORCE ROW LEVEL SECURITY;
CREATE POLICY github_app_setups_tenant ON public.github_app_setups
 USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
 WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.github_app_setups TO app_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.github_app_setups TO app_control_plane;
CREATE POLICY app_control_plane_explicit_rows ON public.github_app_setups
 FOR ALL TO app_control_plane
 USING (current_user = 'app_control_plane') WITH CHECK (current_user = 'app_control_plane');

-- An installation belongs to exactly one organization. The primary key is the
-- cross-tenant substitution guard itself: a second organization presenting the
-- same installation id from a browser redirect collides here and is refused,
-- rather than silently binding another tenant's installation.
CREATE TABLE public.github_app_installations (
 installation_id TEXT PRIMARY KEY CHECK (installation_id ~ '^[0-9]+$'),
 org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
 verified_by UUID NOT NULL REFERENCES public.users(uuid) ON DELETE CASCADE,
 verified_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX github_app_installations_org ON public.github_app_installations(org_id);
ALTER TABLE public.github_app_installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.github_app_installations FORCE ROW LEVEL SECURITY;
CREATE POLICY github_app_installations_tenant ON public.github_app_installations
 USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
 WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.github_app_installations TO app_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.github_app_installations TO app_control_plane;
CREATE POLICY app_control_plane_explicit_rows ON public.github_app_installations
 FOR ALL TO app_control_plane
 USING (current_user = 'app_control_plane') WITH CHECK (current_user = 'app_control_plane');
