-- A resource follow is one person's durable intent to be told when one specific
-- resource instance changes (module/FOLLOWS.md). It is deliberately not an
-- event_subscriptions row: that relation keys a service *principal* to a queue
-- and has room for neither a resource instance nor a human recipient.
--
-- resource_type and resource_id are opaque module-owned strings. The host never
-- joins on them and never interprets them; they are the same generic vocabulary
-- CheckAccess and ShareRecord already speak, which is what lets two unrelated
-- owning modules reuse this relation with no owner-specific branch.
CREATE TABLE public.resource_follows (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES public.users(uuid) ON DELETE CASCADE,
    resource_type TEXT NOT NULL CHECK (length(resource_type) > 0),
    resource_id   TEXT NOT NULL CHECK (length(resource_id) > 0),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at    TIMESTAMPTZ
);

-- Following twice is idempotent, and overlapping follows therefore cannot
-- produce two deliveries for one change.
CREATE UNIQUE INDEX idx_resource_follows_live
    ON public.resource_follows (org_id, user_id, resource_type, resource_id)
    WHERE revoked_at IS NULL;

-- Unfollow is a soft revoke rather than a delete: the suppression rule is
-- defined against the *time* of revocation, so the fact needs a timestamp.
ALTER TABLE public.resource_follows
    ADD CONSTRAINT resource_follows_revoked_after_created
        CHECK (revoked_at IS NULL OR revoked_at >= created_at);

ALTER TABLE public.resource_follows ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.resource_follows FORCE ROW LEVEL SECURITY;

-- user_id is the access key and org_id is descriptive, matching how
-- notifications is already secured (migration 34 as amended by 68). There is
-- deliberately no app.bypass branch: migration 68 removed exactly that shape so
-- a caller cannot manufacture authority with set_config(), and
-- TestActivePoliciesDoNotTrustSessionBypassSettings holds every policy to it.
CREATE POLICY resource_follows_user ON public.resource_follows
    USING (user_id::text = current_setting('app.current_user_id', true))
    WITH CHECK (user_id::text = current_setting('app.current_user_id', true));

CREATE POLICY app_control_plane_explicit_rows ON public.resource_follows
    FOR ALL TO app_control_plane
    USING (current_user = 'app_control_plane')
    WITH CHECK (current_user = 'app_control_plane');

-- Request traffic follows, reads its own follows, and revokes them; a revoke is
-- an UPDATE of revoked_at, so no DELETE is granted to app_tenant.
GRANT SELECT, INSERT, UPDATE ON public.resource_follows TO app_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.resource_follows TO app_control_plane;
