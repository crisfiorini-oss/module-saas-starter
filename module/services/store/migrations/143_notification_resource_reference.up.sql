-- A follow item carries the resource it is about, because the presentation type
-- cannot: notifications.type is CHECK-constrained to six values (migration 15)
-- and a follow item uses `info` like any other product notice. The reference
-- beside the row is what identifies the item as being about a resource, and it
-- is what a visibility recheck filters on at read time — title and body are a
-- cache that outlives the grant, so they can never be that filter themselves.
--
-- Both columns are the owning module's own opaque strings, the same vocabulary
-- resource_follows (migration 142) and CheckAccess already speak. The host never
-- joins on them and never interprets them.
ALTER TABLE public.notifications
    ADD COLUMN resource_type TEXT,
    ADD COLUMN resource_id   TEXT;

-- A reference is whole or absent. A half-set reference would be unfilterable,
-- which is the one thing the reference exists for.
--
-- Both branches are written NULL-safe on purpose. A CHECK rejects only a FALSE
-- result, and `length(NULL) > 0` is NULL, so the shorter
-- `length(resource_type) > 0 AND length(resource_id) > 0` evaluates to NULL for
-- exactly the half-set rows this exists to refuse — and admits every one of
-- them. The explicit IS NOT NULL tests keep the branch FALSE rather than
-- unknown.
ALTER TABLE public.notifications
    ADD CONSTRAINT notifications_resource_reference
        CHECK ((resource_type IS NULL AND resource_id IS NULL)
            OR (resource_type IS NOT NULL AND resource_id IS NOT NULL
                AND length(resource_type) > 0 AND length(resource_id) > 0));

-- Ordinary notifications carry no reference and stay out of the index entirely,
-- so it costs nothing on the existing inbox path.
CREATE INDEX idx_notifications_user_resource
    ON public.notifications (user_id, resource_type, resource_id)
    WHERE resource_type IS NOT NULL;
