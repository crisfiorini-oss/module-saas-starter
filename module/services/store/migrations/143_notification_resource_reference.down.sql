DROP INDEX IF EXISTS public.idx_notifications_user_resource;
ALTER TABLE public.notifications DROP CONSTRAINT IF EXISTS notifications_resource_reference;
ALTER TABLE public.notifications DROP COLUMN IF EXISTS resource_id;
ALTER TABLE public.notifications DROP COLUMN IF EXISTS resource_type;
