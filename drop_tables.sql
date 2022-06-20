-- Deleting all tables in a way that makes sense

\c simtooreal;
ALTER TABLE public.picks
DROP CONSTRAINT fk_items;

ALTER TABLE public.picks
DROP CONSTRAINT fk_robots;

DROP TABLE public.picks CASCADE;
DROP TABLE public.robots CASCADE;
DROP TABLE public.items CASCADE;

DROP SCHEMA public CASCADE;
\c postgres;
DROP DATABASE simtooreal;
