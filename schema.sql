SELECT 'CREATE DATABASE simtooreal'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'simtooreal')\gexec
\c simtooreal;
CREATE SCHEMA IF NOT EXISTS public;

	CREATE TABLE IF NOT EXISTS public.robots (
		robot_id serial PRIMARY KEY,
		robot_name VARCHAR ( 255 ) UNIQUE NOT NULL
	);

	CREATE TABLE IF NOT EXISTS public.items (
		item_id serial PRIMARY KEY,
		item_name VARCHAR ( 255 ) UNIQUE NOT NULL
	);

	CREATE TABLE IF NOT EXISTS public.feedbacks (
		data_id serial PRIMARY KEY,
		feedback_description VARCHAR ( 510 ) NOT NULL,
		feedback_email VARCHAR ( 255 ) NOT NULL
	);

	CREATE TABLE IF NOT EXISTS public.categories (
		data_id serial PRIMARY KEY,
		category_name VARCHAR ( 255 ) UNIQUE NOT NULL
	);

	CREATE TABLE IF NOT EXISTS public.picks (
		pick_id serial PRIMARY KEY,
		pick_timestamp TIMESTAMP NOT NULL,
		item_id serial,
		robot_id serial,
CONSTRAINT fk_item
	  FOREIGN KEY (item_id)
	      REFERENCES public.items(item_id),

CONSTRAINT fk_robot
	  FOREIGN KEY (robot_id)
	      REFERENCES public.robots(robot_id)
	);
