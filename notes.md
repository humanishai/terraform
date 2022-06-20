## Add robot
\c simtooreal
INSERT INTO public.robots values(default,'a1');
ansible-playbook -i hosts insert_robot.yml -e "robot_name='a1'"

## Add item
\c simtooreal
INSERT INTO public.items values(default,'candy bar');
ansible-playbook -i hosts insert_item.yml -e "item_name='candy bar'"

## Get robot by ID
SELECT FROM public.robots WHERE robot_id = '1';

## Get robot by name
SELECT FROM public.robots WHERE robot_name = 'optimus';

## Get item by name
SELECT FROM public.items WHERE item_name = 'candy bar';

## Delete robot
DELETE FROM public.robots WHERE robot_name = 'optimus';

## insert item
ansible-playbook -i hosts insert_item.yml -e "item_name='action toy'"

## Delete all tables and database simtooreal in the database
psql -h database.simtooreal.com -U postgres -d simtooreal -f drop_tables.sql

## Setup database
ansible-playbook -i hosts setup.yml

## Insert categories
psql -h database.simtooreal.com -U postgres -d simtooreal -f categories.sql