
## For local development

Install homebrew

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

For Unix/Linux OS you might go to the official Terraform site and download bin-file with software.
  
Install docker  
Download here https://www.docker.com/products/docker-desktop  
Follow the instructions to install it and start docker desktop  

If on ubuntu install docker and start the docker daemon like so
```
sudo apt update
sudo apt install apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
apt-cache policy docker-ce
sudo apt install docker-ce
sudo apt-get install docker-compose-plugin
```
  
Install Postman  
Download here https://www.postman.com/downloads/  
Follow the instructions to install it  

Install terraform  
```
brew tap hashicorp/tap
brew install hashicorp/tap/terraform
```

This was my version of terraform and my providers
chase@Chases-MacBook-Pro backend % terraform --version  
Terraform v0.14.9
+ provider registry.terraform.io/hashicorp/aws v3.33.0
+ provider registry.terraform.io/hashicorp/template v2.2.0

Install aws cli
```
brew install awscli
```

Install ansible
```
brew install ansible
```

Install postgres
```
brew install postgres
```

Install python annd packages for testing the API
```
brew install python3
pip3 install requests
pip3 install coolname
```

## Create an AWS Account (already done by Admin)

Go through the steps to setup a new AWS account for attaching to Terraform Cloud and login to your root account to get to your [AWS account console](https://us-east-1.console.aws.amazon.com/console/home?region=us-east-1#)
  
## Setup AWS credentials (ask your Admin to do it)

Setup a new user called terraform in us-east-1 that has the "Select AWS credential type" option of "Access key - Programmatic access" checked [using IAM](https://us-east-1.console.aws.amazon.com/iam/home#/users$new?step=details)

The next step is to setup permissions and you should select "Attach existing policies directly" and then choose [AdministratorAccess](https://us-east-1.console.aws.amazon.com/iam/home#/policies/arn%3Aaws%3Aiam%3A%3Aaws%3Apolicy%2FAdministratorAccess)

No need to add any tags

On the review page click "Create User"

The next step you should see an AWS key pair

This AWS key pair you created for the new user called terraform in us-east-1 will be used by terraform for setting up the infrastructure in AWS and use these aws id and keys as `<your aws id>` and `<your aws key>`

Keep this key pair somewhere safe for now by clicking the "Show" link under "Secret access key" to copy and paste it somewhere else and also copy/pasting the "Access key ID"

## Configure AWS locally

After you have stored the "Secret access key" i.e. `<your aws key>` and "Access key ID" i.e. `<your aws id>` by using aws configure command below

```
aws configure
```

## Gain access to a foundation model (already done by Admin)

Setup a GPT-3 OpenAI access account and use the key found here https://beta.openai.com/docs/developer-quickstart/your-api-keys as `<your OpenAI API key>`

## Gain access to model inference as a service provider (already done by Admin)

Setup a replicate alpha access account and use the key found here replicate.com as `<your Replicate API key>`

## Make a private and public ssh key pair
```
ssh-keygen -t rsa -b 4096 -C "<insert your email address>"
```
Press enter a few times to accept defaults until the command is done

Start the ssh agent in the background
```
eval "$(ssh-agent -s)"
```

Add SSH private key to the ssh-agent
```
ssh-add ~/.ssh/id_rsa
```

## Update your public key (send your public key in ~/.ssh/id_rsa.pub to your Admin)

Put your public ssh key (~/.ssh/id_rsa.pub) in the resource "aws_key_pair" "simtooreal" section of the main.tf terraform file as the string value of public_key in quotation marks so you can attempt connecting to resources later
  
You also need to update the IP address allowed to attempt access to resources
you will find this in the following section:  
"aws_security_group" "simtooreal_public"

## Setup Terraform Cloud (already done by Admin)

Setup a [terraform cloud organization](https://app.terraform.io/app/organizations/new)
  
Once you have verified your email address by clicking the link sent to the email you used to sign up, [setup a workspace](https://app.terraform.io/app/simtooreal/workspaces/new)

integrate your workspace with your github repo by choosing a type of "Version Control Workflow"

Choose github.com as your version control provider and authorize Terraform to connect with your github account

If the correct repos do not appear to be an option you may need to add an organization repo

Export your sensitive information as environment variables in terraform cloud located [here](https://app.terraform.io/app/simtooreal/workspaces/simtooreal/variables) under `Environment Variables`

Your environment variables are all sensitive so be sure when you add a variable key value pair you check "sensitive" checkbox
```
TF_VAR_openai_api_key = <your OpenAI API key>
AWS_ACCESS_KEY_ID = <your aws id>
AWS_SECRET_ACCESS_KEY = <your aws key>
TF_VAR_aws_access_key_id = <your aws id>
TF_VAR_aws_secret_access_key = <your aws key>
```

AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY is for Terraform Cloud. TF_VAR_aws_access_key_id and TF_VAR_aws_secret_access_key are used by the terraform variables in variables.tf file.

Now when you push to github terraform cloud will automatically attempt an apply, show you the resulting changes, and ask for your manual confirmation of a terraform plan before a terraform apply is run https://app.terraform.io/app/simtooreal/workspaces/simtooreal/runs  
  
Then state is updated and managed in the cloud automatically for you here https://app.terraform.io/app/simtooreal/workspaces/simtooreal/states

Multiple people can use this, you don't always need to terraform apply, and you don't need to manage sensitive passwords or state on your local machine  
  
Wait for terraform apply to finish and you should have a green output in your run if all goes well

## Setup Terraform Account (send your email to the Admin so they can add you to the terraform cloud organization team)

Setup a terraform cloud account by going to https://app.terraform.io/signup/account

## Enable ssh key agent forwarding and login to the private instance to setup

Open up your ssh config and edit it making sure to use the IP addresses you just found for your instances in EC2
```
nano ~/.ssh/config
```

```
Host *
  AddKeysToAgent yes
  UseKeychain yes
  IdentityFile ~/.ssh/id_rsa
Host 3.237.80.32
  HostName 3.237.80.32
  ForwardAgent yes
  IdentityFile ~/.ssh/id_rsa
  User ubuntu
Host 172.17.0.41
  User ubuntu
  IdentityFile ~/.ssh/id_rsa
  ProxyCommand ssh -W %h:%p 3.237.80.32
```
Close the file

Make sure the config file isn't accessible to everyone
```
chmod 600 ~/.ssh/config
```

Now you will login to your private machine without using a bastion with AWS Systems Manager in the AWS console
```
ssh -A -i "~/.ssh/id_rsa" ubuntu@public.simtooreal.com
```
If you get the error Host key verification failed. you need to open your ~/.ssh/known_hosts file and empty it

This error means that someone may have replaced the instance with another one and is trying to trick you

Usually the simpler explanation is that you yourself or the local infrastructure admin have replaced the instance

But be security minded and be careful
```
ssh -o StrictHostKeyChecking=no -i "~/.ssh/id_rsa" ubuntu@private.simtooreal.com
```
ssm and aws_instance user_data have put a zipped up version of simtooreal on the instance for your convenience
```
cd /data
```

Press ctrl+D once when you setup the database to get back to your local development machine

## Setup github secrets (already done by Admin)

Start a new repo in github called simtooreal

If you are not forking the backend Github repo and want to initialize the backend folder as a git repo
```
git init
git branch -m main
```

Make sure to setup ssh keys in github and locally using [these instructions](https://docs.github.com/en/github/authenticating-to-github/connecting-to-github-with-ssh)

Or use HTTPS

Push to github and setup your repo in github to allow Github actions
```
git add .
git commit -m "initial commit"
git push origin main
```

Make sure you add AWS_ACCESS_KEY_ID with a value of `<your aws id>` and AWS_SECRET_ACCESS_KEY with a value of `<your aws key>` in your Github secrets, for example Dystopia Robotics secrets are found [here](https://github.com/simtooreal/simtooreal/settings/secrets/actions)

## Set github workflows environment variables (already done by Admin)

I have my environment variables set in github workflow but you will need to put your own values in, my settings are [found here](https://github.com/simtooreal/simtooreal/blob/main/.github/workflows/aws.yml)

## Run a Github action so that you can push an image to ECR and deploy automatically (already done by Admin)

When you are ready to zip up some of the scripts to put on the private instance run this command
```
rm simtooreal.tar.gz && rsync -a *.sql simtooreal && rsync -a *.py simtooreal && rsync -a *.yml simtooreal && rsync -a *.txt simtooreal && rsync -a topics.csv simtooreal && rsync -a Dockerfile simtooreal && rsync -a clf.joblib simtooreal && rsync -a templates simtooreal && rsync -a *.json simtooreal && tar -zcvf simtooreal.tar.gz simtooreal && rm -rf simtooreal
```

Once you push to github this also updates the version of simtooreal found on the private instance after you destroy the private instance and re-run the terraform apply in terraform cloud

## Run Terraform Cloud

In order to run the terraform commands in the Makefile you will need to first `terraform login` and follow the instructions to make and locally store your Terraform Cloud API key

Go to [terraform runs](https://app.terraform.io/app/simtooreal/workspaces/simtooreal/runs) and after confirming your plan press the button that says "Start New Plan"

## Get GPUs (already done by Admin)

To get GPUs make sure you reach out to the SALES TEAM and talk to them LIVE as no one else in AWS has a hope of getting your ticket submitted and approved in a day or two

## Run the app locally with Docker

Add this to your .bashrc on a mac or ubuntu
```
alias humanishfrontend='result=${PWD##*/} && if [[ $results -eq "backend" ]]; then cd ../frontend && npm install --legacy-peer-deps && REACT_APP_LOCAL_ENVIRONMENT=True REACT_APP_URL_BACKEND=http://localhost:8080 REACT_APP_URL_FRONTEND=http://localhost:3000 npm start; fi'
alias humanishbackend='docker compose down --volumes && docker compose build --no-cache && docker compose up'
```

Then run this command for them to take effect
```
source ~/.bash_aliases
```

To start the app locally

Run this only once for loading environment variables
```
echo 'POSTGRESQL_USER_NAME=postgres
POSTGRESQL_PASSWORD=magical_password
POSTGRESQL_HOST=backend-database-1
REPLICATE_API_TOKEN=<insert token from admin>
OPENAI_API_KEY=<your OpenAI API key>' > .env
humanishbackend
```

Now you are ready to run the application
```
humanishbackend
```

In a separate terminal window run the frontend
```
humanishfrontend
```

Code changes are automatically fast refreshed when you save a python file

To enter the local database in another terminal on your machine
```
psql --host=backend-database-1 --username=postgres --dbname=humanish -w
```

If you would like to restart the frontend app locally use this command
```
humanishbackend
```

In a separate terminal window run this to restart the frontend locally
```
humanishfrontend
```

To see log messages related to simtooreal_app run this command
```
docker service logs simtooreal_app
```
To see the "CURRENT STATE" of a service and even "ERROR" messages run this command
```
docker service ps simtooreal_app
```
visit localhost in your browser to see the app running
If you ever run into this error
```
ERROR: for simtooreal_app_1  Cannot create container for service app: max depth exceeded

ERROR: for app  Cannot create container for service app: max depth exceeded
ERROR: Encountered errors while bringing up the project.
```
Have no fear it just means you have made too many docker images
To make this message go away run this command
```
docker system prune -a
```
If you want to replace all data from the database but you are running a docker stack you will first need to run these commands
```
docker stack rm simtooreal
docker system prune -a
docker volume rm simtooreal_database-data
docker stack deploy --compose-file=docker-compose.yml simtooreal
```

To troubleshoot a task running in Docker switch app.py in backend to health_check.py
Also comment out the ports for backend
```
    # ports:
    #   - 8080:8080
```
Also in health_check.py change port 8080 to 8090

Next run the docker compose command and then run docker ps in another tab to find the container ID and go inside the container
```
docker compose down --volumes && docker compose build --no-cache && docker compose up
docker ps
docker exec -it e0bbd8fe0c77 /bin/bash
apt update
apt search vim
apt install vim
vim app.py
```

To troubleshoot a task running in ECS say task ea29f8775f8a4028969adb9d03a555c2 on humanish-backend:

First update app.py in the task definition json to health_check.py
```
aws ecs execute-command --cluster humanish --task ea29f8775f8a4028969adb9d03a555c2 --container humanish-backend --interactive --command "bash"
```