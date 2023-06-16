# ThreatWorx GitLab App

![Container image build](https://github.com/threatworx/gitlab_app/actions/workflows/build.yml/badge.svg)

## _Zero Trust Automated AppSec for GitLab Enterprise_

A complete automated AppSec solution part of the ThreatWorx proactive security platform which discovers your Enterprise GitLab repositories and finds vulnerable dependencies, run static tests on code and Infrastructure-As-Code files, finds embedded secrets and more.

## Features

- Code doesn't leave your premises even for scanning - zero trust scan
- Packaged as a container for easy on-premise deployment
- Support for open source vulns and IaC scanning
- Support for on-premise / hosted GitLab Enterprise service
- Auto upgrade using watchtower

## Requirements

- Standard linux system (Redhat, Ubuntu, CentOS etc.) with docker support and port 443 (https) inbound / outbound connectivity and atleast 100GB storage
- SSL certificate for secure communication with GitLab (optional). App supports and will allow creating self signed certificates if none are available.
- GitLab App requires 'read' permissions for repo content and metadata and optional write permissions for PRs (in case you enable the PR workflow)

## Setup GitLab access token

- The app uses Gitlab access tokens to clone repositories for scanning

- To setup a access token go to your GitLab project->Settings->Access Tokens

- Use an appropriate expiry date for your token

- The minimum role required is `Developer` and the minimum scope is `read_repository`

- Access tokens can be created for GitLab Groups as well which allows you to use a single access token for a group of projects / repositories [more](https://docs.gitlab.com/ee/user/group/settings/group_access_tokens.html)

- Remember to copy / store the access token for use later when configuring the app server

## Setup GitLab webhook

- The app uses GitLab webhook to receive events such as a repostory push

- To setup a webhook go to your `GitLab project->Settings->Webhooks`

- Set the URL for the webhook to `https://<your app server>/webhook`

- Set a secret token / password which the app will use to verify incoming webhook requests

- Select `Push events` as the trigger

- If you are using your enterprise SSL certificates, you can enable SSL verification

- Just like the access token, the webhook can be created for a GitLab group which allows for scanning multiple repositories using a single webhook [more])(https://docs.gitlab.com/ee/user/project/integrations/webhooks.html)

## Install and configure the App Service

- Ensure requirements are satisfied on linux system, especially docker support and https inbound / outbound connectivity

- Download / clone the [ThreatWorx GitLab App](https://github.com/threatworx/gitlab_app) repository

```bash
git clone https://github.com/threatworx/gitlab_app.git
```

- Run the setup.sh script to create self signed certificates

```bash
cd gitlab_app
./setup.sh
```

> If you have ssl certificates, copy them to the ``config`` directory and edit the ``uwsgi.ini`` to use your certificates

```
[uwsgi]
...
https = =0,/opt/tw_gitlab_app/config/my.cert,/opt/tw_gitlab_app/config/my.key,...
...
```

- Start the app service by running the ``docker compose`` or the ``docker-compose`` command

```bash
docker compose up -d
```

- Point a browser to ``https://linux-system`` to configure the app service

> The browser will complain about the self signed certificate if are using one
>
> Please be sure to replace it with an appropriate ssl certificate

- Provide required details of your ThreatWorx subscription on the form 

- Select required options for app service and click ``Configure``

> These options can be changed later by editing the ``./config/config.ini`` file

> App will initially do a complete dependency vulnerability scan for all selected repositories
>
> After that, any push will trigger a rescan of the change that is committed
