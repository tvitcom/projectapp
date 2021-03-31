# projectapp

## Introduction

This is application for manages works and people who involve in resulting work.

## Features

Zero features:

[x] - 404, comingsoon, 403 pages
[x] - Landing
[x] - login
[x] - mailer
[x] - logout
[ ] - admin dashboard with current signup users
[x] - new user account
[ ] - edit user profile
[ ] - edit user password
[ ] - drop user account
 
Core features:

[x] - Login-google-oauth (Логин)     - MVP
[ ] - Company&Owners profile (Профиль)     - MVPs
[ ] - Project statuses (Листинг проектов)  - MVP
[ ] - Tasks management (распределение работ сотрудникам)
[ ] - Calendar sharing (Календарь)  - MVP
[ ] - sharing access (by link+phone)
[ ] - sharing files (Файлы) - MVP
[ ] - Export all own data (by own company_id/user_id)

Biz features:

[ ] - Project management (Управление проектами)
[ ] - Team management (Управление персоналом)
[ ] - Inventory management (Инвентарь) 
[ ] - Accounting (Подсчёт затрат)
[ ] - Policy aggrements (политику конфиденциальности и условия использования приложения сайта и его сервисов) 
[ ] - Integration with google calendar
[ ] - wiki
[ ] - chat
[ ] - software-accounting
[ ] - twait functional (for programmers and devops)
[ ] - Service Support and improvements process (Поддержка инцидентов и улучшение продукта)

Secure features:

[ ] - apparmor profile
[x] - cryptocookie
[ ] - monitoring
[ ] - userinputs validation
[x] - redirect HTTP page loads to HTTPS
[ ] - servers timeouts,TCP Keep-Alive period
[x] - default NoRoute, NoMethods pages and logging for this
[ ] - abnomal behavior logging (many err codes for one ip, weird useragent, so on...)
[ ] - alert for abnomal metrics
[x] - csp (anti-xss, anti-clickjacking, cors)
[ ] - rate limiter-byIp frontend
[ ] - rate limiter-byIp user panel
[ ] - rate limiter-byIp admin panel
[ ] - auto-adaptive rate limiters with blacklist ips
[ ] - captcha
[ ] - role based or acl security
[ ] - anti csrf
[ ] - anti breach
[ ] - anti pollution-attacks
[ ] - european requirements GPDR

SEO features:

[ ] - robots.txt
[ ] - json-ld
[ ] - progressive jpeg rendering
[ ] - mobile optimisation

## Deployment

You will rename files:
-	_env to .env
-	_API.md to API.md
-	_GPDR_POLICY.txt to GPDR_POLICY.txt
-	_deploy.conf to deploy.conf
-	_go.mod to go.mod
-	/data/_credentials.json to /data/credentials.json
-	/system/_dummy.service to system/yourPojectName.service
-	/system/hostName.conf system/yourProductionHostName.conf
-  on the Prod run: ./install.sh [...prodhostname...]
	
Then set appropriate config options in files: 
.env , deploy.conf, install.sh, /data/credentials.json, GPDR_POLICY.txt, system/yourPojectName.service
Load sql to your database from file data/*_init.sql

## Legal info
Please see in files: LEGAL.txt, LICENSE and NOTICE.txt files.
Related information about GPDR polycy please see in GPDR_POLICY.txt
