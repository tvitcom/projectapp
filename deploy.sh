#!/bin/sh

## Install golang app as systemd instanse
## Preconditions: root, remote-root, $APPNAME.service
## Alertpoints: STDERR

## USING: sh system/deploy.sh instance-1 OR: sh tools/deploy.sh micro
HOSTNAME=$1
APPROOT=$(pwd)

test -n $HOSTNAME || exit 100

set -a
test -f $PWD/system/$HOSTNAME.conf && . $PWD/system/$HOSTNAME.conf
set +a

## Prepare distr directory

rsync -e "ssh -p $REMOTE_PORT" \
	--exclude=".gitignore" \
	--exclude="filestorage/" \
	--exclude=".env*"	\
	--exclude="info/*"	\
	--exclude="run.sh"	\
	--exclude="logs/server.log" \
	--exclude="logs/errors.log" \
	--exclude="123*" \
	--exclude=".git" \
	-PLSluvr --del --no-perms --no-t \
	$APPROOT"/" $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR"/"

rsync -e "ssh -p $REMOTE_PORT" \
	--exclude="123*" \
	-PLSluvr --no-perms --no-t \
	$APPROOT"/filestorage/" $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR"/filestorage/"
## clean

echo "Transfered to webserver host $REMOTE_HOST:$REMOTE_PORT: Ok!"

ssh -p $REMOTE_PORT root@$REMOTE_HOST "sudo systemctl try-restart $SERVICEUNIT"

echo "!!!ALSO: Sync database data to $REMOTE_HOST!!!"
exit 100
