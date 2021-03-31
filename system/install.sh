#!/bin/bash

## Install golang app as systemd instanse
## Preconditions: root, $APPNAME.service
## Alertpoints: STDERR

APPNAME="projectapp"

# Deploy nginx configs
if [ -f /etc/nginx/nginx.conf-original ]; then
    cp -f nginx.conf /etc/nginx/nginx.conf
    echo "The special file 'nginx.conf' placed successfully in /etc/nginx"
else
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf-original
    echo "The default file 'nginx.conf' backuped in /etc/nginx with -original suffix"
fi

# Backup default nginx and default-site configs
if [ -f /etc/nginx/sites-available/default-original ]; then
	echo "file default config backap file is available"
else
    unlink /etc/nginx/sites-enabled/default;
    mv /etc/nginx/sites-available/default /etc/nginx/sites-available/default-original;
    echo "The default 'default' file buckuped to -original suffix"
fi

cp -f $APPNAME".conf" /etc/nginx/sites-available/$APPNAME;
ln -s /etc/nginx/sites-available/$APPNAME /etc/nginx/sites-enabled/$APPNAME
echo "Sites nginx config is installed"

# start nginx with new configs
sudo systemctl restart nginx

cp -f ../distr/$(arch)/$APPNAME ../$APPNAME;
echo "New build placed: Ok!"

sudo cp -f $APPNAME".service" /lib/systemd/system
sudo chmod 755 /lib/systemd/system/$APPNAME".service"
sudo systemctl enable $APPNAME
sudo systemctl start $APPNAME
sudo systemctl status $APPNAME

echo "Sytemd Unit of $SERVICEUNIT now installed: Ok!"
exit 0
