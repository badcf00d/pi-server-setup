if [ "$(whoami)" != "frost" ] ; then
    sudo adduser frost
    sudo usermod -a -G adm,dialout,cdrom,sudo,audio,video,plugdev,games,users,input,netdev,gpio,i2c,spi frost
    echo 'frost ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/010_frost-nopasswd
    
    echo 
    echo "#### Please ssh back into this device as the user frost"
    exit
fi



echo "#### Deleting pi user"
sudo pkill -u pi
sudo deluser -remove-home pi




echo "#### Adding new sources"
sudo sh -c "cat ${HOME}/pi-server-setup/apt_sources_list >> /etc/apt/sources.list"
echo "#### Adding apt preferences"
sudo sh -c "cat ${HOME}/pi-server-setup/apt_preferences >> /etc/apt/preferences"





echo "#### Installing packages"
sudo apt-get update && \
sudo apt-get upgrade -y && \
sudo apt-get full-upgrade -y && \
sudo apt install -y git man build-essential make nano sqlite3 \
libpam-google-authenticator mumble-server certbot python-certbot-nginx \
fail2ban ipset nmap postfix mutt apache2-utils tree dpkg-dev software-properties-common \
libbrotli-dev brotli htop wget curl xclip libjson-any-perl perl libdata-validate-ip-perl
echo "#### Installed new packages"





echo "#### Setting up google authenticator 2FA SSH"
sudo sh -c "echo 'auth required pam_google_authenticator.so' >> /etc/pam.d/sshd"
sudo service ssh reload

sudo perl -i -pe 's/#*ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
sudo sh -c "echo 'PermitRootLogin no' >> /etc/ssh/sshd_config"

google-authenticator --time-based --disallow-reuse --rate-limit=3 --rate-time=30
sudo service ssh reload






echo "#### Getting prerequisites to build nginx and openssl"
sudo apt-get install -y -t testing gcc
sudo apt-get build-dep -y -t testing nginx-full openssl

mkdir ~/nginx-build
mkdir ~/openssl-build

cd ~/openssl-build
echo "#### Getting openssl sources"
apt-get source -y -t testing openssl
perl -i -pe 's/CONFARGS\s*=/CONFARGS = $1 -march=native/' ~/openssl-build/openssl-*/debian/rules

cd $(echo ~/openssl-build/openssl-* | awk '{ print $1 }')
echo "#### Building openssl, this will take about 45 minutes on an rpi 3"
dpkg-buildpackage -b --no-sign
cd ..
echo "#### Installing openssl"
sudo dpkg --install openssl_*_armhf.deb
sudo dpkg --install libssl1.1_*_armhf.deb
sudo dpkg --install libssl-dev_*_armhf.deb


cd ~/nginx-build
echo "#### Getting nginx sources"
apt-get source -y -t testing nginx
git clone https://github.com/google/ngx_brotli.git
perl -i -pe 's/dpkg-buildflags --get CFLAGS\)/dpkg-buildflags --get CFLAGS\) -ftree-vectorize -march=native/' ~/nginx-build/nginx-*/debian/rules
perl -i -pe "s/common_configure_flags :=/common_configure_flags := --add-module=${HOME//'/'/'\/'}\/nginx-build\/ngx_brotli/" ~/nginx-build/nginx-*/debian/rules

cd $(echo ~/nginx-build/nginx-* | awk '{ print $1 }')
echo "#### Building nginx, this takes about 10 minutes on an rpi 3"
dpkg-buildpackage -b --no-sign
cd ..
echo "#### Installing nginx"
sudo dpkg --install nginx-common_*_all.deb
sudo dpkg --install nginx-full_*_armhf.deb





echo "#### Making site directories"
sudo mkdir -p /var/www/pfrost.me/html
sudo chown -R $USER:$USER /var/www/pfrost.me/html
sudo find /var/www -type d -exec chmod 775 {} \;
echo "#### Exporting site config"
sudo sh -c "cat ${HOME}/pi-server-setup/nginx_site_config > /etc/nginx/sites-enabled/pfrost.me"

sudo mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
echo "#### Exporting nginx config"
sudo sh -c "cat ${HOME}/pi-server-setup/nginx_config > /etc/nginx/nginx.conf"

echo "#### Exporting extra nginx mime types"
sudo perl -i -pe 's/application\/font-woff.*//' /etc/nginx/mime.types
sudo perl -i -pe 's/}//' /etc/nginx/mime.types
sudo sh -c "cat ${HOME}/pi-server-setup/nginx_extra_mime_types >> /etc/nginx/mime.types"
sudo sh -c "echo } >> /etc/nginx/mime.types"

sudo ln -s /etc/nginx/sites-available/pfrost.me /etc/nginx/sites-enabled/
sudo nginx -t
sudo service nginx restart

cd /var/www/pfrost.me/html
echo "#### Cloning website"
git clone https://github.com/badcf00d/pfrostdotme.git .






sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

echo "#### Configuring fail2ban"
sudo perl -i -pe "s/^\[sshd\]/\[sshd\]\nenabled = true\nbanaction = iptables-multiport/m" /etc/fail2ban/jail.local
sudo perl -i -pe "s/^\[nginx-http-auth\]/\[nginx-http-auth\]\nenabled = true\nbanaction = iptables-multiport/m" /etc/fail2ban/jail.local
sudo perl -i -pe "s/^\[nginx-limit-req\]/\[nginx-limit-req\]\nenabled = true\nbanaction = iptables-multiport/m" /etc/fail2ban/jail.local
sudo perl -i -pe "s/^\[nginx-botsearch\]/\[nginx-botsearch\]\nenabled = true\nbanaction = iptables-multiport/m" /etc/fail2ban/jail.local

sudo service fail2ban restart
sudo fail2ban-client status





echo "#### Installing ipset-blacklist"
sudo wget -O /usr/local/sbin/update-blacklist.sh https://raw.githubusercontent.com/trick77/ipset-blacklist/master/update-blacklist.sh
sudo chmod +x /usr/local/sbin/update-blacklist.sh
sudo mkdir -p /etc/ipset-blacklist ; sudo wget -O /etc/ipset-blacklist/ipset-blacklist.conf https://raw.githubusercontent.com/trick77/ipset-blacklist/master/ipset-blacklist.conf
sudo /usr/local/sbin/update-blacklist.sh /etc/ipset-blacklist/ipset-blacklist.conf

echo "#### Setting ipset-blacklist cron jobs"
sudo crontab -l | { cat; echo "46 18 * * *      sudo /usr/local/sbin/update-blacklist.sh /etc/ipset-blacklist/ipset-blacklist.conf"; echo } | sudo crontab -
sudo crontab -l | { cat; echo "@reboot sudo iptables -I INPUT 1 -m set --match-set blacklist src -j DROP"; echo } | sudo crontab -
sudo crontab -l | { cat; echo "@reboot sudo ipset restore < /etc/ipset-blacklist/ip-blacklist.restore"; echo } | sudo crontab -

tee << EOF /etc/fail2ban/action.d/iptables-multiport.local
[Definition]
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> 2 -p <protocol> -m multiport --dports <port> -j f2b-<name>
EOF

echo "#### iptables output:"
sudo iptables -L INPUT -v --line-numbers





echo "#### Installing ddclient:"
#### noninteractive means it skips all the settings
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ddclient
cd ~
echo "#### Cloning latest ddclient:"
git clone https://github.com/ddclient/ddclient.git
sudo cp -f ddclient/ddclient /usr/sbin/

echo "#### Exporting ddclient config:"
sudo sh -c "cat ${HOME}/pi-server-setup/ddclient_config > /etc/ddclient/ddclient.conf"
read -p "Enter your cloudflare login: " cloudflare_login
read -p "Enter your cloudflare global API key: " cloudflare_api_key
sudo perl -i -pe "s/login=/login=${cloudflare_login}/" /etc/ddclient/ddclient.conf
sudo perl -i -pe "s/password=/password=${cloudflare_api_key}/" /etc/ddclient/ddclient.conf
cloudflare_login=""
cloudflare_api_key=""

sudo perl -i -pe "s/run_daemon=\"false\"/run_daemon=\"true\"/" /etc/default/ddclient

sudo service ddclient restart
sudo service ddclient status



echo 
echo "#### Please make sure you have forwarded ports 80 and 443 before we try and run certbot"
read -p "#### The local IP of this device is probably $(hostname -I | awk '{ print $1 }')"
sudo certbot --nginx
sudo perl -i -pe "s/listen 443 ssl;/listen 443 ssl http2;/g" /etc/nginx/sites-available/pfrost.me




echo "#### Mounting NAS"
mkdir -p ~/D-LINKNAS/Volume_1
mkdir -p ~/D-LINKNAS/Volume_2
sudo update-rc.d rpcbind enable

read -p "Enter your NAS login: " nas_login
read -sp "Enter your NAS password: " nas_password
sudo sh -c "echo \"//192.168.7.11/Volume_1 $HOME/D-LINKNAS/Volume_1 cifs username=${nas_login},password=${nas_password},vers=1.0 0 0\" >> /etc/fstab"
sudo sh -c "echo \"//192.168.7.11/Volume_2 $HOME/D-LINKNAS/Volume_2 cifs username=${nas_login},password=${nas_password},vers=1.0 0 0\" >> /etc/fstab"
nas_login=""
nas_password=""

#### Equivalent to using the Wait for Network at Boot option in raspi-config
sudo raspi-config nonint do_boot_wait 0

echo "#### Adding cronjob"
sudo crontab -l | { cat; echo "@reboot mount -a"; echo } | sudo crontab -

read -p "Enter a username to add to the nginx .htpasswd file: " htpasswd_username
sudo htpasswd -c /etc/nginx/.htpasswd $htpasswd_username
echo "#### If you want to add more username/password combinations once your system is setup, run:"
echo "#### sudo htpasswd /etc/nginx/.htpasswd *desired username*"
echo 
htpasswd_username=""

sudo mkdir /var/www/pfrost.me/html/directorydoesnotexist
sudo ln -s ~/D-LINKNAS /var/www/pfrost.me/html/directorydoesnotexist 






echo "#### Setting up mumble server"
sudo dpkg-reconfigure mumble-server

read -sp "Enter a mumble server password: " mumble_server_word
echo "#### Adjusting mumble server settings"
sudo perl -i -pe "s/;*serverpassword=/serverpassword=${mumble_server_word}/" /etc/mumble-server.ini
sudo perl -i -pe "s/;*port=.*/port=2003/" /etc/mumble-server.ini
sudo perl -i -pe "s/;*bandwidth=.*/bandwidth=45000/" /etc/mumble-server.ini
sudo perl -i -pe "s/;*sslCert=.*/sslCert=/etc/letsencrypt/live/pfrost.me/fullchain.pem/" /etc/mumble-server.ini
sudo perl -i -pe "s/;*sslKey=.*/sslKey=/etc/letsencrypt/live/pfrost.me/privkey.pem/" /etc/mumble-server.ini
mumble_server_word=""

sudo service mumble-server restart






echo "#### Installing goaccess"
sudo apt-get install -y -t testing goaccess
cd ~
read -p "Enter your maxmind license key: " maxmind_license_key
wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${maxmind_license_key}&suffix=tar.gz" -O GeoLite2-City.tar.gz
maxmind_license_key=""
tar -xzf GeoLite2-City.tar.gz

echo "#### Exporting goaccess setup"
sudo sh -c "cat ${HOME}/pi-server-setup/goaccess_service_config > /etc/systemd/system/goaccess.service"

sudo systemctl daemon-reload
sudo service goaccess start
sudo systemctl goaccess enable 
sudo service goaccess status 




echo "#### Adding Gitea user"
sudo adduser --system --group --disabled-password --shell /bin/bash --home /home/gitea --gecos 'Git Version Control' gitea
echo "#### Installing Gitea dependencies"
sudo apt-get install -y -t testing nodejs npm golang

echo "#### Cloning Gitea"
cd ~
git clone https://github.com/go-gitea/gitea
cd gitea
git tag -l
read -p "Pick a gitea version to use: " gitea_version
git checkout $gitea_version
gitea_version=""

echo "#### Increasing size of swap file"
sudo perl -i -pe "s/.*CONF_SWAPSIZE=.*/CONF_SWAPSIZE=1024/m" /etc/dphys-swapfile

sudo /etc/init.d/dphys-swapfile stop
sudo /etc/init.d/dphys-swapfile start

TAGS="bindata sqlite sqlite_unlock_notify" make build
    
sudo mv ./gitea /usr/local/bin
sudo chmod +x /usr/local/bin/gitea

sudo mkdir -p /var/lib/gitea/{custom,data,indexers,public,log}
sudo chown gitea: /var/lib/gitea/{data,indexers,log}
sudo chmod 750 /var/lib/gitea/{data,indexers,log}
sudo mkdir /etc/gitea
sudo chown root:gitea /etc/gitea
sudo chmod 770 /etc/gitea

echo "#### Setting up Gitea service"
sudo wget https://raw.githubusercontent.com/go-gitea/gitea/master/contrib/systemd/gitea.service -P /etc/systemd/system/
sudo perl -i -pe "s/\bgit\b/gitea/" /etc/systemd/system/gitea.service

sudo systemctl daemon-reload
sudo systemctl enable gitea
sudo service gitea start

echo "Open up a browser and goto http://$(hostname -I | awk '{ print $1 }'):3000"
echo 'Set the following settings, leave the others default: '
echo 
echo '  Database Type: SQLite3'
echo '  Run As Username: gitea'
echo '  SSH Server Domain: pfrost.me'
echo '  SSH Port: (Defaults to 22, change if needed)'
echo '  Gitea HTTP Listen Port: 3000'
echo '  Gitea Base URL: https://git.pfrost.me/'
read -p "Press enter when you've done that. "

echo "#### Adjusting Gitea settings"
sudo perl -i -pe "s/STATIC_URL_PREFIX.*/STATIC_URL_PREFIX = \/_\/static/" /etc/gitea/app.ini
sudo perl -i -pe "s/DISABLE_REGISTRATION.*/DISABLE_REGISTRATION = true/" /etc/gitea/app.ini
sudo perl -i -pe "s/REGISTER_EMAIL_CONFIRM.*/REGISTER_EMAIL_CONFIRM = true/" /etc/gitea/app.ini
sudo perl -i -pe "s/REQUIRE_SIGNIN_VIEW.*/REQUIRE_SIGNIN_VIEW = true/" /etc/gitea/app.ini

sudo service gitea restart

sudo chmod 750 /etc/gitea
sudo chmod 640 /etc/gitea/app.ini

echo "#### Done :)"