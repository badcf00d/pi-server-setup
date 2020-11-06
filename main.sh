#!/bin/bash
set -e
set -u
trap 'catch $? $LINENO' ERR

BASE_DIR=$(dirname $(readlink -f "$BASH_SOURCE"))

catch() {
    echo 
    case $1 in
        "0")
        echo "Trapped but return value seems ok?"
        ;;

        *)
        echo "Error: command returned $1 on line $(caller)"
        ;;
    esac

    cd $BASE_DIR
    awk 'NR>Line-3 && NR<Line+3 { printf "%-4d%4s%s\n",NR,(NR==Line?"--> ":""),$0 }' Line=$2 $(caller | awk '{ print $2 }')
}



if [ "$(whoami)" != "frost" ] ; then
    echo "#### Creating user frost"
    sudo adduser frost
    sudo usermod -a -G adm,dialout,cdrom,sudo,audio,video,plugdev,games,users,input,netdev,gpio,i2c,spi frost
    echo 'frost ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/010_frost-nopasswd 1&>/dev/null
    echo 
    echo 
    echo "#### Please ssh back into this device as the user frost"
    echo "#### Type 'exit' then probably 'ssh frost@$(hostname -I | awk '{ print $1 }')'"
    exit
fi




if id pi >/dev/null 2>&1; then
    echo "#### Deleting pi user"
    if pgrep pi >/dev/null 2>&1; then
        sudo pkill -u pi
    fi
    sudo deluser -remove-home pi
else
    echo "#### pi user doesn't exist"
fi




if sudo grep -q -- '# Extra apt sources' /etc/apt/sources.list; then
    echo "#### Already added extra apt sources"
else
    echo "#### Adding new sources"
    sudo sh -c "cat ${HOME}/pi-server-setup/apt_sources_list >> /etc/apt/sources.list"
fi

if sudo grep -q -- '# Extra apt preferences' /etc/apt/preferences; then
    echo "#### Already added apt preferences"
else
    echo "#### Adding apt preferences"
    sudo sh -c "cat ${HOME}/pi-server-setup/apt_preferences >> /etc/apt/preferences"
fi





echo "#### Updating repositories"
sudo apt update
echo "#### Upgrading packages"
sudo apt upgrade -y
echo "#### Upgrading distribution"
sudo apt full-upgrade -y
echo "#### Installing packages"
sudo apt install -y git man build-essential make nano sqlite3 \
libpam-google-authenticator mumble-server certbot python-certbot-nginx \
fail2ban ipset nmap postfix mutt apache2-utils tree dpkg-dev software-properties-common \
libbrotli-dev brotli htop wget curl xclip libjson-any-perl perl libdata-validate-ip-perl
echo "#### Installed new packages"





echo "#### Setting up google authenticator 2FA SSH"
google-authenticator --time-based --disallow-reuse --minimal-window --rate-limit=3 --rate-time=30

if sudo grep -q -- '^auth required pam_google_authenticator.so' /etc/pam.d/sshd; then
    echo "#### Already added pam_google_authenticator"
else
    echo "#### Adding pam_google_authenticator"
    sudo sh -c "echo 'auth required pam_google_authenticator.so' >> /etc/pam.d/sshd"
fi

if sudo grep -q -- '^ChallengeResponseAuthentication yes' /etc/ssh/sshd_config; then
    echo "#### Already enabled challenge response authentication"
else
    echo "#### enabling challenge response authentication"
    if sudo grep -q -- '^ChallengeResponseAuthentication' /etc/ssh/sshd_config; then
        sudo perl -i -pe 's/ChallengeResponseAuthentication.*no/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
    else
        sudo sh -c "echo 'ChallengeResponseAuthentication yes' >> /etc/ssh/sshd_config"
    fi
fi

if sudo grep -q -- '^PermitRootLogin no' /etc/ssh/sshd_config; then
    echo "#### Already disabled ssh root login"
else
    echo "#### Disabling root ssh login"
    if sudo grep -q -- '^PermitRootLogin' /etc/ssh/sshd_config; then
        sudo perl -i -pe 's/PermitRootLogin.*yes/PermitRootLogin no/' /etc/ssh/sshd_config
    else
        sudo sh -c "echo 'PermitRootLogin no' >> /etc/ssh/sshd_config"
    fi
fi

sudo service ssh reload






echo "#### Getting prerequisites to build nginx and openssl"
sudo apt install -y -t testing gcc
sudo apt-get build-dep -y -t testing nginx-full openssl

mkdir -p ~/nginx-build
mkdir -p ~/openssl-build

cd ~/openssl-build
echo "#### Getting openssl sources"
apt-get source -y -t testing openssl
perl -i -pe 's/CONFARGS\s*=/CONFARGS = $1 -march=native/' ~/openssl-build/openssl-*/debian/rules

cd $(echo ~/openssl-build/openssl-* | awk '{ print $1 }')
echo "#### Building openssl, this will take about 45 minutes on an rpi 3"
dpkg-buildpackage -b --no-sign
cd ..
echo "#### Installing openssl"
sudo apt install -y --allow-downgrades -t testing ./openssl_*_armhf.deb ./libssl1.1_*_armhf.deb ./libssl-dev_*_armhf.deb

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
sudo apt install -y --allow-downgrades -t testing ./nginx-core_*_armhf.deb ./nginx-common_*_all.deb ./nginx-full_*_armhf.deb





echo "#### Making site directories"
sudo mkdir -p /var/www/pfrost.me/html
sudo chown -R $USER:$USER /var/www/pfrost.me/html
sudo find /var/www -type d -exec chmod 775 {} \;
echo "#### Exporting site config"
sudo sh -c "cat ${HOME}/pi-server-setup/nginx_site_config > /etc/nginx/sites-available/pfrost.me"

sudo mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
echo "#### Exporting nginx config"
sudo sh -c "cat ${HOME}/pi-server-setup/nginx_config > /etc/nginx/nginx.conf"

if sudo grep -q -- '# Extra mime types' /etc/nginx/mime.types; then
    echo "#### Already modified mime types"
else
    echo "#### Exporting extra nginx mime types"
    sudo perl -i -pe 's/application\/font-woff.*//' /etc/nginx/mime.types
    sudo perl -i -pe 's/}//' /etc/nginx/mime.types
    sudo sh -c "cat ${HOME}/pi-server-setup/nginx_extra_mime_types >> /etc/nginx/mime.types"
    sudo sh -c "echo } >> /etc/nginx/mime.types"
fi

sudo ln -s -i -v /etc/nginx/sites-available/pfrost.me /etc/nginx/sites-enabled/
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
sudo service fail2ban status





echo "#### Installing ipset-blacklist"
sudo wget -O /usr/local/sbin/update-blacklist.sh https://raw.githubusercontent.com/trick77/ipset-blacklist/master/update-blacklist.sh
sudo chmod +x /usr/local/sbin/update-blacklist.sh
sudo mkdir -p /etc/ipset-blacklist ; sudo wget -O /etc/ipset-blacklist/ipset-blacklist.conf https://raw.githubusercontent.com/trick77/ipset-blacklist/master/ipset-blacklist.conf
sudo /usr/local/sbin/update-blacklist.sh /etc/ipset-blacklist/ipset-blacklist.conf

echo "#### Setting ipset-blacklist cron jobs"
if sudo crontab -l | sudo grep -q -- 'update-blacklist.sh'; then
    echo "#### Already added update-blacklist"
else
    sudo sh -c '{ sudo crontab -l | { cat; echo "46 18 * * *      sudo /usr/local/sbin/update-blacklist.sh /etc/ipset-blacklist/ipset-blacklist.conf"; echo; } | sudo crontab - ; }'
fi

if sudo crontab -l | sudo grep -q -- '--match-set blacklist src'; then
    echo "#### Already added iptables match-set"
else
    sudo sh -c '{ sudo crontab -l | { cat; echo "@reboot sudo iptables -I INPUT 1 -m set --match-set blacklist src -j DROP"; echo; } | sudo crontab - ; }'
fi

if sudo crontab -l | sudo grep -q -- 'ip-blacklist.restore'; then
    echo "#### Already added blacklist restore"
else
    sudo sh -c '{ sudo crontab -l | { cat; echo "@reboot sudo ipset restore < /etc/ipset-blacklist/ip-blacklist.restore"; echo; } | sudo crontab - ; }'
fi


if sudo grep -q -- 'actionstart = <iptables> -N f2b-<name>' /etc/fail2ban/action.d/iptables-multiport.local; then
    echo "#### Already added fail2ban multiport rule"
else
    sudo tee << EOF /etc/fail2ban/action.d/iptables-multiport.local
[Definition]
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> 2 -p <protocol> -m multiport --dports <port> -j f2b-<name>
EOF
fi

echo "#### iptables output:"
sudo iptables -L INPUT -v --line-numbers





echo "#### Installing ddclient:"
#### noninteractive means it skips all the settings
sudo DEBIAN_FRONTEND=noninteractive apt install -y ddclient
sudo apt install -y -t testing libio-socket-ssl-perl
cd ~
echo "#### Cloning latest ddclient:"
git clone https://github.com/ddclient/ddclient.git
sudo cp -f ddclient/ddclient /usr/sbin/

echo "#### Exporting ddclient config:"
sudo mkdir -p /etc/ddclient
sudo sh -c "cat ${HOME}/pi-server-setup/ddclient_config > /etc/ddclient/ddclient.conf"
read -p "Enter your cloudflare login: " cloudflare_login
read -p "Enter your cloudflare global API key: " cloudflare_api_key
sudo perl -i -pe "s/login=.*/login=${cloudflare_login}/" /etc/ddclient/ddclient.conf
sudo perl -i -pe "s/password=.*/password=${cloudflare_api_key}/" /etc/ddclient/ddclient.conf
cloudflare_login=""
cloudflare_api_key=""

sudo perl -i -pe "s/run_daemon=\"false\"/run_daemon=\"true\"/" /etc/default/ddclient

sudo service ddclient restart
sudo service ddclient status



echo 
echo "#### Please make sure you have forwarded ports 80 and 443 before we try and run certbot"
read -p "#### The local IP of this device is probably $(hostname -I | awk '{ print $1 }') (press enter): "
sudo certbot --nginx
sudo perl -i -pe "s/listen 443 ssl;/listen 443 ssl http2;/g" /etc/nginx/sites-available/pfrost.me




echo "#### Mounting NAS"
mkdir -p ~/D-LINKNAS/Volume_1
mkdir -p ~/D-LINKNAS/Volume_2
sudo update-rc.d rpcbind enable

if sudo grep -q -- '192.168.7.11/Volume_1' /etc/fstab; then
    echo "#### Already modified fstab"
else
    read -p "Enter your NAS login: " nas_login
    read -sp "Enter your NAS password: " nas_password
    echo "#### Modifying fstab"
    sudo sh -c "echo \"//192.168.7.11/Volume_1 $HOME/D-LINKNAS/Volume_1 cifs username=${nas_login},password=${nas_password},vers=1.0 0 0\" >> /etc/fstab"
    sudo sh -c "echo \"//192.168.7.11/Volume_2 $HOME/D-LINKNAS/Volume_2 cifs username=${nas_login},password=${nas_password},vers=1.0 0 0\" >> /etc/fstab"
    nas_login=""
    nas_password=""
fi
#### Equivalent to using the Wait for Network at Boot option in raspi-config
sudo raspi-config nonint do_boot_wait 0

echo "#### Adding cronjob"
if sudo crontab -l | sudo grep -q -- '@reboot mount -a'; then
    echo "#### Already added mount cronjob"
else
    sudo sh -c '{ sudo crontab -l | { cat; echo "@reboot mount -a"; echo; } | sudo crontab - ; }'
fi

read -p "Enter a username to add to the nginx .htpasswd file: " htpasswd_username
if test -f '/etc/nginx/.htpasswd'; then
    sudo htpasswd /etc/nginx/.htpasswd $htpasswd_username
else
    sudo htpasswd -c /etc/nginx/.htpasswd $htpasswd_username
fi
echo "#### If you want to add more username/password combinations once your system is setup, run:"
echo "#### sudo htpasswd /etc/nginx/.htpasswd *desired username*"
echo 
htpasswd_username=""

sudo mkdir -p /var/www/pfrost.me/html/directorydoesnotexist
sudo ln -s -i -v ~/D-LINKNAS /var/www/pfrost.me/html/directorydoesnotexist 






echo "#### Setting up mumble server"
sudo dpkg-reconfigure mumble-server

read -sp "Enter a mumble server password: " mumble_server_word
echo "#### Adjusting mumble server settings"
sudo perl -i -pe "s/;*serverpassword=.*/serverpassword=${mumble_server_word}/" /etc/mumble-server.ini
sudo perl -i -pe "s/;*port=.*/port=2003/" /etc/mumble-server.ini
sudo perl -i -pe "s/;*bandwidth=.*/bandwidth=45000/" /etc/mumble-server.ini
sudo perl -i -pe "s/;*sslCert=.*/sslCert=\/etc\/letsencrypt\/live\/pfrost.me\/fullchain.pem/" /etc/mumble-server.ini
sudo perl -i -pe "s/;*sslKey=.*/sslKey=\/etc\/letsencrypt\/live\/pfrost.me\/privkey.pem/" /etc/mumble-server.ini
mumble_server_word=""

sudo service mumble-server restart






echo "#### Installing goaccess"
sudo apt install -y -t testing goaccess
cd ~
read -p "Enter your maxmind license key: " maxmind_license_key
wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${maxmind_license_key}&suffix=tar.gz" -O GeoLite2-City.tar.gz
maxmind_license_key=""
tar -xzf GeoLite2-City.tar.gz

echo "#### Exporting goaccess setup"
sudo sh -c "cat ${HOME}/pi-server-setup/goaccess_service_config > /etc/systemd/system/goaccess.service"

sudo systemctl daemon-reload
sudo systemctl enable --now goaccess
sudo service goaccess status




echo "#### Adding Gitea user"
sudo adduser --system --group --disabled-password --shell /bin/bash --home /home/gitea --gecos 'Git Version Control' gitea
echo "#### Installing Gitea dependencies"
sudo apt install -y -t testing nodejs npm golang
echo "#### Updating npm"
npm update --dd

echo "#### Cloning Gitea"
cd ~
git clone https://github.com/go-gitea/gitea
cd gitea
git tag -l | sort -n
read -p "Pick a gitea version to use: " gitea_version
git checkout $gitea_version
gitea_version=""

echo "#### Increasing size of swap file"
sudo perl -i -pe "s/.*CONF_SWAPSIZE=.*/CONF_SWAPSIZE=1024/m" /etc/dphys-swapfile

sudo /etc/init.d/dphys-swapfile stop
sudo /etc/init.d/dphys-swapfile start

TAGS="bindata sqlite sqlite_unlock_notify" make build
    
sudo cp ./gitea /usr/local/bin
sudo chmod +x /usr/local/bin/gitea

sudo mkdir -p /var/lib/gitea/{custom,data,indexers,public,log}
sudo chown gitea: /var/lib/gitea/{data,indexers,log}
sudo chmod 750 /var/lib/gitea/{data,indexers,log}
sudo mkdir -p /etc/gitea
sudo chown root:gitea /etc/gitea
sudo chmod 770 /etc/gitea

echo "#### Setting up Gitea service"
sudo wget https://raw.githubusercontent.com/go-gitea/gitea/master/contrib/systemd/gitea.service -P /etc/systemd/system/
sudo perl -i -pe "s/\bgit\b/gitea/g" /etc/systemd/system/gitea.service

sudo systemctl daemon-reload
sudo systemctl enable --now gitea
sudo service gitea status

echo 
echo "Open up a browser and goto http://$(hostname -I | awk '{ print $1 }'):3000/install"
echo 'Set the following settings, leave the others default: '
echo 
echo '  Database Type: SQLite3'
echo '  SSH Server Domain: git.pfrost.me'
echo '  SSH Port: (Defaults to 22, change if needed)'
echo '  Gitea Base URL: https://git.pfrost.me/'
echo 
read -p "Press enter when you've done that. "

echo "#### Adjusting Gitea settings"


if sudo grep -q -- 'STATIC_URL_PREFIX = /_/static' /etc/gitea/app.ini; then
    echo "#### Already added STATIC_URL_PREFIX = /_/static"
else
    sudo perl -i -pe "s/^\[server\]/\[server\]\nSTATIC_URL_PREFIX = \/_\/static/m" /etc/gitea/app.ini
fi
sudo perl -i -pe "s/DISABLE_REGISTRATION.*/DISABLE_REGISTRATION = true/" /etc/gitea/app.ini
sudo perl -i -pe "s/REGISTER_EMAIL_CONFIRM.*/REGISTER_EMAIL_CONFIRM = true/" /etc/gitea/app.ini
sudo perl -i -pe "s/REQUIRE_SIGNIN_VIEW.*/REQUIRE_SIGNIN_VIEW = true/" /etc/gitea/app.ini

sudo service gitea restart
sudo service gitea status

sudo chmod 750 /etc/gitea
sudo chmod 640 /etc/gitea/app.ini

echo "#### Done :)"