# pi-server-setup
A set of script and config files that I use to setup raspberry pi servers from a fresh raspbian install

#### How to run

```
#### Flash raspbian and add the 'ssh' file to the boot partition to enable ssh
#### ssh into the default pi user
sudo apt-get update && \
sudo apt-get install -y git && \
git clone https://github.com/badcf00d/pi-server-setup.git && \
cd pi-server-setup && \
./main.sh


#### ssh into the newly created user
git clone https://github.com/badcf00d/pi-server-setup.git && \
cd pi-server-setup && \
./main.sh
```