wget https://download.fedoraproject.org/pub/fedora/linux/releases/29/Cloud/x86_64/images/Fedora-Cloud-Base-Vagrant-29-1.2.x86_64.vagrant-virtualbox.box
wget https://alt.fedoraproject.org/en/static/checksums/Fedora-Cloud-29-1.2-x86_64-CHECKSUM
sha256sum -c Fedora-Cloud-29-1.2-x86_64-CHECKSUM
vagrant box add Fedora-Cloud-Base-Vagrant-29-1.2.x86_64.vagrant-virtualbox.box --name fedora-cloud-29-local
