# -*- mode: ruby -*-
# vi: set ft=ruby :

$script = <<-SCRIPT
sudo dnf upgrade -y
sudo dnf group install 'C Development Tools and Libraries' -y
sudo dnf install cmake clang rpm-devel unbound-devel bind-utils tcpdump knot-resolver libcmocka-devel -y
echo "policy.add(policy.all(policy.TLS_FORWARD({{'1.1.1.1', hostname='cloudflare-dns.com', ca_file='/etc/pki/tls/certs/ca-bundle.crt'}})))" >> /etc/knot-resolver/kresd.conf
systemctl enable --now kresd@1.service
sudo nmcli con mod 'System eth0' ipv4.ignore-auto-dns yes
sudo nmcli con mod 'System eth0' ipv4.dns '127.0.0.1'
echo 'nameserver 127.0.0.1 > /etc/resolv.conf'
SCRIPT

Vagrant.configure("2") do |config|
  config.vm.box = "fedora-cloud-29-local"
  config.vm.provision "shell", inline: $script 
end
