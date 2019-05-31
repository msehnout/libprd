# -*- mode: ruby -*-
# vi: set ft=ruby :

$script = <<-SCRIPT
sudo dnf upgrade -y
sudo dnf group install 'C Development Tools and Libraries' -y
sudo dnf install cmake clang rpm-devel unbound-devel -y
SCRIPT

Vagrant.configure("2") do |config|
  config.vm.box = "fedora-cloud-29-local"
  config.vm.provision "shell", inline: $script 
end
