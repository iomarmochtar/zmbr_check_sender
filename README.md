See my blog post for description and installation.
The detail background for this script can be seen in [my old blog post](https://iomarmochtar.wordpress.com/2017/09/13/zimbra-prevent-user-customizing-from-header/)

# Installation

- Install package dependencies

```
yum install epel-release
yum install python3-pymilter python3-ldap supervisor git-core
```

- Clone repository

```
cd /opt
git clone --depth=1 --single-branch --branch centos8-python3 https://github.com/iomarmochtar/zmbr_check_sender
```

- Configure daemon process

```
cd zmbr_check_sender/etc
cp daemon.ini /etc/supervisord.d/
```

- Adjust main configuration, see the explanation in mentioned blog post above

```
vim config.ini
```

- Start the service.

```
systemctl enable supervisord
systemctl start supervisord
```
