#等保脚本练习
#溯源

查看postfix 是否启动：systemctl status postfix

关闭邮件服务：systemctl stop postfix

打开postfix启动：systemctl start postfix

关闭开机自动启动postfix服务： systemctl disable postfix

开启开机自启动postfix服务：systemctl enable postfix
