#!/bin/bash
restart_flag=1
#ostype='kylin'

function checkNas() {
  directory="/nas-share/infolevel"
  if [ ! -d "$directory" ]; then
      echo "目录 $directory 不存在，脚本终止执行!"
      exit 1
  fi
  echo "Nas盘已挂载"
}
function changepasswd() {
    read -p 'Are you sure change password?[y/n]:'
    case $REPLY in
    y)

    # 生成随机密码
    random_password=$(openssl rand -base64 10)

    # 确保满足复杂度要求
    #while [[ ! $(echo $random_password | grep -o [[:upper:]]) || ! $(echo $random_password | grep -o [[:lower:]]) || ! $(echo $random_password | grep -o [[:digit:]]) || ! $(echo $random_password | grep -o [!@#$%^&*]) ]]; do
        #random_password=$(openssl rand -base64 $length | tr -dc 'a-zA-Z0-9!@#$%^&*')
    #done

    echo "随机密码为：$random_password"
    echo "$(hostname) 随机密码为：$random_password">>$resultFile
    echo "$(hostname) $random_password">>$directory/passwd.txt

    # 将密码应用于 root 用户
    echo "root:$random_password" | chpasswd

    if [ $? == 0 ];then
      echo "修改密码成功"
    else
      echo "修改密码失败"
    fi
  	;;
    n)
  	;;
    *)
  	echo -e "\033[31;5m         [##Error##]:invalid input       \033[0m"
  	changepasswd
  	;;
    esac
}
function makeResultFile() {
  #正则筛选ip
  ip=$(hostname)
  if [ ! -d "$directory/$ip" ]; then
      mkdir "$directory/$ip"
  fi
      touch "$directory/$ip/$ip.txt"
      resultFile="$directory/$ip/$ip.txt"
    echo "ip = $ip，整改内容如下:">>$resultFile
    echo "整改报告输出"

}

###########################文件备份############################
function backup(){
if [ ! -x "$directory/$ip/backup" ]; then
    if [ ! -d backup ]; then
        mkdir backup
    fi
    if [ -f /etc/pam.d/system-auth ];then
        cp /etc/pam.d/system-auth backup/system-auth.bak
    elif [ -f /etc/pam.d/common-password ];then
        cp /etc/pam.d/common-password backup/common-password.bak
    fi
    if [ -f ~/.ssh/authorized_keys ];then
        cp ~/.ssh/authorized_keys backup/authorized_keys.bak
    fi
    cp /etc/pam.d/sshd backup/sshd.bak
    cp /etc/sudoers backup/sudoers.bak
    cp /etc/ssh/sshd_config backup/sshd_config.bak
    cp /etc/profile backup/profile.bak
    cp /etc/pam.d/su backup/su.bak
    cp /etc/login.defs backup/login_defs.bak  # 增加备份/etc/login.defs
    cp /etc/logrotate.conf backup/logrotate_conf.bak  # 增加备份/etc/logrotate.conf
    if [ ! -d /nas-share/infolevel/$(hostname) ];then
      mkdir /nas-share/infolevel/$(hostname)
    fi
    cp backup/ /$directory/$(hostname)/
    echo "备份成功"
    #echo -e "###########################################################################################"
    #echo -e "\033[1;31m	    Auto backup successfully	    \033[0m"
    #echo -e "###########################################################################################"
else
    #echo -e "###########################################################################################"
    echo "备份失败"
    #echo -e "###########################################################################################"
fi
}
###########################执行备份############################
backup
###########################文件还原############################
function recover(){
if [ -f backup/system-auth.bak ];then
    cp -rf backup/system-auth.bak /etc/pam.d/system-auth
elif [ -f backup/common-password.bak ];then
    cp -rf backup/common-password.bak /etc/pam.d/common-password
fi
if [ -f backup/authorized_keys.bak ];then
    cp -rf backup/authorized_keys.bak ~/.ssh/authorized_keys
fi
    cp -rf backup/sshd.bak /etc/pam.d/sshd
    cp -rf backup/sudoers.bak /etc/sudoers
    cp -rf backup/sshd_config.bak /etc/ssh/sshd_config
    cp -rf backup/profile.bak /etc/profile
    cp -rf backup/login_defs.bak /etc/login.defs  # 增加还原login.defs
    cp -rf backup/logrotate_conf.bak /etc/logrotate.conf  # 增加还原logrotate.conf
    source /etc/profile
    cp -rf backup/su.bak /etc/pam.d/su
    restart_flag=0
    echo -e "\033[1;31m	   8、 Recover success	\033[0m"
}
###########################口令复杂度设置############################
function password(){
    #echo "#########################################################################################"
    #echo -e "\033[1;31m	    set password complexity requirements	\033[0m"
    #echo "#########################################################################################"

if [ -f /etc/pam.d/system-auth ];then
    config="/etc/pam.d/system-auth"
elif [ -f /etc/pam.d/common-password ];then
    config="/etc/pam.d/common-password"
else
    echo -e "\033[1;31m	    Doesn't support this OS	    \033[0m"
    return 1
fi

    grep -i "^password.*requisite.*pam_cracklib.so" $config  > /dev/null
    if [ $? == 0 ];then
        sed -i "s/^password.*requisite.*pam_cracklib\.so.*$/password    requisite       pam_cracklib.so retry=3 difok=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/g" $config
	#echo -e "\033[1;31m密码修改重试3次机会，新密码与老密码必须有3字符不同，最小密码长度12个字符，包含大写字符至少一个，小写字母至少一个，数字至少一个，特殊字符至少一个\033[0m"
    else
        grep -i "pam_pwquality\.so" $config > /dev/null
        if [ $? == 0 ];then
            sed -i "s/password.*requisite.*pam_pwquality\.so.*$/password     requisite       pam_pwquality.so retry=3 difok=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/g" $config
	    #echo -e "\033[1;31m密码修改重试3次机会，新密码与老密码必须有3字符不同，最小密码长度12个字符，包含大写字符至少一个，小写字母至少一个，数字至少一个，特殊字符至少一个\033[0m"
        else
            echo 'password      requisite       pam_cracklib.so retry=3 difok=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' >> $config
	    #echo -e "\033[1;31m密码修改重试3次机会，新密码与老密码必须有3字符不同，最小密码长度12个字符，包含大写字符至少一个，小写字母至少一个，数字至少一个，特殊字符至少一个\033[0m"
        fi
    fi

    if [ $? == 0 ];then
        echo -e "密码复杂度设置成功"
    else
        echo -e "\033[31;5m	    [Password complexity set failed]	\033[0m"
	exit 1
    fi
}
#######################Logon failure handling################################
function logon(){
    #echo "#########################################################################################"
    #echo -e "\033[1;31m	    set logon failure handling		\033[0m"
    #echo "#########################################################################################"
    logonconfig=/etc/pam.d/sshd
    read -p 'Are you sure set logon failure handling?[y/n]:'
    case $REPLY in
    y)
	grep -i "^auth.*required.*pam_tally2.so.*$" $logonconfig  > /dev/null
	if [ $? == 0 ];then
	   sed -i "s/auth.*required.*pam_tally2.so.*$/auth required pam_tally2.so deny=3 unlock_time=300 even_deny_root root_unlock_time=300/g" $logonconfig > /dev/null
        else
	   sed -i '/^#%PAM-1.0/a\auth required pam_tally2.so deny=3 unlock_time=300 even_deny_root root_unlock_time=300' $logonconfig > /dev/null
        fi

	if [ $? == 0 ];then
	    echo "#########################################################################################"
	    echo -e "\033[37;5m	    [Logon failure handling set success]	\033[0m"
	    echo -e "\033[1;31m限制登入失败三次，普通账号锁定5分钟，root账号锁定5分钟\033[0m"
	    echo "#########################################################################################"
	else
	    echo "#########################################################################################"
	    echo -e "\033[31;5m	    [Logon failure handling set failed]	\033[0m"
	    echo "#########################################################################################"
	    exit 1
	fi
	;;
    n)
	;;
    *)
	echo -e "\033[31;5m         [##Error##]:invalid input       \033[0m"
	logon
	;;
    esac
}
#######################修改系统/etc/login.defs文件中的设置密码长度和定期更换要求参数################################
function loginfail() {
  logonconfig=/etc/pam.d/sshd
  grep -i "^auth.*required.*pam_tally2.so.*$" $logonconfig  > /dev/null
  if [ $? == 0 ];then
    sed -i "s/auth.*required.*pam_tally2.so.*$/auth required pam_tally2.so deny=3 unlock_time=300 even_deny_root root_unlock_time=300/g" $logonconfig > /dev/null
  else
    sed -i '/^#%PAM-1.0/a\auth required pam_tally2.so deny=3 unlock_time=300 even_deny_root root_unlock_time=300' $logonconfig > /dev/null
  fi
  echo "登录失败已处理"
}
function modify_login_defs() {
    #Set logging of successful logins to yes
    LOG_OK_LOGINS="yes"

    #Set logging of unknown usernames when login failures are recorded to yes
    LOG_UNKFAIL_ENAB="yes"

    #Set maximum days between password changes to 90
    PASS_MAX_DAYS="90"

    #Set minimum days before users can change their password to 0
    PASS_MIN_DAYS="0"

    #Set the minimum password length to 8
    PASS_MIN_LEN="8"

    #Set the warning age for password expiration to 7
    PASS_WARN_AGE="7"

    # Read the /etc/login.defs file
    while read line
    do
        #skip comment lines
        if [[ "$line" =~ ^#.* ]]; then
            continue
        fi

        # Check if the line contains LOG_OK_LOGINS
        if [[ $line == *LOG_OK_LOGINS* ]]
        then
            # Replace the line with the new LOG_OK_LOGINS value
            sed -i "s/$line/LOG_OK_LOGINS\t\t$LOG_OK_LOGINS/g" /etc/login.defs
        fi

        # Check if the line contains LOG_UNKFAIL_ENAB
        if [[ $line == *LOG_UNKFAIL_ENAB* ]]
        then
            # Replace the line with the new LOG_UNKFAIL_ENAB value
            sed -i "s/$line/LOG_UNKFAIL_ENAB\t$LOG_UNKFAIL_ENAB/g" /etc/login.defs
        fi

        # Check if the line contains PASS_MAX_DAYS
        if [[ $line == *PASS_MAX_DAYS* ]]
        then
            # Replace the line with the new PASS_MAX_DAYS value
            sed -i "s/$line/PASS_MAX_DAYS\t$PASS_MAX_DAYS/g" /etc/login.defs
        fi

        # Check if the line contains PASS_MIN_DAYS
        if [[ $line == *PASS_MIN_DAYS* ]]
        then
            # Replace the line with the new PASS_MIN_DAYS value
            sed -i "s/$line/PASS_MIN_DAYS\t$PASS_MIN_DAYS/g" /etc/login.defs
        fi

        # Check if the line contains PASS_MIN_LEN
        if [[ $line == *PASS_MIN_LEN* ]]
        then
            # Check if the PASS_MIN_LEN is blank
            if [[ -z $line ]]
            then
                # Append the PASS_MIN_LEN to the end of the /etc/login.defs file
                echo "PASS_MIN_LEN $PASS_MIN_LEN" >> /etc/login.defs
            else
                # Replace the line with the new PASS_MIN_LEN value
                sed -i "s/$line/PASS_MIN_LEN\t$PASS_MIN_LEN/g" /etc/login.defs
            fi
        fi

        # Check if the line contains PASS_WARN_AGE
        if [[ $line == *PASS_WARN_AGE* ]]
        then
            # Replace the line with the new PASS_WARN_AGE value
            sed -i "s/$line/PASS_WARN_AGE\t$PASS_WARN_AGE/g" /etc/login.defs
        fi
    done < /etc/login.defs
}
function serviceDown() {
    systemctl stop postfix
}
function checkResult() {
    echo "等保整改报告">>$resultFile
    echo "报告时间 $(date)">>$resultFile,
    echo "1.身份鉴别-口令复杂度要求">>$resultFile
    grep -i "^password.*requisite.*pam_cracklib.so" /etc/pam.d/system-auth>>$resultFile
    if [ $? == 0 ];then
        echo "密码复杂度:已设置">>$resultFile
    else
        grep -i "pam_pwquality\.so" /etc/pam.d/system-auth>>$resultFile
        if [ $? == 0 ];then
    	echo "密码复杂度:已设置">>$resultFile
        else
    	echo "密码复杂度:未设置,请加固密码--------[需调整]"
        fi
    fi
    #echo "=============================dividing line================================"
    echo "1.身份鉴别-口令过期天数">>$resultFile
    more /etc/login.defs | grep -E "PASS_MAX_DAYS">>$resultFile
    more /etc/login.defs | grep -E "PASS_MAX_DAYS" | grep -v "#" |awk -F' '  '{if($2!=90){print ">>>密码过期天数是"$2"天,请管理员改成90天------[需调整]"}}'
    #echo "=============================dividing line================================"
    echo "2.身份鉴别-登录失败策略">>$resultFile
    grep -i "^auth.*required.*pam_tally2.so.*$" /etc/pam.d/sshd>>$resultFile
    if [ $? == 0 ];then
      echo "登入失败处理:已开启">>$resultFile
    else
      echo "登入失败处理:未开启,请加固登入失败锁定功能----------[需调整]"
    fi
    echo "3.身份鉴别-未采用两种及两种以上身份鉴别技术的组合进行身份鉴别:无法整改">>$resultFile
    echo "4.访问控制-未限制默认账户的远程访问:无法整改">>$resultFile
    echo "5.访问控制-未删除或禁用用户名为“icinga”、“cloud-user”的多余账户">>$resultFile
    echo "icinga用户已锁定，状态如下:">>$resultFile
    cat /etc/shadow| grep icinga>>$resultFile
    echo "cloud-user用户已锁定，状态如下:">>$resultFile
    cat /etc/shadow| grep cloud-user>>$resultFile
    echo "6.访问控制 未对管理的角色进行划分/管理用户未划分管理角色/未授予管理用户所需的最小权限，无法实现权限分离。">>$resultFile
    echo "用户名\t\t用户组\t\t权限">>$resultFile
    echo "----------------------------------------------"
    while IFS=: read -r username _ uid gid _ home shell; do
        group=$(grep ":$gid:" /etc/group | cut -d: -f1)
        permissions=$(sudo -l -U "$username" 2>/dev/null | grep "(ALL) NOPASSWD:" | awk '{print $3}')
        echo -e "$username\t\t$group\t\t$permissions">>$resultFile
    done < /etc/passwd
    echo "7.访问控制 未对重要主体和客体设置安全标记:无法整改">>$resultFile
    echo "8.入侵防范-关闭无用服务：postfix服务状态">>$resultFile
    systemctl status  postfix | grep Active>>$resultFile
    echo "9.恶意代码防范：@紫光云或微信提供">>$resultFile
    echo "10.可信验证:无法整改">>$resultFile
    echo "11.数据完整性：暂未申请服务">>$resultFile
    echo "12.数据备份恢复：暂未申请服务，以下为手动备份">>$resultFile
    echo "备份路径为backup/">>$resultFile
    echo "备份文件如下：">>$resultFile
    ls backup>>$resultFile
    echo "13.数据备份恢复:异地机房 无法整改">>$resultFile
    echo "14.数据备份恢复:热冗余部署 微信整理提供">>$resultFile
}
function abandonUser() {
  echo "禁用账户icinga,cloud-user:"
  #重启usermod -p password icinga
  usermod -L icinga
  usermod -L cloud-user

}
function userControl() {
  echo "访问控制-用户组及最小用户"
  groupadd sysgroup
  createUser sysadmin
  usermod -G sysgroup sysadmin

  groupadd secgroup
  createUser secadmin
  usermod -G secgroup secadmin
  chown -R secadmin:secadmin /etc
  chmod 700 /etc
  groupadd auditgroup
  createUser auditadmin
  usermod -G auditgroup auditadmin
  #echo "auditadmin     ALL = (root) NOPASSWD: /usr/bin/cat, /usr/bin/less, /usr/bin/more, /usr/bin/tail, /usr/bin/head" | tee -a /etc/sudoers
  chown -R auditadmin:auditadmin /var/log
  chmod 700 /var/log
}
function createUser(){

  local username=$1
  local password='H3c#12#$'
  useradd "$username"
  echo "$username:$password" | chpasswd
  echo "用户已创建：'$1'"
}
function  main() {
    checkNas
    password
    makeResultFile
    changepasswd
    loginfail
    abandonUser
    modify_login_defs
    serviceDown
    userControl
    checkResult
}
main
