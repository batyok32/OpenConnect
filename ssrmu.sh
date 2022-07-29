#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS 6+/Debian 6+/Ubuntu 14.04+
#	Description: Install the ShadowsocksR mudbjson server
#	Version: 1.0.27
#	Author: translated by den4ik
#	Blog: https://doub.io/ss-jc60/
#=================================================

sh_ver="1.0.26"
filepath=$(cd "$(dirname "$0")"; pwd)
file=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
ssr_folder="/usr/local/shadowsocksr"
config_file="${ssr_folder}/config.json"
config_user_file="${ssr_folder}/user-config.json"
config_user_api_file="${ssr_folder}/userapiconfig.py"
config_user_mudb_file="${ssr_folder}/mudb.json"
ssr_log_file="${ssr_folder}/ssserver.log"
Libsodiumr_file="/usr/local/lib/libsodium.so"
Libsodiumr_ver_backup="1.0.15"
Server_Speeder_file="/serverspeeder/bin/serverSpeeder.sh"
LotServer_file="/appex/bin/serverSpeeder.sh"
BBR_file="${file}/bbr.sh"
jq_file="${ssr_folder}/jq"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[данные]${Font_color_suffix}"
Error="${Red_font_prefix}[ошибка]${Font_color_suffix}"
Tip="${Green_font_prefix}[внимание]${Font_color_suffix}"
Separator_1="——————————————————————————————"

check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} Текущий пользователь не является ROOT(или не имеет прав ROOT, вы не можете продолжить операцию ${Green_background_prefix} sudo su ${Font_color_suffix}Для получения временных ROOT-прав (после выполнения вам будет предложено ввести пароль текущей учетной записи)." && exit 1
}
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	bit=`uname -m`
}
check_pid(){
	PID=`ps -ef |grep -v grep | grep server.py |awk '{print $2}'`
}
check_crontab(){
	[[ ! -e "/usr/bin/crontab" ]] && echo -e "${Error} Отсутствуют зависимости Crontab ，Установите его вручную CentOS: yum install crond -y , Debian/Ubuntu: apt-get install cron -y !" && exit 1
}
SSR_installation_status(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} Папка ShadowsocksR не найдена, пожалуйста, проверьте !" && exit 1
}
Server_Speeder_installation_status(){
	[[ ! -e ${Server_Speeder_file} ]] && echo -e "${Error} Резкая скорость не установлена(Server Speeder)，Пожалуйста, проверьте !" && exit 1
}
LotServer_installation_status(){
	[[ ! -e ${LotServer_file} ]] && echo -e "${Error} Не установлен LotServer，Пожалуйста, проверьте !" && exit 1
}
BBR_installation_status(){
	if [[ ! -e ${BBR_file} ]]; then
		echo -e "${Error} Скрипт BBR не найден, начните загрузку..."
		cd "${file}"
		if ! wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/bbr.sh; then
			echo -e "${Error} BBR Ошибка загрузки скрипта !" && exit 1
		else
			echo -e "${Info} BBR Загрузка скрипта завершена !"
			chmod +x bbr.sh
		fi
	fi
}
# Установите правила брандмауэра
Add_iptables(){
	if [[ ! -z "${ssr_port}" ]]; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
	fi
}
Del_iptables(){
	if [[ ! -z "${port}" ]]; then
		iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
	fi
}
Save_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
	fi
}
Set_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
		chkconfig --level 2345 iptables on
		chkconfig --level 2345 ip6tables on
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
		echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' > /etc/network/if-pre-up.d/iptables
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
}
# Считывание информации о конфигурации
Get_IP(){
	ip=$(wget -qO- -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ip}" ]]; then
		ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ip}" ]]; then
			ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ip}" ]]; then
				ip="VPS_IP"
			fi
		fi
	fi
}
Get_User_info(){
	Get_user_port=$1
	user_info_get=$(python mujson_mgr.py -l -p "${Get_user_port}")
	match_info=$(echo "${user_info_get}"|grep -w "### user ")
	if [[ -z "${match_info}" ]]; then
		echo -e "${Error} Не удалось получить информацию о пользователе ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	fi
	user_name=$(echo "${user_info_get}"|grep -w "user :"|awk -F "user : " '{print $NF}')
	port=$(echo "${user_info_get}"|grep -w "port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	password=$(echo "${user_info_get}"|grep -w "passwd :"|awk -F "passwd : " '{print $NF}')
	method=$(echo "${user_info_get}"|grep -w "method :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol=$(echo "${user_info_get}"|grep -w "protocol :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol_param=$(echo "${user_info_get}"|grep -w "protocol_param :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${protocol_param} ]] && protocol_param="0(неограниченный)"
	obfs=$(echo "${user_info_get}"|grep -w "obfs :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#transfer_enable=$(echo "${user_info_get}"|grep -w "transfer_enable :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}'|awk -F "ytes" '{print $1}'|sed 's/KB/ KB/;s/MB/ MB/;s/GB/ GB/;s/TB/ TB/;s/PB/ PB/')
	#u=$(echo "${user_info_get}"|grep -w "u :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#d=$(echo "${user_info_get}"|grep -w "d :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	forbidden_port=$(echo "${user_info_get}"|grep -w "forbidden_port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${forbidden_port} ]] && forbidden_port="неограниченный"
	speed_limit_per_con=$(echo "${user_info_get}"|grep -w "speed_limit_per_con :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	speed_limit_per_user=$(echo "${user_info_get}"|grep -w "speed_limit_per_user :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	Get_User_transfer "${port}"
}
Get_User_transfer(){
	transfer_port=$1
	#echo "transfer_port=${transfer_port}"
	all_port=$(${jq_file} '.[]|.port' ${config_user_mudb_file})
	#echo "all_port=${all_port}"
	port_num=$(echo "${all_port}"|grep -nw "${transfer_port}"|awk -F ":" '{print $1}')
	#echo "port_num=${port_num}"
	port_num_1=$(echo $((${port_num}-1)))
	#echo "port_num_1=${port_num_1}"
	transfer_enable_1=$(${jq_file} ".[${port_num_1}].transfer_enable" ${config_user_mudb_file})
	#echo "transfer_enable_1=${transfer_enable_1}"
	u_1=$(${jq_file} ".[${port_num_1}].u" ${config_user_mudb_file})
	#echo "u_1=${u_1}"
	d_1=$(${jq_file} ".[${port_num_1}].d" ${config_user_mudb_file})
	#echo "d_1=${d_1}"
	transfer_enable_Used_2_1=$(echo $((${u_1}+${d_1})))
	#echo "transfer_enable_Used_2_1=${transfer_enable_Used_2_1}"
	transfer_enable_Used_1=$(echo $((${transfer_enable_1}-${transfer_enable_Used_2_1})))
	#echo "transfer_enable_Used_1=${transfer_enable_Used_1}"
	
	if [[ ${transfer_enable_1} -lt 1024 ]]; then
		transfer_enable="${transfer_enable_1} B"
	elif [[ ${transfer_enable_1} -lt 1048576 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1024'}')
		transfer_enable="${transfer_enable} KB"
	elif [[ ${transfer_enable_1} -lt 1073741824 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1048576'}')
		transfer_enable="${transfer_enable} MB"
	elif [[ ${transfer_enable_1} -lt 1099511627776 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1073741824'}')
		transfer_enable="${transfer_enable} GB"
	elif [[ ${transfer_enable_1} -lt 1125899906842624 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1099511627776'}')
		transfer_enable="${transfer_enable} TB"
	fi
	#echo "transfer_enable=${transfer_enable}"
	if [[ ${u_1} -lt 1024 ]]; then
		u="${u_1} B"
	elif [[ ${u_1} -lt 1048576 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1024'}')
		u="${u} KB"
	elif [[ ${u_1} -lt 1073741824 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1048576'}')
		u="${u} MB"
	elif [[ ${u_1} -lt 1099511627776 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1073741824'}')
		u="${u} GB"
	elif [[ ${u_1} -lt 1125899906842624 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1099511627776'}')
		u="${u} TB"
	fi
	#echo "u=${u}"
	if [[ ${d_1} -lt 1024 ]]; then
		d="${d_1} B"
	elif [[ ${d_1} -lt 1048576 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1024'}')
		d="${d} KB"
	elif [[ ${d_1} -lt 1073741824 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1048576'}')
		d="${d} MB"
	elif [[ ${d_1} -lt 1099511627776 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1073741824'}')
		d="${d} GB"
	elif [[ ${d_1} -lt 1125899906842624 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1099511627776'}')
		d="${d} TB"
	fi
	#echo "d=${d}"
	if [[ ${transfer_enable_Used_1} -lt 1024 ]]; then
		transfer_enable_Used="${transfer_enable_Used_1} B"
	elif [[ ${transfer_enable_Used_1} -lt 1048576 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1024'}')
		transfer_enable_Used="${transfer_enable_Used} KB"
	elif [[ ${transfer_enable_Used_1} -lt 1073741824 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1048576'}')
		transfer_enable_Used="${transfer_enable_Used} MB"
	elif [[ ${transfer_enable_Used_1} -lt 1099511627776 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1073741824'}')
		transfer_enable_Used="${transfer_enable_Used} GB"
	elif [[ ${transfer_enable_Used_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1099511627776'}')
		transfer_enable_Used="${transfer_enable_Used} TB"
	fi
	#echo "transfer_enable_Used=${transfer_enable_Used}"
	if [[ ${transfer_enable_Used_2_1} -lt 1024 ]]; then
		transfer_enable_Used_2="${transfer_enable_Used_2_1} B"
	elif [[ ${transfer_enable_Used_2_1} -lt 1048576 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1024'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} KB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1073741824 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1048576'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} MB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1099511627776 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1073741824'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} GB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1099511627776'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} TB"
	fi
	#echo "transfer_enable_Used_2=${transfer_enable_Used_2}"
}
Get_User_transfer_all(){
	if [[ ${transfer_enable_Used_233} -lt 1024 ]]; then
		transfer_enable_Used_233_2="${transfer_enable_Used_233} B"
	elif [[ ${transfer_enable_Used_233} -lt 1048576 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1024'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} KB"
	elif [[ ${transfer_enable_Used_233} -lt 1073741824 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1048576'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} MB"
	elif [[ ${transfer_enable_Used_233} -lt 1099511627776 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1073741824'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} GB"
	elif [[ ${transfer_enable_Used_233} -lt 1125899906842624 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1099511627776'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} TB"
	fi
}
urlsafe_base64(){
	date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
	echo -e "${date}"
}
ss_link_qr(){
	SSbase64=$(urlsafe_base64 "${method}:${password}@${ip}:${port}")
	SSurl="ss://${SSbase64}"
	SSQRcode="http://doub.pw/qr/qr.php?text=${SSurl}"
	ss_link=" SS    ссылка : ${Green_font_prefix}${SSurl}${Font_color_suffix} \n SS  QR-код : ${Green_font_prefix}${SSQRcode}${Font_color_suffix}"
}
ssr_link_qr(){
	SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
	SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
	SSRPWDbase64=$(urlsafe_base64 "${password}")
	SSRbase64=$(urlsafe_base64 "${ip}:${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}")
	SSRurl="ssr://${SSRbase64}"
	SSRQRcode="http://doub.pw/qr/qr.php?text=${SSRurl}"
	ssr_link=" SSR   ссылка : ${Red_font_prefix}${SSRurl}${Font_color_suffix} \n SSR QR-код : ${Red_font_prefix}${SSRQRcode}${Font_color_suffix} \n "
}
ss_ssr_determine(){
	protocol_suffix=`echo ${protocol} | awk -F "_" '{print $NF}'`
	obfs_suffix=`echo ${obfs} | awk -F "_" '{print $NF}'`
	if [[ ${protocol} = "origin" ]]; then
		if [[ ${obfs} = "plain" ]]; then
			ss_link_qr
			ssr_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				ss_link=""
			else
				ss_link_qr
			fi
		fi
	else
		if [[ ${protocol_suffix} != "compatible" ]]; then
			ss_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				if [[ ${obfs_suffix} = "plain" ]]; then
					ss_link_qr
				else
					ss_link=""
				fi
			else
				ss_link_qr
			fi
		fi
	fi
	ssr_link_qr
}
# Отображение информации о конфигурации
View_User(){
	SSR_installation_status
	List_port_user
	while true
	do
		echo -e "Пожалуйста, введите порт пользователя, в котором вы хотите просмотреть информацию об учетной записи"
		read -e -p "(По умолчанию: отмена):" View_user_port
		[[ -z "${View_user_port}" ]] && echo -e "отмена..." && exit 1
		View_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${View_user_port}"',')
		if [[ ! -z ${View_user} ]]; then
			Get_User_info "${View_user_port}"
			View_User_info
			break
		else
			echo -e "${Error} Пожалуйста, введите правильный порт !"
		fi
	done
}
View_User_info(){
	ip=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	[[ -z "${ip}" ]] && Get_IP
	ss_ssr_determine
	clear && echo "===================================================" && echo
	echo -e " 用户 [${user_name}] 的配置信息：" && echo
	echo -e " I  P\t    : ${Green_font_prefix}${ip}${Font_color_suffix}"
	echo -e " порт\t    : ${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " пароль\t    : ${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " метод шифрования\t    : ${Green_font_prefix}${method}${Font_color_suffix}"
	echo -e " протокол\t    : ${Red_font_prefix}${protocol}${Font_color_suffix}"
	echo -e " obfs\t    : ${Red_font_prefix}${obfs}${Font_color_suffix}"
	echo -e " Ограничение на количество устройств : ${Green_font_prefix}${protocol_param}${Font_color_suffix}"
	echo -e " Однопоточное ограничение скорости : ${Green_font_prefix}${speed_limit_per_con} KB/S${Font_color_suffix}"
	echo -e " Общее ограничение скорости пользователя : ${Green_font_prefix}${speed_limit_per_user} KB/S${Font_color_suffix}"
	echo -e " Запрещенные порты : ${Green_font_prefix}${forbidden_port} ${Font_color_suffix}"
	echo
	echo -e " Использованный трафик : загружено: ${Green_font_prefix}${u}${Font_color_suffix} + загружено: ${Green_font_prefix}${d}${Font_color_suffix} = ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix}"
	echo -e " Оставшийся трафик : ${Green_font_prefix}${transfer_enable_Used} ${Font_color_suffix}"
	echo -e " Общий пользовательский трафик : ${Green_font_prefix}${transfer_enable} ${Font_color_suffix}"
	echo -e "${ss_link}"
	echo -e "${ssr_link}"
	echo -e " ${Green_font_prefix} подсказка: ${Font_color_suffix}
 В браузере откройте ссылку на QR-код, и вы увидите изображение QR-кода.
 За согласием и неразберихой[ _compatible ]，Относится к совместимости с исходным протоколом/запутыванию."
	echo && echo "==================================================="
}
# Установите информацию о конфигурации
Set_config_user(){
	echo "Пожалуйста, введите имя пользователя, которое вы хотите установить (пожалуйста, не повторяйте его, оно используется для различения, китайский язык и пробелы не поддерживаются, и будет сообщено об ошибке !)"
	read -e -p "(по умолчанию: doubi):" ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="doubi"
	ssr_user=$(echo "${ssr_user}"|sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "	имя пользователя : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_port(){
	while true
	do
	echo -e "Пожалуйста, введите пользовательский порт, который вы хотите установить(Не повторяйте, используется для различения)"
	read -e -p "(по умолчанию: 2333):" ssr_port
	[[ -z "$ssr_port" ]] && ssr_port="2333"
	echo $((${ssr_port}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]; then
			echo && echo ${Separator_1} && echo -e "	порт : ${Green_font_prefix}${ssr_port}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Пожалуйста, введите правильный номер(1-65535)"
		fi
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-65535)"
	fi
	done
}
Set_config_password(){
	echo "Пожалуйста, введите пароль пользователя, который вы хотите установить"
	read -e -p "(по умолчанию: doub.io):" ssr_password
	[[ -z "${ssr_password}" ]] && ssr_password="doub.io"
	echo && echo ${Separator_1} && echo -e "	код : ${Green_font_prefix}${ssr_password}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_method(){
	echo -e "Пожалуйста, выберите метод шифрования пользователя, который вы хотите установить
	
 ${Green_font_prefix} 1.${Font_color_suffix} none
 ${Tip} Если используется auth_chain_* Серии протоколов, рекомендуется выбрать метод шифрования none (Эта серия протоколов поставляется с RC4 шифрованием)，Запутанный по желанию
 
 ${Green_font_prefix} 2.${Font_color_suffix} rc4
 ${Green_font_prefix} 3.${Font_color_suffix} rc4-md5
 ${Green_font_prefix} 4.${Font_color_suffix} rc4-md5-6
 
 ${Green_font_prefix} 5.${Font_color_suffix} aes-128-ctr
 ${Green_font_prefix} 6.${Font_color_suffix} aes-192-ctr
 ${Green_font_prefix} 7.${Font_color_suffix} aes-256-ctr
 
 ${Green_font_prefix} 8.${Font_color_suffix} aes-128-cfb
 ${Green_font_prefix} 9.${Font_color_suffix} aes-192-cfb
 ${Green_font_prefix}10.${Font_color_suffix} aes-256-cfb
 
 ${Green_font_prefix}11.${Font_color_suffix} aes-128-cfb8
 ${Green_font_prefix}12.${Font_color_suffix} aes-192-cfb8
 ${Green_font_prefix}13.${Font_color_suffix} aes-256-cfb8
 
 ${Green_font_prefix}14.${Font_color_suffix} salsa20
 ${Green_font_prefix}15.${Font_color_suffix} chacha20
 ${Green_font_prefix}16.${Font_color_suffix} chacha20-ietf
 ${Tip} salsa20/chacha20-*Ряд методов шифрования, требуется дополнительная установка. libsodium ，В противном случае он не запуститсяShadowsocksR !" && echo
	read -e -p "(по умолчанию: 5. aes-128-ctr):" ssr_method
	[[ -z "${ssr_method}" ]] && ssr_method="5"
	if [[ ${ssr_method} == "1" ]]; then
		ssr_method="none"
	elif [[ ${ssr_method} == "2" ]]; then
		ssr_method="rc4"
	elif [[ ${ssr_method} == "3" ]]; then
		ssr_method="rc4-md5"
	elif [[ ${ssr_method} == "4" ]]; then
		ssr_method="rc4-md5-6"
	elif [[ ${ssr_method} == "5" ]]; then
		ssr_method="aes-128-ctr"
	elif [[ ${ssr_method} == "6" ]]; then
		ssr_method="aes-192-ctr"
	elif [[ ${ssr_method} == "7" ]]; then
		ssr_method="aes-256-ctr"
	elif [[ ${ssr_method} == "8" ]]; then
		ssr_method="aes-128-cfb"
	elif [[ ${ssr_method} == "9" ]]; then
		ssr_method="aes-192-cfb"
	elif [[ ${ssr_method} == "10" ]]; then
		ssr_method="aes-256-cfb"
	elif [[ ${ssr_method} == "11" ]]; then
		ssr_method="aes-128-cfb8"
	elif [[ ${ssr_method} == "12" ]]; then
		ssr_method="aes-192-cfb8"
	elif [[ ${ssr_method} == "13" ]]; then
		ssr_method="aes-256-cfb8"
	elif [[ ${ssr_method} == "14" ]]; then
		ssr_method="salsa20"
	elif [[ ${ssr_method} == "15" ]]; then
		ssr_method="chacha20"
	elif [[ ${ssr_method} == "16" ]]; then
		ssr_method="chacha20-ietf"
	else
		ssr_method="aes-128-ctr"
	fi
	echo && echo ${Separator_1} && echo -e "	шифрование : ${Green_font_prefix}${ssr_method}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_protocol(){
	echo -e "Пожалуйста, выберите подключаемый протокол, который вы хотите настроить
	
 ${Green_font_prefix}1.${Font_color_suffix} origin
 ${Green_font_prefix}2.${Font_color_suffix} auth_sha1_v4
 ${Green_font_prefix}3.${Font_color_suffix} auth_aes128_md5
 ${Green_font_prefix}4.${Font_color_suffix} auth_aes128_sha1
 ${Green_font_prefix}5.${Font_color_suffix} auth_chain_a
 ${Green_font_prefix}6.${Font_color_suffix} auth_chain_b
 ${Tip} Если используется auth_chain_* Серии протоколов, рекомендуется выбрать метод шифрования none (Эта серия протоколов поставляется с RC4 шифрование)，Запутанный по желанию" && echo
	read -e -p "(по умолчанию: 3. auth_aes128_md5):" ssr_protocol
	[[ -z "${ssr_protocol}" ]] && ssr_protocol="3"
	if [[ ${ssr_protocol} == "1" ]]; then
		ssr_protocol="origin"
	elif [[ ${ssr_protocol} == "2" ]]; then
		ssr_protocol="auth_sha1_v4"
	elif [[ ${ssr_protocol} == "3" ]]; then
		ssr_protocol="auth_aes128_md5"
	elif [[ ${ssr_protocol} == "4" ]]; then
		ssr_protocol="auth_aes128_sha1"
	elif [[ ${ssr_protocol} == "5" ]]; then
		ssr_protocol="auth_chain_a"
	elif [[ ${ssr_protocol} == "6" ]]; then
		ssr_protocol="auth_chain_b"
	else
		ssr_protocol="auth_aes128_md5"
	fi
	echo && echo ${Separator_1} && echo -e "	протокол : ${Green_font_prefix}${ssr_protocol}${Font_color_suffix}" && echo ${Separator_1} && echo
	if [[ ${ssr_protocol} != "origin" ]]; then
		if [[ ${ssr_protocol} == "auth_sha1_v4" ]]; then
			read -e -p "Следует ли настроить подключаемый модуль протокола на совместимость с исходной версией(_compatible)？[Y/n]" ssr_protocol_yn
			[[ -z "${ssr_protocol_yn}" ]] && ssr_protocol_yn="y"
			[[ $ssr_protocol_yn == [Yy] ]] && ssr_protocol=${ssr_protocol}"_compatible"
			echo
		fi
	fi
}
Set_config_obfs(){
	echo -e "Пожалуйста, выберите подключаемый модуль для обфускации пользователя, который вы хотите настроить
	
 ${Green_font_prefix}1.${Font_color_suffix} plain
 ${Green_font_prefix}2.${Font_color_suffix} http_simple
 ${Green_font_prefix}3.${Font_color_suffix} http_post
 ${Green_font_prefix}4.${Font_color_suffix} random_head
 ${Green_font_prefix}5.${Font_color_suffix} tls1.2_ticket_auth
 ${Tip} Если используется ShadowsocksR Прокси-игру рекомендуется выбирать, чтобы ее не путали с оригинальной версией или plain Запутать, а затем клиент выбирает plain，В противном случае это увеличит задержку !
 другие, Если вы выберете tls1.2_ticket_auth，Затем клиент может выбрать tls1.2_ticket_fastauth，Таким образом, его можно замаскировать, не увеличивая задержку !
 Если вы строите в популярных районах, таких как Япония и Соединенные Штаты, тогда выбирайте plain Путаница может с меньшей вероятностью быть заблокирована !" && echo
	read -e -p "(по умолчанию: 1. plain):" ssr_obfs
	[[ -z "${ssr_obfs}" ]] && ssr_obfs="1"
	if [[ ${ssr_obfs} == "1" ]]; then
		ssr_obfs="plain"
	elif [[ ${ssr_obfs} == "2" ]]; then
		ssr_obfs="http_simple"
	elif [[ ${ssr_obfs} == "3" ]]; then
		ssr_obfs="http_post"
	elif [[ ${ssr_obfs} == "4" ]]; then
		ssr_obfs="random_head"
	elif [[ ${ssr_obfs} == "5" ]]; then
		ssr_obfs="tls1.2_ticket_auth"
	else
		ssr_obfs="plain"
	fi
	echo && echo ${Separator_1} && echo -e "	запутывать : ${Green_font_prefix}${ssr_obfs}${Font_color_suffix}" && echo ${Separator_1} && echo
	if [[ ${ssr_obfs} != "plain" ]]; then
			read -e -p "Следует ли устанавливать плагин запутывания, совместимый с оригинальной версией(_compatible)？[Y/n]" ssr_obfs_yn
			[[ -z "${ssr_obfs_yn}" ]] && ssr_obfs_yn="y"
			[[ $ssr_obfs_yn == [Yy] ]] && ssr_obfs=${ssr_obfs}"_compatible"
			echo
	fi
}
Set_config_protocol_param(){
	while true
	do
	echo -e "Пожалуйста, введите количество устройств, которые пользователь хочет установить, и количество устройств, которые пользователь хочет ограничить (${Green_font_prefix} auth_* Действителен только в том случае, если он несовместим с оригинальной версией ${Font_color_suffix})"
	echo -e "${Tip} Ограничение на количество устройств: количество клиентов, к которым каждый порт может подключаться одновременно (многопортовый режим, каждый порт рассчитывается независимо), рекомендуется иметь не менее 2."
	read -e -p "(Значение по умолчанию: неограниченное):" ssr_protocol_param
	[[ -z "$ssr_protocol_param" ]] && ssr_protocol_param="" && echo && break
	echo $((${ssr_protocol_param}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_protocol_param} -ge 1 ]] && [[ ${ssr_protocol_param} -le 9999 ]]; then
			echo && echo ${Separator_1} && echo -e "	Ограничение на количество устройств : ${Green_font_prefix}${ssr_protocol_param}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Пожалуйста, введите правильный номер(1-9999)"
		fi
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-9999)"
	fi
	done
}
Set_config_speed_limit_per_con(){
	while true
	do
	echo -e "Пожалуйста, введите верхний предел установленного пользователем ограничения скорости в одном потоке(единица：KB/S)"
	echo -e "${Tip} Ограничение скорости для одного потока: Верхний предел ограничения скорости для одного потока на порт недопустим для многопоточности."
	read -e -p "(Значение по умолчанию: неограниченное):" ssr_speed_limit_per_con
	[[ -z "$ssr_speed_limit_per_con" ]] && ssr_speed_limit_per_con=0 && echo && break
	echo $((${ssr_speed_limit_per_con}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_con} -ge 1 ]] && [[ ${ssr_speed_limit_per_con} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e "	Однопоточное ограничение скорости : ${Green_font_prefix}${ssr_speed_limit_per_con} KB/S${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Пожалуйста, введите правильный номер(1-131072)"
		fi
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-131072)"
	fi
	done
}
Set_config_speed_limit_per_user(){
	while true
	do
	echo
	echo -e "Пожалуйста, введите верхний предел общего ограничения скорости пользователя, которого вы хотите установить(единица：KB/S)"
	echo -e "${Tip} Общее ограничение скорости порта: верхний предел общего ограничения скорости каждого порта и общего ограничения скорости одного порта."
	read -e -p "(Значение по умолчанию: неограниченное):" ssr_speed_limit_per_user
	[[ -z "$ssr_speed_limit_per_user" ]] && ssr_speed_limit_per_user=0 && echo && break
	echo $((${ssr_speed_limit_per_user}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_user} -ge 1 ]] && [[ ${ssr_speed_limit_per_user} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e "	Общее ограничение скорости пользователя : ${Green_font_prefix}${ssr_speed_limit_per_user} KB/S${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Пожалуйста, введите правильный номер(1-131072)"
		fi
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-131072)"
	fi
	done
}
Set_config_transfer(){
	while true
	do
	echo
	echo -e "Пожалуйста, введите общий лимит трафика, который может использовать пользователь, которого вы хотите установить(единица: GB, 1-838868 GB)"
	read -e -p "(Значение по умолчанию: неограниченное):" ssr_transfer
	[[ -z "$ssr_transfer" ]] && ssr_transfer="838868" && echo && break
	echo $((${ssr_transfer}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_transfer} -ge 1 ]] && [[ ${ssr_transfer} -le 838868 ]]; then
			echo && echo ${Separator_1} && echo -e "	Общий пользовательский трафик : ${Green_font_prefix}${ssr_transfer} GB${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Пожалуйста, введите правильный номер(1-838868)"
		fi
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-838868)"
	fi
	done
}
Set_config_forbid(){
	echo "Пожалуйста, введите порт, доступ к которому пользователю, которого вы хотите настроить, запрещен"
	echo -e "${Tip} Запрещенные порты：Например, доступ запрещен 25порт，Пользователи не смогут получить доступ к почтовому порту 25 через SSR прокси，Если это запрещено 80,443 Тогда пользователь не сможет получить обычный доступ http/https сайт。
Формат блока с одним портом: 25
Блокировать несколько форматов портов: 23,465
Формат сегмента блочного порта: 233-266
Блокировать порты нескольких форматов: 25,465,233-666 (Без двоеточия:)"
	read -e -p "(Значение по умолчанию пусто и не запрещает доступ к какому-либо порту):" ssr_forbid
	[[ -z "${ssr_forbid}" ]] && ssr_forbid=""
	echo && echo ${Separator_1} && echo -e "	Запрещенные порты : ${Green_font_prefix}${ssr_forbid}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_enable(){
	user_total=$(echo $((${user_total}-1)))
	for((integer = 0; integer <= ${user_total}; integer++))
	do
		echo -e "integer=${integer}"
		port_jq=$(${jq_file} ".[${integer}].port" "${config_user_mudb_file}")
		echo -e "port_jq=${port_jq}"
		if [[ "${ssr_port}" == "${port_jq}" ]]; then
			enable=$(${jq_file} ".[${integer}].enable" "${config_user_mudb_file}")
			echo -e "enable=${enable}"
			[[ "${enable}" == "null" ]] && echo -e "${Error} Получить текущий порт[${ssr_port}]Сбой в отключенном состоянии !" && exit 1
			ssr_port_num=$(cat "${config_user_mudb_file}"|grep -n '"port": '${ssr_port}','|awk -F ":" '{print $1}')
			echo -e "ssr_port_num=${ssr_port_num}"
			[[ "${ssr_port_num}" == "null" ]] && echo -e "${Error} Получить текущий порт[${ssr_port}]Количество строк не удалось !" && exit 1
			ssr_enable_num=$(echo $((${ssr_port_num}-5)))
			echo -e "ssr_enable_num=${ssr_enable_num}"
			break
		fi
	done
	if [[ "${enable}" == "1" ]]; then
		echo -e "порт [${ssr_port}] Статус учетной записи является：${Green_font_prefix}задействовать${Font_color_suffix} , Следует ли переключаться на ${Red_font_prefix}запрещать${Font_color_suffix} ?[Y/n]"
		read -e -p "(по умолчанию: Y):" ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn="y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="0"
		else
			echo "отмена..." && exit 0
		fi
	elif [[ "${enable}" == "0" ]]; then
		echo -e "порт [${ssr_port}] Статус учетной записи является：${Green_font_prefix}запрещать${Font_color_suffix} , Следует ли переключаться на ${Red_font_prefix}задействовать${Font_color_suffix} ?[Y/n]"
		read -e -p "(по умолчанию: Y):" ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn = "y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="1"
		else
			echo "отмена..." && exit 0
		fi
	else
		echo -e "${Error} Отключенное состояние текущего порта является ненормальным[${enable}] !" && exit 1
	fi
}
Set_user_api_server_pub_addr(){
	addr=$1
	if [[ "${addr}" == "Modify" ]]; then
		server_pub_addr=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
		if [[ -z ${server_pub_addr} ]]; then
			echo -e "${Error} Не удалось получить текущий настроенный IP-адрес сервера или доменное имя!" && exit 1
		else
			echo -e "${Info} Текущий настроенный IP-адрес сервера или доменное имя： ${Green_font_prefix}${server_pub_addr}${Font_color_suffix}"
		fi
	fi
	echo "Пожалуйста, введите IP-адрес сервера или доменное имя, которые будут отображаться в конфигурации пользователя (Если сервер имеет несколько IP-адресов, вы можете указать IP-адрес или доменное имя, отображаемое в конфигурации пользователя)"
	read -e -p "(Автоматическое определение IP-адреса внешней сети по умолчанию):" ssr_server_pub_addr
	if [[ -z "${ssr_server_pub_addr}" ]]; then
		Get_IP
		if [[ ${ip} == "VPS_IP" ]]; then
			while true
			do
			read -e -p "${Error} Автоматическое определение IP-адреса внешней сети не удалось, пожалуйста, вручную введите IP-адрес сервера или доменное имя" ssr_server_pub_addr
			if [[ -z "$ssr_server_pub_addr" ]]; then
				echo -e "${Error} Не может быть пусто!"
			else
				break
			fi
			done
		else
			ssr_server_pub_addr="${ip}"
		fi
	fi
	echo && echo ${Separator_1} && echo -e "	IP-адрес или доменное имя : ${Green_font_prefix}${ssr_server_pub_addr}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_all(){
	lal=$1
	if [[ "${lal}" == "Modify" ]]; then
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	else
		Set_config_user
		Set_config_port
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	fi
}
# Изменение информации о конфигурации
Modify_config_password(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -k "${ssr_password}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить пароль пользователя ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Пароль пользователя был успешно изменен ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} (Примечание: Может потребоваться около десяти секунд, прежде чем будет применена последняя конфигурация)"
	fi
}
Modify_config_method(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -m "${ssr_method}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить метод шифрования пользователя ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Метод шифрования пользователя был успешно изменен ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} (Примечание: Может потребоваться около десяти секунд, прежде чем будет применена последняя конфигурация)"
	fi
}
Modify_config_protocol(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -O "${ssr_protocol}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось внести изменения в пользовательское соглашение ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Пользовательское соглашение было успешно изменено ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} (Примечание: Может потребоваться около десяти секунд, прежде чем будет применена последняя конфигурация)"
	fi
}
Modify_config_obfs(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -o "${ssr_obfs}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Ошибка изменения путаницы пользователя не удалась ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Пользователь успешно запутал и изменил ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} (Примечание: Может потребоваться около десяти секунд, прежде чем будет применена последняя конфигурация)"
	fi
}
Modify_config_protocol_param(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -G "${ssr_protocol_param}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить параметры пользовательского соглашения (ограничение на количество устройств) ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Рекомендуемые пользователем параметры (ограничение на количество устройств) были успешно изменены ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} (Примечание: Может потребоваться около десяти секунд, прежде чем будет применена последняя конфигурация)"
	fi
}
Modify_config_speed_limit_per_con(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -s "${ssr_speed_limit_per_con}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить однопоточное ограничение скорости пользователя ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Ограничение скорости однопоточной работы пользователя было успешно изменено ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} (Примечание: Может потребоваться около десяти секунд, прежде чем будет применена последняя конфигурация)"
	fi
}
Modify_config_speed_limit_per_user(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -S "${ssr_speed_limit_per_user}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить общее ограничение скорости пользовательского порта ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Общее ограничение скорости пользовательского порта было успешно изменено ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} (Примечание: Может потребоваться около десяти секунд, прежде чем будет применена последняя конфигурация)"
	fi
}
Modify_config_connect_verbose_info(){
	sed -i 's/"connect_verbose_info": '"$(echo ${connect_verbose_info})"',/"connect_verbose_info": '"$(echo ${ssr_connect_verbose_info})"',/g' ${config_user_file}
}
Modify_config_transfer(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -t "${ssr_transfer}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить общий пользовательский трафик ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Общий пользовательский трафик был успешно изменен ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} (Примечание: Может потребоваться около десяти секунд, прежде чем будет применена последняя конфигурация)"
	fi
}
Modify_config_forbid(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -f "${ssr_forbid}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Пользователю запрещен доступ к порту, и модификация не удалась ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Пользователь запрещает доступ к порту, и модификация проходит успешно ${Green_font_prefix}[порт: ${ssr_port}]${Font_color_suffix} (Примечание: Может потребоваться около десяти секунд, прежде чем будет применена последняя конфигурация)"
	fi
}
Modify_config_enable(){
	sed -i "${ssr_enable_num}"'s/"enable": '"$(echo ${enable})"',/"enable": '"$(echo ${ssr_enable})"',/' ${config_user_mudb_file}
}
Modify_user_api_server_pub_addr(){
	sed -i "s/SERVER_PUB_ADDR = '${server_pub_addr}'/SERVER_PUB_ADDR = '${ssr_server_pub_addr}'/" ${config_user_api_file}
}
Modify_config_all(){
	Modify_config_password
	Modify_config_method
	Modify_config_protocol
	Modify_config_obfs
	Modify_config_protocol_param
	Modify_config_speed_limit_per_con
	Modify_config_speed_limit_per_user
	Modify_config_transfer
	Modify_config_forbid
}
Check_python(){
	python_ver=`python -h`
	if [[ -z ${python_ver} ]]; then
		echo -e "${Info} Python не установлен, запустите установку..."
		if [[ ${release} == "centos" ]]; then
			yum install -y python
		else
			apt-get install -y python
		fi
	fi
}
Centos_yum(){
	yum update
	cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
	if [[ $? = 0 ]]; then
		yum install -y vim unzip crond net-tools
	else
		yum install -y vim unzip crond
	fi
}
Debian_apt(){
	apt-get update
	cat /etc/issue |grep 9\..*>/dev/null
	if [[ $? = 0 ]]; then
		apt-get install -y vim unzip cron net-tools
	else
		apt-get install -y vim unzip cron
	fi
}
# Загрузка ShadowsocksR
Download_SSR(){
	cd "/usr/local"
	wget -N --no-check-certificate "https://github.com/ToyoDAdoubiBackup/shadowsocksr/archive/manyuser.zip"
	#git config --global http.sslVerify false
	#env GIT_SSL_NO_VERIFY=true git clone -b manyuser https://github.com/ToyoDAdoubiBackup/shadowsocksr.git
	#[[ ! -e ${ssr_folder} ]] && echo -e "${Error} Сбой загрузки сервера ShadowsocksR !" && exit 1
	[[ ! -e "manyuser.zip" ]] && echo -e "${Error} Не удалось загрузить сжатый пакет сервера ShadowsocksR !" && rm -rf manyuser.zip && exit 1
	unzip "manyuser.zip"
	[[ ! -e "/usr/local/shadowsocksr-manyuser/" ]] && echo -e "${Error} Сбой распаковки сервера ShadowsocksR !" && rm -rf manyuser.zip && exit 1
	mv "/usr/local/shadowsocksr-manyuser/" "/usr/local/shadowsocksr/"
	[[ ! -e "/usr/local/shadowsocksr/" ]] && echo -e "${Error} Ошибка переименования сервера ShadowsocksR !" && rm -rf manyuser.zip && rm -rf "/usr/local/shadowsocksr-manyuser/" && exit 1
	rm -rf manyuser.zip
	cd "shadowsocksr"
	cp "${ssr_folder}/config.json" "${config_user_file}"
	cp "${ssr_folder}/mysql.json" "${ssr_folder}/usermysql.json"
	cp "${ssr_folder}/apiconfig.py" "${config_user_api_file}"
	[[ ! -e ${config_user_api_file} ]] && echo -e "${Error} Сервер ShadowsocksR apiconfig.py Ошибка копирования !" && exit 1
	sed -i "s/API_INTERFACE = 'sspanelv2'/API_INTERFACE = 'mudbjson'/" ${config_user_api_file}
	server_pub_addr="127.0.0.1"
	Modify_user_api_server_pub_addr
	#sed -i "s/SERVER_PUB_ADDR = '127.0.0.1'/SERVER_PUB_ADDR = '${ip}'/" ${config_user_api_file}
	sed -i 's/ \/\/ only works under multi-user mode//g' "${config_user_file}"
	echo -e "${Info} Загрузка сервера ShadowsocksR завершена !"
}
Service_SSR(){
	if [[ ${release} = "centos" ]]; then
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/service/ssrmu_centos -O /etc/init.d/ssrmu; then
			echo -e "${Error} Сбой загрузки скрипта управления службой ShadowsocksR !" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		chkconfig --add ssrmu
		chkconfig ssrmu on
	else
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/service/ssrmu_debian -O /etc/init.d/ssrmu; then
			echo -e "${Error} Сбой загрузки скрипта управления службой ShadowsocksR !" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		update-rc.d -f ssrmu defaults
	fi
	echo -e "${Info} Загрузка скрипта управления службой ShadowsocksR завершена !"
}
# Установите анализатор JQ
JQ_install(){
	if [[ ! -e ${jq_file} ]]; then
		cd "${ssr_folder}"
		if [[ ${bit} = "x86_64" ]]; then
			mv "jq-linux64" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64" -O ${jq_file}
		else
			mv "jq-linux32" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux32" -O ${jq_file}
		fi
		[[ ! -e ${jq_file} ]] && echo -e "${Error} Синтаксическому анализатору JQ не удалось переименовать, пожалуйста, проверьте !" && exit 1
		chmod +x ${jq_file}
		echo -e "${Info} Установка анализатора JQ завершена, продолжайте..." 
	else
		echo -e "${Info} Анализатор JQ установлен, продолжайте..."
	fi
}
# Зависимость от установки
Installation_dependency(){
	if [[ ${release} == "centos" ]]; then
		Centos_yum
	else
		Debian_apt
	fi
	[[ ! -e "/usr/bin/unzip" ]] && echo -e "${Error} полагаться unzip(Распакуйте сжатый пакет) Установка завершилась неудачно, в основном это проблема с исходным кодом пакета, пожалуйста, проверьте !" && exit 1
	Check_python
	#echo "nameserver 1.1.1.1" > /etc/resolv.conf
	#echo "nameserver 1.0.0.1" >> /etc/resolv.conf
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	if [[ ${release} == "centos" ]]; then
		/etc/init.d/crond restart
	else
		/etc/init.d/cron restart
	fi
}
Install_SSR(){
	check_root
	[[ -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR Папка уже существует, пожалуйста, проверьте(Если установка завершилась неудачей или имеется старая версия, пожалуйста, сначала удалите ее ) !" && exit 1
	echo -e "${Info} Начните настройку конфигурации учетной записи ShadowsocksR..."
	Set_user_api_server_pub_addr
	Set_config_all
	echo -e "${Info} Начните установку/настройку зависимостей ShadowsocksR..."
	Installation_dependency
	echo -e "${Info} Начните загрузку/установку файла ShadowsocksR..."
	Download_SSR
	echo -e "${Info} Начните загрузку/установку служебного скрипта ShadowsocksR(init)..."
	Service_SSR
	echo -e "${Info} Начните загрузку/установку JQ-анализатора..."
	JQ_install
	echo -e "${Info} Начните добавлять начальных пользователей..."
	Add_port_user "install"
	echo -e "${Info} Начните настройку брандмауэра iptables..."
	Set_iptables
	echo -e "${Info} Начните добавлять правила брандмауэра iptables..."
	Add_iptables
	echo -e "${Info} Начните сохранять правила брандмауэра iptables..."
	Save_iptables
	echo -e "${Info} После установки всех шагов запустите сервер ShadowsocksR..."
	Start_SSR
	Get_User_info "${ssr_port}"
	View_User_info
}
Update_SSR(){
	SSR_installation_status
	echo -e "В связи с приостановкой обновления сервера ShadowsocksR компанией Broken Baby эта функция временно отключена."
	#cd ${ssr_folder}
	#git pull
	#Restart_SSR
}
Uninstall_SSR(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR не установлен, пожалуйста, проверьте!" && exit 1
	echo "Вы точно хотите удалить ShadowsocksR？[y/N]" && echo
	read -e -p "(по умолчанию: n):" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid
		[[ ! -z "${PID}" ]] && kill -9 ${PID}
		user_info=$(python mujson_mgr.py -l)
		user_total=$(echo "${user_info}"|wc -l)
		if [[ ! -z ${user_info} ]]; then
			for((integer = 1; integer <= ${user_total}; integer++))
			do
				port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
				Del_iptables
			done
			Save_iptables
		fi
		if [[ ! -z $(crontab -l | grep "ssrmu.sh") ]]; then
			crontab_monitor_ssr_cron_stop
			Clear_transfer_all_cron_stop
		fi
		if [[ ${release} = "centos" ]]; then
			chkconfig --del ssrmu
		else
			update-rc.d -f ssrmu remove
		fi
		rm -rf ${ssr_folder} && rm -rf /etc/init.d/ssrmu
		echo && echo " Удаление ShadowsocksR завершено !" && echo
	else
		echo && echo " Удаление было отменено..." && echo
	fi
}
Check_Libsodium_ver(){
	echo -e "${Info} Начнинается получение новой версии libsodium..."
	Libsodiumr_ver=$(wget -qO- "https://github.com/jedisct1/libsodium/tags"|grep "/jedisct1/libsodium/releases/tag/"|head -1|sed -r 's/.*tag\/(.+)\">.*/\1/')
	[[ -z ${Libsodiumr_ver} ]] && Libsodiumr_ver=${Libsodiumr_ver_backup}
	echo -e "${Info} libsodium Последняя версия - это ${Green_font_prefix}${Libsodiumr_ver}${Font_color_suffix} !"
}
Install_Libsodium(){
	if [[ -e ${Libsodiumr_file} ]]; then
		echo -e "${Error} libsodium Установлен, следует ли перезаписывать установку(обновлять)？[y/N]"
		read -e -p "(по умолчанию: n):" yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Nn] ]]; then
			echo "отмененный..." && exit 1
		fi
	else
		echo -e "${Info} libsodium Не установлен, начните установку..."
	fi
	Check_Libsodium_ver
	if [[ ${release} == "centos" ]]; then
		yum update
		echo -e "${Info} Зависимость от установки..."
		yum -y groupinstall "Development Tools"
		echo -e "${Info} загрузка..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} загрузка..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} Скомпилировать и установить..."
		./configure --disable-maintainer-mode && make -j2 && make install
		echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
	else
		apt-get update
		echo -e "${Info} Зависимость от установки..."
		apt-get install -y build-essential
		echo -e "${Info} загрузка..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} 解压..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} Скомпилировать и установить..."
		./configure --disable-maintainer-mode && make -j2 && make install
	fi
	ldconfig
	cd .. && rm -rf libsodium-${Libsodiumr_ver}.tar.gz && rm -rf libsodium-${Libsodiumr_ver}
	[[ ! -e ${Libsodiumr_file} ]] && echo -e "${Error} libsodium Сбой установки !" && exit 1
	echo && echo -e "${Info} libsodium Успешная установка !" && echo
}
# Отображение информации о подключении
debian_View_user_connection_info(){
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Пользователь не найден, пожалуйста, проверьте !" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |grep ":${user_port} " |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"имя пользователя: ${Green_font_prefix}"${user_info_233}"${Font_color_suffix}\t порт: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t Общее количество связанных IP-адресов: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t Текущий IP-адрес канала связи: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
	done
	echo -e "Общее количество пользователей: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} Общее количество связанных IP-адресов: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
	echo -e "${user_list_all}"
}
centos_View_user_connection_info(){
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Пользователь не найден, пожалуйста, проверьте !" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' | grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' |grep ":${user_port} "|grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"имя пользователя: ${Green_font_prefix}"${user_info_233}"${Font_color_suffix}\t порт: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t Общее количество связанных IP-адресов: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t Общее количество связанных IP-адресов: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
	done
	echo -e "Общее количество пользователей: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} Общее количество связанных IP-адресов: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
	echo -e "${user_list_all}"
}
View_user_connection_info(){
	SSR_installation_status
	echo && echo -e "Пожалуйста, выберите формат, который вы хотите отобразить：
 ${Green_font_prefix}1.${Font_color_suffix} Формат отображения IP-адреса
 ${Green_font_prefix}2.${Font_color_suffix} Отображение формата присвоения IP+IP" && echo
	read -e -p "(по умолчанию: 1):" ssr_connection_info
	[[ -z "${ssr_connection_info}" ]] && ssr_connection_info="1"
	if [[ ${ssr_connection_info} == "1" ]]; then
		View_user_connection_info_1 ""
	elif [[ ${ssr_connection_info} == "2" ]]; then
		echo -e "${Tip} Определить домашний IP-адрес (ipip.net ), если есть больше IP-адресов, это может занять много времени..."
		View_user_connection_info_1 "IP_address"
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-2)" && exit 1
	fi
}
View_user_connection_info_1(){
	format=$1
	if [[ ${release} = "centos" ]]; then
		cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
		if [[ $? = 0 ]]; then
			debian_View_user_connection_info "$format"
		else
			centos_View_user_connection_info "$format"
		fi
	else
		debian_View_user_connection_info "$format"
	fi
}
get_IP_address(){
	#echo "user_IP_1=${user_IP_1}"
	if [[ ! -z ${user_IP_1} ]]; then
	#echo "user_IP_total=${user_IP_total}"
		for((integer_1 = ${user_IP_total}; integer_1 >= 1; integer_1--))
		do
			IP=`echo "${user_IP_1}" |sed -n "$integer_1"p`
			#echo "IP=${IP}"
			IP_address=`wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP}|sed 's/\"//g;s/,//g;s/\[//g;s/\]//g'`
			#echo "IP_address=${IP_address}"
			user_IP="${user_IP}\n${IP}(${IP_address})"
			#echo "user_IP=${user_IP}"
			sleep 1s
		done
	fi
}
# Изменение конфигурации пользователя
Modify_port(){
	List_port_user
	while true
	do
		echo -e "Пожалуйста, введите порт пользователя, который вы хотите изменить"
		read -e -p "(По умолчанию: отмена):" ssr_port
		[[ -z "${ssr_port}" ]] && echo -e "отмененный..." && exit 1
		Modify_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${ssr_port}"',')
		if [[ ! -z ${Modify_user} ]]; then
			break
		else
			echo -e "${Error} Пожалуйста, введите правильный порт !"
		fi
	done
}
Modify_Config(){
	SSR_installation_status
	echo && echo -e "Что ты собираешься делать?
 ${Green_font_prefix}1.${Font_color_suffix}  Добавление конфигурации пользователя
 ${Green_font_prefix}2.${Font_color_suffix}  Удалить конфигурацию пользователя
————— Изменение конфигурации пользователя —————
 ${Green_font_prefix}3.${Font_color_suffix}  Изменение пароля пользователя
 ${Green_font_prefix}4.${Font_color_suffix}  Измените метод шифрования
 ${Green_font_prefix}5.${Font_color_suffix}  Измените подключаемый модуль протокола
 ${Green_font_prefix}6.${Font_color_suffix}  Измените подключаемый модуль запутывания
 ${Green_font_prefix}7.${Font_color_suffix}  Измените ограничение на количество устройств
 ${Green_font_prefix}8.${Font_color_suffix}  Изменение ограничения скорости однопоточной передачи
 ${Green_font_prefix}9.${Font_color_suffix}  Измените общее ограничение скорости пользователя
 ${Green_font_prefix}10.${Font_color_suffix} Изменение общего пользовательского трафика
 ${Green_font_prefix}11.${Font_color_suffix} Измените пользователя, чтобы отключить порт
 ${Green_font_prefix}12.${Font_color_suffix} Измените все конфигурации
————— другие —————
 ${Green_font_prefix}13.${Font_color_suffix} Измените IP-адрес или доменное имя, отображаемое в конфигурации пользователя
 
 ${Tip} Имя пользователя и порт пользователя не могут быть изменены. если вам нужно их изменить, пожалуйста, воспользуйтесь функцией ручного изменения скрипта. !" && echo
	read -e -p "(По умолчанию: отмена):" ssr_modify
	[[ -z "${ssr_modify}" ]] && echo "отмененный..." && exit 1
	if [[ ${ssr_modify} == "1" ]]; then
		Add_port_user
	elif [[ ${ssr_modify} == "2" ]]; then
		Del_port_user
	elif [[ ${ssr_modify} == "3" ]]; then
		Modify_port
		Set_config_password
		Modify_config_password
	elif [[ ${ssr_modify} == "4" ]]; then
		Modify_port
		Set_config_method
		Modify_config_method
	elif [[ ${ssr_modify} == "5" ]]; then
		Modify_port
		Set_config_protocol
		Modify_config_protocol
	elif [[ ${ssr_modify} == "6" ]]; then
		Modify_port
		Set_config_obfs
		Modify_config_obfs
	elif [[ ${ssr_modify} == "7" ]]; then
		Modify_port
		Set_config_protocol_param
		Modify_config_protocol_param
	elif [[ ${ssr_modify} == "8" ]]; then
		Modify_port
		Set_config_speed_limit_per_con
		Modify_config_speed_limit_per_con
	elif [[ ${ssr_modify} == "9" ]]; then
		Modify_port
		Set_config_speed_limit_per_user
		Modify_config_speed_limit_per_user
	elif [[ ${ssr_modify} == "10" ]]; then
		Modify_port
		Set_config_transfer
		Modify_config_transfer
	elif [[ ${ssr_modify} == "11" ]]; then
		Modify_port
		Set_config_forbid
		Modify_config_forbid
	elif [[ ${ssr_modify} == "12" ]]; then
		Modify_port
		Set_config_all "Modify"
		Modify_config_all
	elif [[ ${ssr_modify} == "13" ]]; then
		Set_user_api_server_pub_addr "Modify"
		Modify_user_api_server_pub_addr
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-13)" && exit 1
	fi
}
List_port_user(){
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Пользователь не найден, пожалуйста, проверьте !" && exit 1
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_username=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		Get_User_transfer "${user_port}"
		transfer_enable_Used_233=$(echo $((${transfer_enable_Used_233}+${transfer_enable_Used_2_1})))
		user_list_all=${user_list_all}"имя пользователя: ${Green_font_prefix} "${user_username}"${Font_color_suffix}\t порт: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t Использование трафика (использованное + оставшееся = общее): ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix} + ${Green_font_prefix}${transfer_enable_Used}${Font_color_suffix} = ${Green_font_prefix}${transfer_enable}${Font_color_suffix}\n"
	done
	Get_User_transfer_all
	echo && echo -e "=== Общее количество пользователей ${Green_background_prefix} "${user_total}" ${Font_color_suffix}"
	echo -e ${user_list_all}
	echo -e "=== Сумма текущего трафика, используемого всеми пользователями: ${Green_background_prefix} ${transfer_enable_Used_233_2} ${Font_color_suffix}\n"
}
Add_port_user(){
	lalal=$1
	if [[ "$lalal" == "install" ]]; then
		match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
	else
		while true
		do
			Set_config_all
			match_port=$(python mujson_mgr.py -l|grep -w "port ${ssr_port}$")
			[[ ! -z "${match_port}" ]] && echo -e "${Error} Порт [${ssr_port}] Уже существует, пожалуйста, не добавляйте его повторно !" && exit 1
			match_username=$(python mujson_mgr.py -l|grep -w "user \[${ssr_user}]")
			[[ ! -z "${match_username}" ]] && echo -e "${Error} Имя пользователя [${ssr_user}] Уже существует, пожалуйста, не добавляйте его повторно !" && exit 1
			match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
			if [[ -z "${match_add}" ]]; then
				echo -e "${Error} Ошибка добавления пользователя ${Green_font_prefix}[имя пользователя: ${ssr_user} , порт: ${ssr_port}]${Font_color_suffix} "
				break
			else
				Add_iptables
				Save_iptables
				echo -e "${Info} Пользователь успешно добавлен ${Green_font_prefix}[имя пользователя: ${ssr_user} , порт: ${ssr_port}]${Font_color_suffix} "
				echo
				read -e -p "Продолжите ли вы добавлять пользовательские конфигурации?[Y/n]:" addyn
				[[ -z ${addyn} ]] && addyn="y"
				if [[ ${addyn} == [Nn] ]]; then
					Get_User_info "${ssr_port}"
					View_User_info
					break
				else
					echo -e "${Info} Продолжайте добавлять пользовательскую конфигурацию..."
				fi
			fi
		done
	fi
}
Del_port_user(){
	List_port_user
	while true
	do
		echo -e "Пожалуйста, введите порт пользователя, который вы хотите удалить"
		read -e -p "(По умолчанию: отмена):" del_user_port
		[[ -z "${del_user_port}" ]] && echo -e "отмена..." && exit 1
		del_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${del_user_port}"',')
		if [[ ! -z ${del_user} ]]; then
			port=${del_user_port}
			match_del=$(python mujson_mgr.py -d -p "${del_user_port}"|grep -w "delete user ")
			if [[ -z "${match_del}" ]]; then
				echo -e "${Error} Ошибка удаления пользователя ${Green_font_prefix}[порт: ${del_user_port}]${Font_color_suffix} "
			else
				Del_iptables
				Save_iptables
				echo -e "${Info} Пользователь успешно удален ${Green_font_prefix}[порт: ${del_user_port}]${Font_color_suffix} "
			fi
			break
		else
			echo -e "${Error} Пожалуйста, введите правильный порт !"
		fi
	done
}
Manually_Modify_Config(){
	SSR_installation_status
	vi ${config_user_mudb_file}
	echo "Вы перезапускаете ShadowsocksR сейчас?[Y/n]" && echo
	read -e -p "(по умолчанию: y):" yn
	[[ -z ${yn} ]] && yn="y"
	if [[ ${yn} == [Yy] ]]; then
		Restart_SSR
	fi
}
Clear_transfer(){
	SSR_installation_status
	echo && echo -e "Что ты собираешься делать?
 ${Green_font_prefix}1.${Font_color_suffix}  Очистить трафик, используемый одним пользователем
 ${Green_font_prefix}2.${Font_color_suffix}  Очистить весь использованный трафик пользователей (невосполнимый)
 ${Green_font_prefix}3.${Font_color_suffix}  Время запуска, весь пользовательский трафик сбрасывается до нуля
 ${Green_font_prefix}4.${Font_color_suffix}  Время остановки Весь пользовательский трафик сбрасывается до нуля
 ${Green_font_prefix}5.${Font_color_suffix}  Измените время, весь пользовательский трафик будет обнулен до нуля" && echo
	read -e -p "(по умолчанию: отменять):" ssr_modify
	[[ -z "${ssr_modify}" ]] && echo "отмененный..." && exit 1
	if [[ ${ssr_modify} == "1" ]]; then
		Clear_transfer_one
	elif [[ ${ssr_modify} == "2" ]]; then
		echo "Обязательно очистите трафик, используемый всеми пользователями？[y/N]" && echo
		read -e -p "(по умолчанию: n):" yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Yy] ]]; then
			Clear_transfer_all
		else
			echo "отменять..."
		fi
	elif [[ ${ssr_modify} == "3" ]]; then
		check_crontab
		Set_crontab
		Clear_transfer_all_cron_start
	elif [[ ${ssr_modify} == "4" ]]; then
		check_crontab
		Clear_transfer_all_cron_stop
	elif [[ ${ssr_modify} == "5" ]]; then
		check_crontab
		Clear_transfer_all_cron_modify
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-5)" && exit 1
	fi
}
Clear_transfer_one(){
	List_port_user
	while true
	do
		echo -e "Пожалуйста, введите пользовательский порт, на котором вы хотите очистить используемый трафик"
		read -e -p "(По умолчанию: отмена):" Clear_transfer_user_port
		[[ -z "${Clear_transfer_user_port}" ]] && echo -e "отмененный..." && exit 1
		Clear_transfer_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${Clear_transfer_user_port}"',')
		if [[ ! -z ${Clear_transfer_user} ]]; then
			match_clear=$(python mujson_mgr.py -c -p "${Clear_transfer_user_port}"|grep -w "clear user ")
			if [[ -z "${match_clear}" ]]; then
				echo -e "${Error} Пользователь использовал трафик для очистки и потерпел неудачу ${Green_font_prefix}[порт: ${Clear_transfer_user_port}]${Font_color_suffix} "
			else
				echo -e "${Info} Пользователь использовал трафик для успешной очистки ${Green_font_prefix}[порт: ${Clear_transfer_user_port}]${Font_color_suffix} "
			fi
			break
		else
			echo -e "${Error} Пожалуйста, введите правильный порт !"
		fi
	done
}
Clear_transfer_all(){
	cd "${ssr_folder}"
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Пользователь не найден, пожалуйста, проверьте !" && exit 1
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		match_clear=$(python mujson_mgr.py -c -p "${user_port}"|grep -w "clear user ")
		if [[ -z "${match_clear}" ]]; then
			echo -e "${Error} Пользователь использовал трафик для очистки и потерпел неудачу ${Green_font_prefix}[порт: ${user_port}]${Font_color_suffix} "
		else
			echo -e "${Info} Пользователь использовал трафик для успешной очистки ${Green_font_prefix}[порт: ${user_port}]${Font_color_suffix} "
		fi
	done
	echo -e "${Info} Весь пользовательский трафик очищается до нуля !"
}
Clear_transfer_all_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	echo -e "\n${Crontab_time} /bin/bash $file/ssrmu.sh clearall" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} По времени весь пользовательский трафик сбрасывается до нуля, и запуск завершается сбоем !" && exit 1
	else
		echo -e "${Info} По времени весь пользовательский трафик сбрасывается до нуля, и запуск проходит успешно !"
	fi
}
Clear_transfer_all_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} По времени весь пользовательский трафик был очищен до нуля и не удалось остановить !" && exit 1
	else
		echo -e "${Info} По времени весь пользовательский трафик сбрасывается до нуля и успешно останавливается !"
	fi
}
Clear_transfer_all_cron_modify(){
	Set_crontab
	Clear_transfer_all_cron_stop
	Clear_transfer_all_cron_start
}
Set_crontab(){
		echo -e "Пожалуйста, введите интервал времени очистки трафика
 === 格式说明 ===
 * * * * * Соответствуют минутам, часам, дням, месяцам, неделям
 ${Green_font_prefix} 0 2 1 * * ${Font_color_suffix} Означает, что использованный трафик очищается в 2:00 1-го числа каждого месяца
 ${Green_font_prefix} 0 2 15 * * ${Font_color_suffix} Означает, что использованный трафик очищается в 2:00 15 числа каждого месяца
 ${Green_font_prefix} 0 2 */7 * * ${Font_color_suffix} Означает, что использованный трафик очищается в 2:00 каждые 7 дней
 ${Green_font_prefix} 0 2 * * 0 ${Font_color_suffix} Означает, что используемый трафик очищается каждое воскресенье (7)
 ${Green_font_prefix} 0 2 * * 3 ${Font_color_suffix} Означает, что используемый трафик очищается каждую среду (3)" && echo
	read -e -p "(Значение по умолчанию: 0 2 1 * * 2 :00 1-го числа каждого месяца):" Crontab_time
	[[ -z "${Crontab_time}" ]] && Crontab_time="0 2 1 * *"
}
Start_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} ShadowsocksR Активен !" && exit 1
	/etc/init.d/ssrmu start
}
Stop_SSR(){
	SSR_installation_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} ShadowsocksR не активен !" && exit 1
	/etc/init.d/ssrmu stop
}
Restart_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && /etc/init.d/ssrmu stop
	/etc/init.d/ssrmu start
}
View_Log(){
	SSR_installation_status
	[[ ! -e ${ssr_log_file} ]] && echo -e "${Error} Файл журнала ShadowsocksR не существует !" && exit 1
	echo && echo -e "${Tip} по ${Red_font_prefix}Ctrl+C${Font_color_suffix} Завершить просмотр журнала" && echo -e "Если вам нужно просмотреть полное содержимое журнала, пожалуйста, используйте ${Red_font_prefix}cat ${ssr_log_file}${Font_color_suffix} команду." && echo
	tail -f ${ssr_log_file}
}
# Резкая скорость
Configure_Server_Speeder(){
	echo && echo -e "Что ты собираешься делать?
 ${Green_font_prefix}1.${Font_color_suffix} Установите резкую скорость
 ${Green_font_prefix}2.${Font_color_suffix} Удаление sharp speed
————————
 ${Green_font_prefix}3.${Font_color_suffix} Начните резкую скорость
 ${Green_font_prefix}4.${Font_color_suffix} Остановите резкую скорость
 ${Green_font_prefix}5.${Font_color_suffix} Перезапуск резкой скорости
 ${Green_font_prefix}6.${Font_color_suffix} Проверьте состояние резкой скорости
 
 Примечание: Ruisu и LotServer не могут быть установлены /запущены одновременно!" && echo
	read -e -p "(По умолчанию: отмена):" server_speeder_num
	[[ -z "${server_speeder_num}" ]] && echo "отмененный..." && exit 1
	if [[ ${server_speeder_num} == "1" ]]; then
		Install_ServerSpeeder
	elif [[ ${server_speeder_num} == "2" ]]; then
		Server_Speeder_installation_status
		Uninstall_ServerSpeeder
	elif [[ ${server_speeder_num} == "3" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} start
		${Server_Speeder_file} status
	elif [[ ${server_speeder_num} == "4" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} stop
	elif [[ ${server_speeder_num} == "5" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} restart
		${Server_Speeder_file} status
	elif [[ ${server_speeder_num} == "6" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} status
	else
		echo -e "${Error}Пожалуйста, введите правильный номер(1-6)" && exit 1
	fi
}
Install_ServerSpeeder(){
	[[ -e ${Server_Speeder_file} ]] && echo -e "${Error} Ускоритель сервера установлен!" && exit 1
	#Одолжи 91юнь.счастливая версия Sharp speed от rog
	wget --no-check-certificate -qO /tmp/serverspeeder.sh https://raw.githubusercontent.com/91yun/serverspeeder/master/serverspeeder.sh
	[[ ! -e "/tmp/serverspeeder.sh" ]] && echo -e "${Error} Не удалось загрузить установочный скрипт Ruisu !" && exit 1
	bash /tmp/serverspeeder.sh
	sleep 2s
	PID=`ps -ef |grep -v grep |grep "serverspeeder" |awk '{print $2}'`
	if [[ ! -z ${PID} ]]; then
		rm -rf /tmp/serverspeeder.sh
		rm -rf /tmp/91yunserverspeeder
		rm -rf /tmp/91yunserverspeeder.tar.gz
		echo -e "${Info} Установка ускорителя сервера завершена!" && exit 1
	else
		echo -e "${Error} Ошибка установки ускорителя сервера!" && exit 1
	fi
}
Uninstall_ServerSpeeder(){
	echo "Обязательно удалите Sharp speed(Server Speeder)？[y/N]" && echo
	read -e -p "(по умолчанию: n):" unyn
	[[ -z ${unyn} ]] && echo && echo "отмененный..." && exit 1
	if [[ ${unyn} == [Yy] ]]; then
		chattr -i /serverspeeder/etc/apx*
		/serverspeeder/bin/serverSpeeder.sh uninstall -f
		echo && echo "Деинсталляция ускорителя сервера завершена!" && echo
	fi
}
# LotServer
Configure_LotServer(){
	echo && echo -e "Что ты собираешься делать?
 ${Green_font_prefix}1.${Font_color_suffix} устанавливать LotServer
 ${Green_font_prefix}2.${Font_color_suffix} разгрузка LotServer
————————
 ${Green_font_prefix}3.${Font_color_suffix} включать LotServer
 ${Green_font_prefix}4.${Font_color_suffix} остановка LotServer
 ${Green_font_prefix}5.${Font_color_suffix} возобновлять LotServer
 ${Green_font_prefix}6.${Font_color_suffix} проверить LotServer состояние
 
 Примечание: Ruisu и LotServer не могут быть установлены /запущены одновременно!" && echo
	read -e -p "(По умолчанию: отмена):" lotserver_num
	[[ -z "${lotserver_num}" ]] && echo "отмененный..." && exit 1
	if [[ ${lotserver_num} == "1" ]]; then
		Install_LotServer
	elif [[ ${lotserver_num} == "2" ]]; then
		LotServer_installation_status
		Uninstall_LotServer
	elif [[ ${lotserver_num} == "3" ]]; then
		LotServer_installation_status
		${LotServer_file} start
		${LotServer_file} status
	elif [[ ${lotserver_num} == "4" ]]; then
		LotServer_installation_status
		${LotServer_file} stop
	elif [[ ${lotserver_num} == "5" ]]; then
		LotServer_installation_status
		${LotServer_file} restart
		${LotServer_file} status
	elif [[ ${lotserver_num} == "6" ]]; then
		LotServer_installation_status
		${LotServer_file} status
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-6)" && exit 1
	fi
}
Install_LotServer(){
	[[ -e ${LotServer_file} ]] && echo -e "${Error} LotServer установленный !" && exit 1
	#Github: https://github.com/0oVicero0/serverSpeeder_Install
	wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh"
	[[ ! -e "/tmp/appex.sh" ]] && echo -e "${Error} LotServer Не удалось загрузить установочный скрипт !" && exit 1
	bash /tmp/appex.sh 'install'
	sleep 2s
	PID=`ps -ef |grep -v grep |grep "appex" |awk '{print $2}'`
	if [[ ! -z ${PID} ]]; then
		echo -e "${Info} LotServer Установка завершена !" && exit 1
	else
		echo -e "${Error} LotServer Сбой установки !" && exit 1
	fi
}
Uninstall_LotServer(){
	echo "Обязательно удалите LotServer？[y/N]" && echo
	read -e -p "(по умолчанию: n):" unyn
	[[ -z ${unyn} ]] && echo && echo "отмененный..." && exit 1
	if [[ ${unyn} == [Yy] ]]; then
		wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh" && bash /tmp/appex.sh 'uninstall'
		echo && echo "LotServer Удаление завершено !" && echo
	fi
}
# BBR
Configure_BBR(){
	echo && echo -e "  Что ты собираешься делать?
	
 ${Green_font_prefix}1.${Font_color_suffix} устанавливать BBR
————————
 ${Green_font_prefix}2.${Font_color_suffix} включать BBR
 ${Green_font_prefix}3.${Font_color_suffix} остановка BBR
 ${Green_font_prefix}4.${Font_color_suffix} проверить BBR состояние" && echo
echo -e "${Green_font_prefix} [Пожалуйста, обратите внимание перед установкой] ${Font_color_suffix}
1. Чтобы установить и включить BBR, необходимо заменить ядро, и существует риск невозможности его замены (его нельзя включить после перезагрузки).)
2. Этот скрипт поддерживает замену ядра только для систем Debian/Ubuntu. OpenVZ и Docker не поддерживают замену ядра.
3. Debian Будет предложено во время замены ядра [ Следует ли завершать деинсталляцию ядра ] ，Пожалуйста выберите ${Green_font_prefix} NO ${Font_color_suffix}" && echo
	read -e -p "(По умолчанию: отмена):" bbr_num
	[[ -z "${bbr_num}" ]] && echo "отмененный..." && exit 1
	if [[ ${bbr_num} == "1" ]]; then
		Install_BBR
	elif [[ ${bbr_num} == "2" ]]; then
		Start_BBR
	elif [[ ${bbr_num} == "3" ]]; then
		Stop_BBR
	elif [[ ${bbr_num} == "4" ]]; then
		Status_BBR
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-4)" && exit 1
	fi
}
Install_BBR(){
	[[ ${release} = "centos" ]] && echo -e "${Error} Этот скрипт не поддерживает установку BBR в системе CentOS!" && exit 1
	BBR_installation_status
	bash "${BBR_file}"
}
Start_BBR(){
	BBR_installation_status
	bash "${BBR_file}" start
}
Stop_BBR(){
	BBR_installation_status
	bash "${BBR_file}" stop
}
Status_BBR(){
	BBR_installation_status
	bash "${BBR_file}" status
}
# Другие функции
Other_functions(){
	echo && echo -e "  Что ты собираешься делать?
	
  ${Green_font_prefix}1.${Font_color_suffix} выделять BBR
  ${Green_font_prefix}2.${Font_color_suffix} выделять 锐速(ServerSpeeder)
  ${Green_font_prefix}3.${Font_color_suffix} выделять LotServer(Материнская компания Ruisu)
  ${Tip} Ruisu/LotServer/BBR не поддерживает OpenVZ！
  ${Tip} Sharp speed и LotServer не могут сосуществовать!
————————————
  ${Green_font_prefix}4.${Font_color_suffix} 一Ключевой запрет BT/PT/SPAM (iptables)
  ${Green_font_prefix}5.${Font_color_suffix} 一Разблокировка ключа BT/PT/SPAM (iptables)
————————————
  ${Green_font_prefix}6.${Font_color_suffix} Переключить режим вывода журнала ShadowsocksR
  —— Описание: По умолчанию SSR выводит только журналы ошибок. Этот пункт можно переключить на вывод подробных журналов доступа.
  ${Green_font_prefix}7.${Font_color_suffix} Мониторинг рабочего состояния сервера ShadowsocksR
  —— Описание: Эта функция подходит для сервера SSR. Процесс часто завершается. После запуска этой функции он будет обнаруживаться каждую минуту. Когда процесс не существует, сервер SSR будет запущен автоматически." && echo
	read -e -p "(По умолчанию: отмена):" other_num
	[[ -z "${other_num}" ]] && echo "отмененный..." && exit 1
	if [[ ${other_num} == "1" ]]; then
		Configure_BBR
	elif [[ ${other_num} == "2" ]]; then
		Configure_Server_Speeder
	elif [[ ${other_num} == "3" ]]; then
		Configure_LotServer
	elif [[ ${other_num} == "4" ]]; then
		BanBTPTSPAM
	elif [[ ${other_num} == "5" ]]; then
		UnBanBTPTSPAM
	elif [[ ${other_num} == "6" ]]; then
		Set_config_connect_verbose_info
	elif [[ ${other_num} == "7" ]]; then
		Set_crontab_monitor_ssr
	else
		echo -e "${Error} Пожалуйста, введите правильный номер [1-7]" && exit 1
	fi
}
#Запрет BT PT SPAM
BanBTPTSPAM(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh banall
	rm -rf ban_iptables.sh
}
# Разблокировка BT PT SPAM
UnBanBTPTSPAM(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh unbanall
	rm -rf ban_iptables.sh
}
Set_config_connect_verbose_info(){
	SSR_installation_status
	[[ ! -e ${jq_file} ]] && echo -e "${Error} Анализатор JQ не существует, пожалуйста, проверьте !" && exit 1
	connect_verbose_info=`${jq_file} '.connect_verbose_info' ${config_user_file}`
	if [[ ${connect_verbose_info} = "0" ]]; then
		echo && echo -e "Текущий режим ведения журнала: ${Green_font_prefix}Простой режим (только вывод журнала ошибок)${Font_color_suffix}" && echo
		echo -e "Убедитесь, что вы хотите переключиться на ${Green_font_prefix}Подробный режим (вывод подробного журнала подключений + журнал ошибок)${Font_color_suffix}？[y/N]"
		read -e -p "(по умолчанию: n):" connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="1"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			echo && echo "	отмененный..." && echo
		fi
	else
		echo && echo -e "Текущий режим ведения журнала: ${Green_font_prefix}Подробный режим (вывод подробного журнала подключений + журнал ошибок)${Font_color_suffix}" && echo
		echo -e "Убедитесь, что вы хотите переключиться на ${Green_font_prefix}Простой режим (только вывод журнала ошибок)${Font_color_suffix}？[y/N]"
		read -e -p "(по умолчанию: n):" connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="0"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			echo && echo "	отмененный..." && echo
		fi
	fi
}
Set_crontab_monitor_ssr(){
	SSR_installation_status
	crontab_monitor_ssr_status=$(crontab -l|grep "ssrmu.sh monitor")
	if [[ -z "${crontab_monitor_ssr_status}" ]]; then
		echo && echo -e "Текущий режим мониторинга: ${Green_font_prefix}Не включен${Font_color_suffix}" && echo
		echo -e "Убедитесь, что вы хотите открыть его как ${Green_font_prefix}Мониторинг состояния работы сервера ShadowsocksR${Font_color_suffix} Функция?(Когда процесс закрывается, автоматически запускается сервер SSR)[Y/n]"
		read -e -p "(По умолчанию: y):" crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="y"
		if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
			crontab_monitor_ssr_cron_start
		else
			echo && echo "	отмененный..." && echo
		fi
	else
		echo && echo -e "Текущий режим мониторинга: ${Green_font_prefix}Включенный${Font_color_suffix}" && echo
		echo -e "Убедитесь в том, чтобы закрыть как ${Green_font_prefix}Мониторинг состояния работы сервера ShadowsocksR${Font_color_suffix} Функция?？(Когда процесс закрывается, автоматически запускается сервер SSR)[y/N]"
		read -e -p "(по умолчанию: n):" crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="n"
		if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
			crontab_monitor_ssr_cron_stop
		else
			echo && echo "	отмененный..." && echo
		fi
	fi
}
crontab_monitor_ssr(){
	SSR_installation_status
	check_pid
	if [[ -z ${PID} ]]; then
		echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Он обнаруживает, что сервер ShadowsocksR не запущен, и начинает запуск..." | tee -a ${ssr_log_file}
		/etc/init.d/ssrmu start
		sleep 1s
		check_pid
		if [[ -z ${PID} ]]; then
			echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Не удалось запустить сервер ShadowsocksR..." | tee -a ${ssr_log_file} && exit 1
		else
			echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Сервер ShadowsocksR успешно запущен..." | tee -a ${ssr_log_file} && exit 1
		fi
	else
		echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Процесс сервера ShadowsocksR выполняется в обычном режиме..." exit 0
	fi
}
crontab_monitor_ssr_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	echo -e "\n* * * * * /bin/bash $file/ssrmu.sh monitor" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} Не удалось запустить функцию мониторинга состояния работы сервера ShadowsocksR !" && exit 1
	else
		echo -e "${Info} Функция мониторинга состояния работы сервера ShadowsocksR успешно запущена !"
	fi
}
crontab_monitor_ssr_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Функция мониторинга состояния работы сервера ShadowsocksR остановлена и вышла из строя !" && exit 1
	else
		echo -e "${Info} Функция мониторинга состояния работы сервера ShadowsocksR успешно остановлена !"
	fi
}
Update_Shell(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/ssrmu.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1) && sh_new_type="github"
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} Невозможно подключиться к Github !" && exit 0
	if [[ -e "/etc/init.d/ssrmu" ]]; then
		rm -rf /etc/init.d/ssrmu
		Service_SSR
	fi
	cd "${file}"
	wget -N --no-check-certificate "https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/ssrmu.sh" && chmod +x ssrmu.sh
	echo -e "Скрипт был обновлен до последней версии[ ${sh_new_ver} ] !(Примечание: Поскольку метод обновления заключается в прямой перезаписи текущего запущенного скрипта, ниже могут быть запрошены некоторые ошибки, просто игнорируйте их.)" && exit 0
}
# Отображение состояния меню
menu_status(){
	if [[ -e ${ssr_folder} ]]; then
		check_pid
		if [[ ! -z "${PID}" ]]; then
			echo -e " Текущее состояние: ${Green_font_prefix}установленный${Font_color_suffix} а ${Green_font_prefix}Активированный${Font_color_suffix}"
		else
			echo -e " Текущее состояние: ${Green_font_prefix}установленный${Font_color_suffix} только ${Red_font_prefix}Не начато${Font_color_suffix}"
		fi
		cd "${ssr_folder}"
	else
		echo -e " Текущее состояние: ${Red_font_prefix}Не установлен${Font_color_suffix}"
	fi
}
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} Этот сценарий не поддерживает текущую систему ${release} !" && exit 1
action=$1
if [[ "${action}" == "clearall" ]]; then
	Clear_transfer_all
elif [[ "${action}" == "monitor" ]]; then
	crontab_monitor_ssr
else
	echo -e "  ShadowsocksR MuJSON一Сценарий управления ключами ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  ---- Toyo | doub.io/ss-jc60 ----

  ${Green_font_prefix}1.${Font_color_suffix} Установка ShadowsocksR
  ${Green_font_prefix}2.${Font_color_suffix} Обновление ShadowsocksR
  ${Green_font_prefix}3.${Font_color_suffix} Удаление ShadowsocksR
  ${Green_font_prefix}4.${Font_color_suffix} Установка libsodium(chacha20)
————————————
  ${Green_font_prefix}5.${Font_color_suffix} Просмотр информации об учетной записи
  ${Green_font_prefix}6.${Font_color_suffix} Отображение информации о подключении
  ${Green_font_prefix}7.${Font_color_suffix} Настройка конфигурации пользователя
  ${Green_font_prefix}8.${Font_color_suffix} Вручную измените конфигурацию
  ${Green_font_prefix}9.${Font_color_suffix} Настройте трафик для очистки
————————————
 ${Green_font_prefix}10.${Font_color_suffix} Включить ShadowsocksR
 ${Green_font_prefix}11.${Font_color_suffix} Остановить ShadowsocksR
 ${Green_font_prefix}12.${Font_color_suffix} Запустить ShadowsocksR
 ${Green_font_prefix}13.${Font_color_suffix} Проверить ShadowsocksR журнал
————————————
 ${Green_font_prefix}14.${Font_color_suffix} Другие функции
 ${Green_font_prefix}15.${Font_color_suffix} Сценарий обновления
 "
	menu_status
	echo && read -e -p "Пожалуйста, введите номер [1-15]：" num
case "$num" in
	1)
	Install_SSR
	;;
	2)
	Update_SSR
	;;
	3)
	Uninstall_SSR
	;;
	4)
	Install_Libsodium
	;;
	5)
	View_User
	;;
	6)
	View_user_connection_info
	;;
	7)
	Modify_Config
	;;
	8)
	Manually_Modify_Config
	;;
	9)
	Clear_transfer
	;;
	10)
	Start_SSR
	;;
	11)
	Stop_SSR
	;;
	12)
	Restart_SSR
	;;
	13)
	View_Log
	;;
	14)
	Other_functions
	;;
	15)
	Update_Shell
	;;
	*)
	echo -e "${Error} Пожалуйста, введите правильный номер [1-15]"
	;;
esac
fi