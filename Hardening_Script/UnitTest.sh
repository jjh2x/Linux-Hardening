#! /bin/sh
export BLACK='\033[1;30m'
export RED='\033[1;31m'
export GREEN='\033[1;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[1;35m'
export NC='\033[0m'

export STATUS_NUM=1

export SUCCESS_NUM=0
export FAIL_NUM=0
export HOLD_NUM=0


export DATE_NOW="$(date +%Y%m%d)_$(date +%H%M%S)"

# $OS_VERSION=5 or 7
export OS_VERSION=$(cat /etc/redhat-release | grep -o '[0-9]' | awk 'NR==1 {print $1}')
#echo -e "OS_VERSION : $OS_VERSION"

# Taking IP address value
case $OS_VERSION in
	5)
	  export SERVER_IP=$(ip addr | grep '10.1' | awk '{print $2}' | cut -d '/' -f 1)
	;;

	7)
	  export SERVER_IP=$(hostname -I | awk '{print $1}')
	;;
esac

export HOSTNAME=$(hostname)

export HARDENING_HOME="/opt/Hardening_Script"
export RESULT_FILE_NAME="${HARDENING_HOME}/result_${SERVER_IP}.txt"
touch ${RESULT_FILE_NAME}
cat /dev/null > ${RESULT_FILE_NAME}


success_func() {
	SUCCESS_NUM=$((SUCCESS_NUM + 1))
	echo -e "Completed!" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
}

fail_func() {
	FAIL_NUM=$((FAIL_NUM + 1))
	echo -e "Failed!!" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
}

showHardening_num() {
	# $1 : Title_str
	echo -e "${RED}Hardening # $STATUS_NUM${NC} $1"
	echo -e "Hardening..."

	echo -e $"\n""[# $STATUS_NUM] $1"$"\n" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
}

showResult_num() {
	echo -e $"\n""${BLACK}[Current Result]${NC}"
	echo -e "${GREEN}Success_num :${NC} $SUCCESS_NUM"
	#echo -e "${YELLOW}Hold_num :${NC} $hold_num"
	echo -e "${RED}Fail_num :${NC} $FAIL_NUM"
	echo -e "___________________________________________________________________________"
}


Verification_Vendor_Supported_Release() {
	# V-204458
	### RHEL OS must be a vendor supported release ###

	Title_str="RHEL OS must be a vendor supported release"
	showHardening_num "${Title_str}"
	
	os_name=$(cat /etc/os-release | grep -E "^NAME" | cut -d "=" -f2 | cut -d "\"" -f2 | cut -d " " -f1)
	echo -e "os_name: ${os_name}"
	os_ver_id=$(cat /etc/os-release | grep -E "^VERSION_ID" | cut -d "=" -f2)
	os_ver_id="${os_ver_id:1:-1}"

	os_ver_major="${os_ver_id:0:1}"
	os_ver_major=$((os_ver_major))

	os_ver_minor="${os_ver_id:2}"
	os_ver_minor=$((os_ver_minor))
	#echo -e "os_ver_id: ${os_ver_id}"
	echo -e "os_ver_major: ${os_ver_major}"
	echo -e "os_ver_minor: ${os_ver_minor}"
	
	case $os_name in
	    CentOS)
		if [ "${os_ver_major}" <= 6 ] || [ "${os_ver_major}" == 8 ]; then
		    echo -e "${RED}This OS Relase needs to be confirmed!${NC}"
		    fail_func
		else
		    echo -e "${GREEN}Hardening: ${NC} This system is a vendor supported release"
		    success_func
		fi
	    ;;
	    
	    Red)
		if [[ "$os_ver_major" -le 6 ]]; then
		    echo -e "${RED}This OS Relase needs to be confirmed!${NC}"
		    fail_func
		elif [[ "$os_ver_major" -eq 7 ]]; then
		    if [[ "$os_ver_minor" -le 7 ]]; then
			echo -e "${RED}This OS Relase needs to be confirmed!${NC}"
		        fail_func
		    else
			echo -e "${GREEN}Hardening: ${NC} This system is a vendor supported release"
		        success_func
		    fi

		else
		    echo -e "${GREEN}Hardening: ${NC} This system is a vendor supported release"
		    success_func
		fi

	    ;;

	    Oracle)
		echo -e "${GREEN}Hardening: ${NC} This system is a vendor supported release"
		success_func
	    ;;
	    
	    * )
		echo -e "${RED}This OS Relase needs to be confirmed!${NC}"
		fail_func
	    ;;
	esac

	
	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

GDM_AutomaticLogin_Disabling() {
	# V-204432
	### 'gnome_gdm_disable_automatic_login' ###

	Title_str="Setting 'GNOME_GDM' automatic login is disabled"
	showHardening_num "${Title_str}"
	
	yum list installed gdm
	gdm_install_checks=$?
	
	grep -i automaticloginenable /etc/gdm/custom.conf 2>&1
	disableAutoLogin_checks=$?

	if [[ gdm_install_checks -eq 1 ]]; then
	    echo "This system doesn't have 'gdm' Package"
	    success_func

	else
	    #echo -e "disableAutoLogin_checks: ${disableAutoLogin_checks}"
	    if [[ "${disalbeAutoLogin_checks}" -eq 0 ]]; then	# There is string of "AutomaticLoginEnable"
		sed -i "s/^AutomaticLoginEnable=.*/AutomaticLoginEnable=False/g" /etc/gdm/custom.conf
	    else
		sed -i "/^\[daemon\]/a \
		AutomaticLoginEnable=False" /etc/gdm/custom.conf
	    fi	
	
	    # Validation
	    str_forComparing_24="AutomaticLoginEnable=False"
	    echo
	    echo -e "Verifying 'AutomaticLoginEnable' option ${RED}(must return 'AutomaticLoginEnable=False')${NC}:"
	    grep -i automaticloginenable /etc/gdm/custom.conf
	    disableAutoLogin_checks=$?

	    if [[ "${disableAutoLogin_checks}" -eq "${str_forComparing_24}" ]]; then
		echo -e "${GREEN}Hardening:${NC} GNOME_GDM disable automatic login"
		success_func
	    else
		echo -e "${RED}UnableToRemediate:${NC} GNOME_GDM disable automatic login is failed!"
		fail_func
	    fi

	fi

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

FileInfo_Matching_VendorValue() {
	# V-204392
	### Ensure file permissions, ownership, and group membership of system files and commands match the vendor values ###

	Title_str="File Permissions, Ownership, Group membership of 'system files' and 'commands' matching the vendor values"
	showHardening_num "${Title_str}"
	
	
	for i in `rpm -Va | grep -E '^.{1}M|^.{5}U|^.{6}G' | cut -d " " -f 4,5`
	do
	    echo "Iteration[i] : $i"
 
	    for j in `rpm -qf $i`
	    do 
		rpm -ql $j --dump | cut -d " " -f 1,5,6,7 | grep $i

	  	echo "Iteration[j] : $j"		
	    done
	done

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

Vsftpd_Disable() {
	# V-204620
	### 'Ensure FTP Server is not enabled' ###

	Title_str="'vsftpd' Package Remove"
	showHardening_num "${Title_str}"

	# FTP를 사용하든 사용하지 않든 anonymous 계정과 관련된 hardening은 무조건 수행
	VSFTPD_Anonymous_Disable
	
	# 현재 상태가 active이든 아니든 reboot시 vsftpd가 start 되지 않도록 해야 함
	systemctl disable vsftpd

	FTP_Checks="$(systemctl status vsftpd | grep Active | awk '{print $2}')"

	# echo -e "현재 FTP_Checks : ${FTP_Checks}"

	if [[ "$FTP_Checks" == "inactive" ]]; then
		echo -e "${GREEN}Hardening:${NC} This system's vsftpd service is disabled."
		success_func
	elif [[ "$FTP_Checks" == "active" ]]; then

		echo -e "${YELLOW}Disabling 'vsftpd' service...${NC}"

		# vsftpd 서비스 기동 중지
		systemctl stop vsftpd
		FTP_Disabling_Check=$?

		# vsftpd 서비스 기동 중지 성공
		if [[ "$FTP_Disabling_Check" -eq 0 ]]; then
			echo -e "${GREEN}Hardening:${NC} Ensure FTP Server is disabled successfully!"
			success_func
		
		# vsftpd 서비스 기동 중지 실패
		else
			echo -e "${RED}UnabledToRemediate:${NC} FTP Server disabling is Failed"
			fail_func
		fi
	
		#HOLD_NUM=$((HOLD_NUM + 1))
		#echo -e "${YELLOW}Hold :${NC} Machine doesn't remove 'vsftpd' Package"
		#echo -e "'vsftpd' Packages O" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
		
	fi

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

Vsftpd_Disable_VALI() {
	# V-204620
	### 'Ensure FTP Server is not enabled' ###

	Title_str="'vsftpd' Package Remove"
	showHardening_num "${Title_str}"
	
	# 현재 상태가 active이든 아니든 reboot시 vsftpd가 start 되지 않도록 해야 함
	systemctl disable vsftpd

	FTP_Checks="$(systemctl status vsftpd | grep Active | awk '{print $2}')"

	# echo -e "현재 FTP_Checks : ${FTP_Checks}"

	if [[ "$FTP_Checks" == "inactive" ]]; then
		echo -e "${GREEN}Hardening:${NC} This system's vsftpd service is disabled."
		success_func

		echo -e "'vsftpd' Service disabled" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
		
	elif [[ "$FTP_Checks" == "active" ]]; then
		echo -e "${RED}Not Remediated!!${NC} vsftpd disabling is Failed"
		fail_func "${Title_str}"

		echo -e "'vsftpd' Service enabled" | tee -a ${RESULT_FILE_NAME} > '/dev/null'	
	fi

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

VSFTPD_Anonymous_Disable() {
	# Disabling Anonymous FTP
	Title_str="(Added) Disabling Anonymous FTP"

	# 'ftp' 계정이 /bin/false인지 확인
	FTP_Shell="$(grep 'ftp' /etc/passwd | awk -F ':' '{print $7}')"

	# 'ftp' 계정이 쉘 접속 불가하도록 잘 설정되어 있는 경우
	if [[ $FTP_Shell == "/bin/false/" ]]; then
		echo -e "'ftp' Account ${GREEN}can't access${NC} the shell"
	
	# 'ftp' 계정 자체가 존재하지 않는 경우
	elif [[ -z "$FTP_Shell" ]]; then
		echo -e "'ftp' Account does ${GREEN}not exist.${NC}"
	
	# 'ftp' 계정이 /bin/false 쉘로 지정되어 있지 않은 경우
	else
		echo -e "'ftp' account is now ${RED}can access${NC} the shell. This will ${GREEN}be Disabled!${NC}"
		usermod -s /bin/false/ ftp
	fi

	# vsftpd.conf 에서 'anonymous' 계정 disable
	sed -ri "s/^(\s*)anonymous_enable\s*=\s*\S+(\s*#.*)?\s*/\1anonymous_enable=NO\2/" /etc/vsftpd/vsftpd.conf
	
	anonyFTP_dis_result="$(egrep "^(\s*)anonymous_enable=NO(\s*)" /etc/vsftpd/vsftpd.conf)"
	anonyFTP_dis_result=$?
	
	if [[ "$anonyFTP_dis_result" -eq 0 ]]; then
		echo -e "Hardening related to FTP's ${BLACK}anonymous account${NC} has been ${GREEN}applied.${NC}"
	else
		echo -e "Hardening related to FTP's ${BLACK}anonymous account${NC} has ${RED}not been applied.${NC}"
	fi

	# vsftpd.conf 적용 위해 vsftpd 서비스 restart (ftp 서비스를 사용하는 경우 conf 파일 적용 위함)
	systemctl restart vsftpd
}

Filtering_Weak_Conf(){
	# $1 : 첫번째 argument. 현재 시스템에 설정되어 있는 config
	IFS=',' read -ra result_array <<< $1

	# $@ : 두번째 argument(배열). 제외되어야 할 config
	TOBE_EXCEPTED_CONFIG=("$@")

	filtered_config_str=""
    for field in "${result_array[@]}"; do
        continue_str="False"

		
        for i in "${!TOBE_EXCEPTED_CONFIG[@]}"; do
            if [[ "${TOBE_EXCEPTED_CONFIG[i]}" == $field ]]; then
                continue_str="True"
                unset TOBE_EXCEPTED_CONFIG[i]
                break
            fi
        done

        if [[ "$continue_str" == "True" ]]; then
            continue
        else
            filtered_config_str="$filtered_config_str,$field"
        fi
    done

	filtered_config_str="$(echo $filtered_config_str | cut -c 2-)"

	echo ${filtered_config_str}
}

SSH_Weak_Conf_Remdiation() {
	# 현재 시스템에 설정되어 있는 KEX Algorithms
    current_KEX=$(sshd -T | grep -oP '(?<=^kexalgorithms\s)\S+')

	# 제외되어야 할 KEX Algorithms
	TOBE_DISABLED_KEX=("diffie-hellman-group16-sha512" "diffie-hellman-group18-sha512" "diffie-hellman-group-exchange-sha1" "diffie-hellman-group14-sha256" "diffie-hellman-group14-sha1" "diffie-hellman-group1-sha1" "ecdh-sha2-nistp256" "ecdh-sha2-nistp384" "ecdh-sha2-nistp521")

	KEX_append_str="KexAlgorithms $(Filtering_Weak_Conf "$current_KEX" ${TOBE_DISABLED_KEX[@]})"

	# /etc/ssh/sshd_config에 KexAlgorithms 설정이 들어가 있는지 판단
	grep_result="$(grep -e "^KexAlgorithms" /etc/ssh/sshd_config)"

	# KexAlgorithms 설정이 없다면
	if [[ -z $grep_result ]]; then
		echo "$KEX_append_str" >> /etc/ssh/sshd_config
	# KexAlogirhtms 설정이 있다면
	else
		sed -i "s/^KexAlgorithms.*/$KEX_append_str/g" /etc/ssh/sshd_config
	fi

	systemctl restart sshd

}

UnitTest() {
	SSH_Weak_Conf_Remdiation
}

UnitTest
