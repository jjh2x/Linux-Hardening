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

export HARDENING_HOME="/root/hardening"
export RESULT_FILE_NAME="${HARDENING_HOME}/exec_log/result_${SERVER_IP}.txt"
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


UnitTest() {
	GDM_AutomaticLogin_Disabling
}

UnitTest
