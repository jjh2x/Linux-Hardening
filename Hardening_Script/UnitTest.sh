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

export HARDENING_HOME="/opt/hardening"
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

# 하드닝 수행 유닛테스트 시 사용
showHardening_num() {
	# $1 : Title_str
	echo -e "${RED}Hardening # $STATUS_NUM${NC} $1"
	echo -e "Hardening..."

	echo -e $"\n""[# $STATUS_NUM] $1"$"\n" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
}

# 하드닝 검증 유닛테스트 시 사용
showRemediating_num() {
	# $1 : Title_str
	echo -e "${RED}Hardening Status Checking # $STATUS_NUM${NC} $1"
	echo -e "Checking..."

	echo -e $"\n""[# $STATUS_NUM] $1"$"\n" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
}

showResult_num() {
	echo -e $"\n""${BLACK}[Current Result]${NC}"
	echo -e "${GREEN}Success_num :${NC} $SUCCESS_NUM"
	#echo -e "${YELLOW}Hold_num :${NC} $hold_num"
	echo -e "${RED}Fail_num :${NC} $FAIL_NUM"
	echo -e "___________________________________________________________________________"
}


VSFTPD_Anonymous_Disable() {
	# Disabling Anonymous FTP
	Title_str="(Added) Disabling Anonymous FTP"

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

Vsftpd_Disable() {
	# V-204620
	### 'Ensure FTP Server is not enabled' ###

	Title_str="'vsftpd' Package Disable and ftp anonymous accounts Hardening"
	showHardening_num "${Title_str}"

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

	# 'vsftpd' 패키지 설치 여부 확인
	yum list installed vsftpd
	VSFTPD_CHECK=$?

	# 'vsftpd' 패키지가 설치되어 있지 않은 경우
	if [[ "${VSFTPD_CHECK}" -eq 1 ]]; then
		echo -e "current VSFTPD_CHECK : ${VSFTPD_CHECK}"

		echo -e "${GREEN}Hardening:${NC} 'vsftpd' package isn't installed in this system"
		success_func

	# 'vsftpd' 패키지가 설치되어 있는 경우
	elif [[ "${VSFTPD_CHECK}" -eq 0 ]]; then
		echo -e "current VSFTPD_CHECK : ${VSFTPD_CHECK}"

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
	fi

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

Vsftpd_Disable_VALI() {
	# V-204620
	### 'Ensure FTP Server is not enabled' ###

	Title_str="'vsftpd' Package Disable"
	showRemediating_num "${Title_str}"

	# 'vsftpd' 패키지 설치 여부 확인
	yum list installed vsftpd
	VSFTPD_CHECK=$?

	# 'vsftpd' 패키지가 설치되어 있지 않은 경우
	if [[ "${VSFTPD_CHECK}" -eq 1 ]]; then
		echo -e "current VSFTPD_CHECK : ${VSFTPD_CHECK}"

		echo -e "${GREEN}Hardening:${NC} 'vsftpd' package isn't installed in this system"
		success_func

	# 'vsftpd' 패키지가 설치되어 있는 경우
	elif [[ "${VSFTPD_CHECK}" -eq 0 ]]; then
		echo -e "current VSFTPD_CHECK : ${VSFTPD_CHECK}"

		# 현재 상태가 active이든 아니든 reboot시 vsftpd가 start 되지 않도록 해야 함
		systemctl disable vsftpd

		FTP_Checks="$(systemctl status vsftpd | grep Active | awk '{print $2}')"

		if [[ "$FTP_Checks" == "inactive" ]]; then
			echo -e "${GREEN}Hardening:${NC} This system's vsftpd service is disabled."
			success_func

			echo -e "'vsftpd' Service disabled" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
		
		elif [[ "$FTP_Checks" == "active" ]]; then
			echo -e "${RED}Not Remediated!!${NC} vsftpd disabling is Failed"
			fail_func "${Title_str}"

			echo -e "'vsftpd' Service enabled" | tee -a ${RESULT_FILE_NAME} > '/dev/null'	
		fi
			
	fi

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

UnitTest() {
	Vsftpd_Disable_VALI
}

UnitTest
