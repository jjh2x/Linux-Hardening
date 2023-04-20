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

export VALID_NUM=0
export VALID_STR=""

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
export HARDENING_STATUS_DIR="${HARDENING_HOME}/status/2023_Q1"

export RESULT_FILE_NAME="${HARDENING_STATUS_DIR}/result_${SERVER_IP}_${DATE_NOW}.txt"
export WARNING_FILE_NAME="${HARDENING_STATUS_DIR}/WARNING_${SERVER_IP}_${DATE_NOW}.txt"

touch ${RESULT_FILE_NAME}
cat /dev/null > ${RESULT_FILE_NAME}


success_func() {
	SUCCESS_NUM=$((SUCCESS_NUM + 1))
	VALID_NUM=$((VALID_NUM + 1))
	
	#echo -e "VALID_NUM: ${VALID_NUM}"
}

fail_func() {
	FAIL_NUM=$((FAIL_NUM + 1))
	VALID_STR=$VALID_STR$'\n'"Please Checking the [$1]"

	#echo -e "VALID_NUM: ${VALID_NUM}"
}

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

option_Usage() {
	cat <<EOF

How to run) ./Main_Status.sh [-m|--mahcine]|[-s|--server]
Example) ./Main_Status.sh -m

Available options:
-m, --machine		The target device to record a hardening status is 'Machine'
-s, --server		The target device to record a hardening status is 'Server'

EOF
	exit
}

validating_Hardening() {

	execute_option="$1"

	echo
	echo -e "${GREEN}System Hardening Status Checking script for Linux executed successfully!!${NC}"
	echo
	echo -e "${YELLOW}Summary:${NC}"
	echo -e "${YELLOW}Success:${NC} $SUCCESS_NUM" 
	echo -e "${YELLOW}Failed:${NC} $FAIL_NUM"
	#echo -e "${YELLOW}Remediation Hold:${NC} $hold_num"

	######################################################################################

	# Validation of Hardening

	#LATEST_RESULT_FILENAME="$(ls -ltr result_${SERVER_IP}* | tail -2 | head -1 | awk '{print $9}')"

	#DIFF_RESULT="$(diff ${LATEST_RESULT_FILENAME} ${RESULT_FILE_NAME})"

	echo -e ""
	echo -e ""
	echo -e "Hostname : ${BLACK}$HOSTNAME${NC}"

	#echo -e "execute_option: ${execute_option}"
	case $execute_option in
	    machine)
		if [[ "${VALID_NUM}" -eq 13 ]]; then
	    	    echo -e "${GREEN}Hardening result has not changed!${NC}"

		else

	    	    echo -e "${RED}Hardening result has changed!${NC}"
	    	    echo -e "${VALID_STR}"
		
		    mv "${RESULT_FILE_NAME}" "${WARNING_FILE_NAME}" 
		fi
	    
	    ;;

	    server)	
		if [[ "${VALID_NUM}" -eq 15 ]]; then
	    	    echo -e "${GREEN}Hardening result has not changed!${NC}"

		else
	    	    echo -e "${RED}Hardening result has changed!${NC}"
	    	    echo -e "${VALID_STR}"

		    mv "${RESULT_FILE_NAME}" "${WARNING_FILE_NAME}" 
		fi

	    ;;

	esac

	exit 0
}


if [[ $# -eq 0 ]]
then
	option_Usage
fi

while test $# -gt 0
do
    case "$1" in 
	-m| --machine)
	    echo -e "--------------- Checking Status of Hardening in this ${BLUE}Machine${NC} ---------------"
	    echo ""

	    source "${HARDENING_HOME}/script/Status_Checking.sh"
	    Checking_Machine	# This function is in 'Status_Checking_Machine.sh'
	    
	    validating_Hardening "machine"

	    break;;

	-s| --server)
	    echo -e "--------------- Checking Status of Hardening in this ${BLUE}Server${NC} ---------------"	
	    echo ""
	    
	    source "${HARDENING_HOME}/script/Status_Checking.sh"
	    Checking_Server	# This function is in 'Status_Checking_Machine.sh'

	    validating_Hardening "server"

	    break;;

	-*)
	    echo -e "${RED}Please use the correct options!${NC}"
	    option_Usage
	    exit 1;;
    esac
    shift		
done

