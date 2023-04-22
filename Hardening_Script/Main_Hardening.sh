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

	7|8)
	  export SERVER_IP=$(hostname -I | awk '{print $1}')
	;;
esac

export HOSTNAME=$(hostname)

export HARDENING_HOME="/root/hardening"
export HARDENING_LOG_DIR="${HARDENING_HOME}/exec_log"

export RESULT_FILE_NAME="${HARDENING_LOG_DIR}/result_${SERVER_IP}.txt"
export FAILED_FILE_NAME="${HARDENING_LOG_DIR}/FAILED_${SERVER_IP}.txt"

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

option_Usage() {
	cat <<EOF

How to run) ./Main_Hardening.sh [-m|--mahcine]|[-s|--server]
Example) ./Main_Hardening.sh -m

Available options:
-m, --machine		The target device to record a hardening status is 'Machine'
-s, --server		The target device to record a hardening status is 'Server'

EOF
	exit
}

if [[ $# -eq 0 ]]
then
	option_Usage
fi

while test $# -gt 0
do
    case "$1" in 
	-m| --machine)
	    echo -e "--------------- Hardening this ${BLUE}Machine${NC} ---------------"
	    echo ""

	    source "${HARDENING_HOME}/script/Hardening_Execution.sh"
	    Hardening_Machine	# This function is in 'Hardening_Execution.sh'

	    break;;
	-s| --server)
	    echo -e "--------------- Hardening this ${BLUE}Server${NC} ---------------"	
	    echo ""
	    
	    source "${HARDENING_HOME}/script/Hardening_Execution.sh"
	    Hardening_Server	# This function is in 'Hardening_Execution.sh'

	    break;;
	-*)
	    echo -e "${RED}Please use the correct options!${NC}"
	    option_Usage
	    exit 1;;
    esac
    shift		
done


#########################################################################################
echo
echo -e "Hostname : ${BLACK}$HOSTNAME${NC}"
echo -e "${GREEN}System Hardening for Red Hat Enterprise Linux $OS_VERSION executed successfully!!${NC}"
echo
echo -e "${YELLOW}Summary:${NC}"
echo -e "${YELLOW}Success:${NC} $SUCCESS_NUM" 
echo -e "${YELLOW}Fail:${NC} $FAIL_NUM"
#echo -e "${YELLOW}Remediation Hold:${NC} $HOLD_NUM"

#######################################################################################
