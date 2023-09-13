#! /bin/sh


PermitEmptyPasswords_No() {
	# V-204425
	### Ensure SSH PermitEmptyPasswords is disabled ###
	Title_str="'PermitEmptyPasswords' No"
	showHardening_num "${Title_str}"

	Empty_PW_Checks_1="$(egrep -q "^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$/\1PermitEmptyPasswords no\2/" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config)"
	Empty_PW_Checks_1=$?

	if [[ "$Empty_PW_Checks_1" -eq 0 ]]; then
		echo -e "${GREEN}Hardening:${NC} Ensure SSH PermitEmptyPasswords is disabled"
		success_func 
	else
		echo -e "${RED}UnableToRemediate:${NC} Ensure SSH PermitEmptyPasswords is disabled"
		fail_func 
	fi

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

NoEmptyPassword_Setting() {
	# V-204424
	### Hardening: 'no_empty_passwords' ###
	Title_str="'No_Empty_Passwords' Setting"
	showHardening_num "${Title_str}"

	case $OS_VERSION in
		5)
		  sed -i 's/\<nullok\>//g' /etc/pam.d/system-auth
		  sed -i 's/\<nullok\>//g' /etc/pam.d/system-auth-ac
		  N_E_P_result="$(egrep nullok /etc/pam.d/system-auth /etc/pam.d/system-auth-ac)"
 #echo -e "#4 : OS_Version : $OS_VERSION"
		;;
		7)
	    	  sed --follow-symlinks -i 's/\<nullok\>//g' /etc/pam.d/system-auth
		  sed --follow-symlinks -i 's/\<nullok\>//g' /etc/pam.d/password-auth
		  N_E_P_result="$(egrep nullok /etc/pam.d/system-auth /etc/pam.d/password-auth)"
#echo -e "#4 : OS_Version : $OS_VERSION"
		;;
	esac

	echo "$N_E_P_result"
	if [ -n "$N_E_P_result" ]; then
		echo -e "${RED}UnableToRemediate:${NC} No Empty Passwords Settings"
		fail_func
	else
		echo -e "${GREEN}Hardening:${NC} No Empty Passwords Settings"
		success_func
	fi

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

TelnetServer_Remove() {
	# V-204502
	### Ensure telnet-server is not enabled ###

	Title_str="'Telnet-Server' Remove"
	showHardening_num "${Title_str}"
	
	Telnet_check="$(yum list installed telnet-server)"
	Telnet_check=$?

	# 'telnet-server' Package X
	if [[ "$Telnet_check" -eq 1 ]]; then
		echo -e "${GREEN}Hardening:${NC} Ensure telnet-server is not enabled"
		success_func

	# 'telnet-server' Package O
	else
		Telnet_Remove_Check="$(yum remove telnet-server -y)"
		Telnet_Remove_Check=$?
		if [[ "$Telnet_Remove_Check" -eq 0 ]];then
			yum list installed telnet-server
			Telnet_check=$?
			if [[ "$Telnet_check" -eq 1 ]]; then
				echo -e "${GREEN}Hardening:${NC} Ensure telnet-server is not enabled"
				success_func
			fi
		else
			echo -e "${RED}UnableToRemediate:${NC} Ensure telnet-server is not enabled"
			fail_func
		fi
	fi

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

SNMP_CommunityStrings_Change() {
	# V-204627
	### Ensure SNMP community strings be changed from default  ###

	Title_str="SNMP 'community strings' Change"
	showHardening_num "${Title_str}"

	echo -e "${YELLOW}This is Hold${NC}"
	HOLD_NUM=$((HOLD_NUM + 1 ))
	
	echo -e "This is about 'SNMP community strings'. Current Status is 'Hold'." | tee -a ${RESULT_FILE_NAME} > '/dev/null'


	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

TFTP_Server_Remove() {
	# V-204621
	### Ensure tftp-server is not enabled ###

	Title_str="'tftp-server' Package Remove"
	showHardening_num "${Title_str}"

	TFTP_Checks="$(yum list installed tftp-server)"
	TFTP_Checks=$?

	if [[ "$TFTP_Checks" -eq 1 ]]; then
		echo -e "${GREEN}Hardening:${NC} This system has no tftp-server package"
		success_func

	else
		yum remove tftp-server -y
		yum list installed tftp-server
		TFTP_Checks=$?
		if [[ "$TFTP_Checks" -eq 1 ]]; then
			echo -e "${GREEN}Hardening:${NC} Ensure TFTP-Server is Removed and not enabled successfully!"
			success_func
		else
			echo -e "${RED}UnabledToRemediate:${NC} TFTP-Server disabling is Failed"
			fail_func
		fi
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

Vsftpd_Disable() {
	# V-204620
	### 'Ensure FTP Server is not enabled' ###

	Title_str="'vsftpd' Package Disable"
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

RPM_Verifying_Hashes() {
	# V-251702
	### Ensure 'RPM_Verify_Hashes' ###

	Title_str="RPM Verifying 'Hash Algorythms'"
	showHardening_num "${Title_str}"
	
	#files_with_incorrect_hash=$(rpm -Va | grep -E '^..5.* /(bin|sbin|lib|lib64|usr)/' | awk '{print $NF}' )
	#packages_to_reinstall=$(rpm -qf $files_with_incorect_hash | tr '\n' ' ')

	#reinstall_result="$(yum reinstall -y $packages_to_reinstall)"
	#reinstall_result=$?
	#if [[ "$reinstall_result" -eq 0 ]]; then
	#	echo -e "${GREEN}Hardening:${NC} 'RPM_Verify_Hashes'"
	#	SUCCESS_NUM=$((SUCCESS_NUM + 1))
	#else
	#	echo -e "${RED}UnableToRemediate:${NC} 'RPM_Verify_Hashes'"
	#	FAIL_NUM=$((FAIL_NUM + 1))
	#fi

	echo -e "${YELLOW}This is Hold${NC}"
	HOLD_NUM=$((HOLD_NUM + 1))
	echo -e "This is about 'RPM_Verify_Hashes'. Current Status is 'Hold'." | tee -a ${RESULT_FILE_NAME} > '/dev/null'

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

Setting_SSH_Protocol2() {
	# V-204594
	### Ensure SSH Protocol is set to 2 ###

	Title_str="Setting SSH Protocol2"
	showHardening_num "${Title_str}"
	#SSH2_Check="$(egrep -q "^(\s*)Protocol\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)Protocol\s+\S+(\s*#.*)?\s*$/\1Protocol 2\2/" /etc/ssh/sshd_config || echo "Protocol 2" >> /etc/ssh/sshd_config)"
	#SSH2_Check_=$?
	#if [[ "$SSH2_Check" -eq 0 ]]; then
	#	echo -e "${GREEN}Hardening:${NC} Ensure SSH Protocol is set to 2"
	#	SUCCESS_NUM=$((SUCCESS_NUM + 1))
	#else
	#	echo -e "${RED}UnableToRemediate:${NC} Ensure SSH Protocol is set to 2"
	#	FAIL_NUM=$((FAIL_NUM + 1))
	#fi

	echo -e "[Searching 'Protocol' text in /etc/ssh/sshd_config]" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
	echo -e "$(egrep "^(\s*)Protocol\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config)" | tee -a ${RESULT_FILE_NAME} > '/dev/null'

	echo -e "Machine dosen't use SSH Protocol2"
	echo -e "${YELLOW}This is Hold${NC}"
	HOLD_NUM=$((HOLD_NUM + 1))

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

FileInfo_Matching_VendorValue() {
	# V-204392
	### Ensure file permissions, ownership, and group membership of system files and commands match the vendor values ###

	Title_str="File Permissions, Ownership, Group membership of 'system files' and 'commands' matching the vendor values"
	showHardening_num "${Title_str}"

	echo -e "${YELLOW}This is Hold${NC}"

	HOLD_NUM=$((HOLD_NUM + 1))
	echo -e "This is about 'File permissions, ownership, and group membership of system files and commands'. Current Status is 'Hold'." | tee -a ${RESULT_FILE_NAME} > '/dev/null'

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

Grub2_FipsMode_Setting() {
	# V-204497
	### 'grub2_enable_fips_mode' ###

	Title_str="Setting GRUB2 to use 'FIPS Mode'"
	showHardening_num "${Title_str}"

	echo -e "${YELLOW}This is Hold${NC}"
	echo -e "This is about 'GRUB2_enable_fips_mode'. Current Status is 'Hold'." | tee -a ${RESULT_FILE_NAME} > '/dev/null'
	HOLD_NUM=$((HOLD_NUM + 1))


# prelink not installed
#if test -e /etc/sysconfig/prelink -o -e /usr/sbin/prelink; then
#    if grep -q ^PRELINKING /etc/sysconfig/prelink
#    then
#        sed -i 's/^PRELINKING[:blank:]*=[:blank:]*[:alpha:]*/PRELINKING=no/' /etc/sysconfig/prelink
#    else
#        printf '\n' >> /etc/sysconfig/prelink
#        printf '%s\n' '# Set PRELINKING=no per security requirements' 'PRELINKING=no' >> /etc/sysconfig/prelink
#    fi

#    # Undo previous prelink changes to binaries if prelink is available.
#    if test -x /usr/sbin/prelink; then
#        /usr/sbin/prelink -ua
#    fi
#fi

#if grep -q -m1 -o aes /proc/cpuinfo; then
#	if ! rpm -q --quiet "dracut-fips-aesni" ; then
#    yum install -y "dracut-fips-aesni"
#fi
#fi
#if ! rpm -q --quiet "dracut-fips" ; then
#    yum install -y "dracut-fips"
#fi

#dracut -f

# Correct the form of default kernel command line in  grub
#if grep -q '^GRUB_CMDLINE_LINUX=.*fips=.*"'  /etc/default/grub; then
	# modify the GRUB command-line if a fips= arg already exists
#	sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)fips=[^[:space:]]*\(.*"\)/\1 fips=1 \2/'  /etc/default/grub
#else
	# no existing fips=arg is present, append it
#	sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)"/\1 fips=1"/'  /etc/default/grub
#fi

# Get the UUID of the device mounted at /boot.
#BOOT_UUID=$(findmnt --noheadings --output uuid --target /boot)

#if grep -q '^GRUB_CMDLINE_LINUX=".*boot=.*"'  /etc/default/grub; then
	# modify the GRUB command-line if a boot= arg already exists
#	sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)boot=[^[:space:]]*\(.*"\)/\1 boot=UUID='"${BOOT_UUID} \2/" /etc/default/grub
#else
	# no existing boot=arg is present, append it
#	sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)"/\1 boot=UUID='${BOOT_UUID}'"/'  /etc/default/grub
#fi

# Correct the form of kernel command line for each installed kernel in the bootloader
#/sbin/grubby --update-kernel=ALL --args="fips=1 boot=UUID=${BOOT_UUID}"

# Changes to "/etc/default/grub" require rebuilding the "grub.cfg" file as follows
#grub2-mkconfig -o /boot/grub2/grub.cfg
#grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
# END fix for 'grub2_enable_fips_mode'fips_mode_result1="$(cat /proc/sys/crypto/fips_enabled)"

#echo -e "${RED}You Need To Reboot${NC} for applying "fips mode""
#fips_mode_result1="$(cat /proc/sys/crypto/fips_enabled)"
#fips_mode_result2="$(ls -l /etc/system-fips)"
#echo "Verifying fips_mode_1: $fips_mode_result1 (must be 1)"
#echo "Verifying fips_mode_2: $fips_mode_result2 (must return /etc/system-fips)"


	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

Lock_NullPW_Accounts() {
	# V-251702
	### 'LOCK accounts configured with Blank or Null Passwords' ###

	Title_str="Lock accounts configured with Blank or Null PW"
	showHardening_num "${Title_str}"

	# Accounts configured with Blank or Null Passwords
	Null_PW_Checks_result="$(awk -F: '!$2 {print $1}' /etc/shadow)"
	Null_PW_Lock_user=""

	for user in $Null_PW_Checks_result; do
		if [ -n $user ] && [ $user != "demo" ] 
		then
			passwd -l $user
			Null_PW_Lock_user=$Null_PW_Lock_user$'\n'$user
		else
			echo -e "There is no accounts configured with Blank or Null PW." | tee -a ${RESULT_FILE_NAME} > '/dev/null' 
		fi
	done
	
	success_func
	echo -e "${GREEN}Hardening:${NC} Lock accounts configured with Blank or Null Passwords"

	echo
	echo -e "[Locked User List]${NC} ${RED}(Must Be NO RETURN)${NC}:"
	echo -e "These users password is null. Change the PW Right Now!"
	echo -e "${RED}$Null_PW_Lock_user${NC}"


	# list making
	echo -e "[Locked_User(Blank or Null PW)_List]" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
	echo -e "$Null_PW_Lock_user" | tee -a ${RESULT_FILE_NAME} > '/dev/null'

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

Setting_SystemAccount_NonLogin() {
	# V-204462
	### Ensure system accounts are non-login ###

	Title_str="Setting 'System Accounts' Non-Login"
	showHardening_num "${Title_str}"

	Locked_user_list=""
	Nologin_user_list=""
	for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
		if [ $user != "root" ] && [ $user != "demo" ]
		then
			/usr/sbin/usermod -L $user
			Locked_user_list=$Locked_user_list$'\n'$user
			if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]
			then
				/usr/sbin/usermod -s /sbin/nologin $user
				Nologin_user_list=$Nologin_user_list$'\n'$user
			fi
		fi
	done

	success_func

	# list making 
	echo -e "[Locked_User_List]" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
	echo -e "$Locked_user_list" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
	echo -e | tee -a ${RESULT_FILE_NAME} > '/dev/null'
	echo -e "[Nologin_User_List]" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
	echo -e "$Nologin_user_list" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
	echo -e "${GREEN}Hardening:${NC} Ensure system accounts are non-login"

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
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


CAD_Key_Disabling_FILE() {
	# V-204456
	### '00-disable-CAD' file checks ###

	Title_str="Setting 'Ctrl+Alt+De'l Key is Disabled #1 (GUI)"
	showHardening_num "${Title_str}"

	case $OS_VERSION in
		5)
		  CAD_Key_Check="$(grep -E '^ca::ctrlaltdel' /etc/inittab)"
		  CAD_Key_Check=$?

		  if [[ $CAD_Key_Check -eq 1 ]]; then
		  	echo -e "${GREEN}Hardening:${NC} Disable 'Ctrl+Alt+Del' Key is disabled #2"
			success_func
			echo -e "This is about 'ca:ctrlaltdel~' in /etc/intitab DIR. Success!!" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
		  else
			sed -ri '/ca::ctrlaltdel/ s/^/#/' /etc/inittab
			init q

			grep -E '^ca::ctrlaltdel' /etc/inittab
			CAD_Key_Check=$?
			if [[ $CAD_Key_Check -eq 1 ]]; then
				echo -e "${GREEN}Hardening:${NC} Disable 'Ctrl+Alt+Del' Key is disabled #2"
				success_func
				echo -e "This is about 'ca:ctrlaltdel~' in /etc/intitab DIR. Success!!" | tee -a ${RESULT_FILE_NAME} > '/dev/null'

			else
				echo -e "${RED}Failed:${NC} Disabling 'Ctrl+Alt+Del' Key is Failed."
				fail_func
				echo -e "This is about 'ca::ctrlaltdel~' in /etc/intitab DIR. Failed!!" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
		  	fi
		  fi
		;;

		7|8)
		  disableCAD_file_dir="/etc/dconf/db/local.d/00-disable-CAD"
		  if [ ! -e $disableCAD_file_dir ]; then
		  	echo "[org/gnome/settings-daemon/plugins/media-keys]" > $disableCAD_file_dir
		  	echo "logout=''" >> $disableCAD_file_dir
		  	dconf update

		  else
		  	echo -e "'00-disable-CAD'${NC} ${GREEN}exists.${NC} Success!!"
		  fi

		  disableCAD_file_checks="$(grep logout $disableCAD_file_dir)"
		  echo
		  echo -e "Verifying if there is '00-disable-CAD' file"
		  echo -e "${RED}(Must Return 'logout='')${NC}"
		  echo -e "${BLUE}$disableCAD_file_checks${NC}"

		  if [[ "$disableCAD_file_checks" == 'logout='\'''\''' ]]; then
		  echo -e "${GREEN}Hardening:${NC} 'Ctrl+Alt+Del' Key is Disalbed #1"
		  success_func

		  else
		  	echo -e "${RED}UnableToRemediate:${NC} 'Ctrl+Alt+Del' Key is Disabled #1"
		  	fail_func
		  fi

		;;
	esac
	  
	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

CAD_Key_Disabling_Systemctl() {
	# V-204455
	### Ensure 'Ctrl+Alt+Del' Key is disabled ###

	Title_str="Setting 'Ctrl+Alt+Del' Key is disabled #2"
	showHardening_num "${Title_str}"
	
	case $OS_VERSION in
		5)
		  echo -e "RHEL5 has not 'ctrl-alt-del.target'"
		  echo -e "This Remediation is Passed."
		  echo -e "RHEL5 : systemctl mask 'ctrl-alt-del.target' X -> PASS" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
		  success_func
		  echo -e "${GREEN}Hardening:${NC} 'Ctrl+Alt+Del' Key is Disabled #1"
		;;

		7|8)
		  rhel_CAD_Key="$(systemctl mask ctrl-alt-del.target)"
		  rhel_CAD_Key=$?
		  if [[ "$rhel_CAD_Key" -eq 0 ]]; then
		  	echo -e "${GREEN}Hardening:${NC} Disable 'Ctrl+Alt+Del' Key is disabled #2"
		  	success_func

		  else
			echo -e "${RED}UnableToRemediate:${NC} Disable 'Ctrl+Alt+Del' Key is disabled #2"
			fail_func

		  fi

		;;
	esac
	 
	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

Setting_UEFI_Authentication() {
	# V-204440
	### 'Making authentication upon UEFI booting into single-user and maintenanace modes' ###

	Title_str="Making authentication upon UEFI booting"
	showHardening_num "${Title_str}"

	echo -e "${YELLOW}This is Hold${NC}"
	HOLD_NUM=$((HOLD_NUM + 1))
	echo -e "This is about 'Making Authentication upon UEFI booting'. Current Status is 'Hold'." | tee -a ${RESULT_FILE_NAME} > '/dev/null'

	#UEFI_Checks="$(ls /sys/firmware/efi)"
	#UEFI_Checks=$?
	#if [[ $UEFI_Checks -eq 0 ]]; then
	#	GRUB2_PW_Checks="$(grep -iw grub2_password /boot/efi/EFI/redhat/user.cfg | cut -c 16-33)"
	#	str_forComparing_18="grub.pbkdf2.sha512"

	#	echo -e "This is UEFI Booting System."

	#	if [[ $GRUB2_PW_Checks != $str_forComparing_18 ]] || [[ ! -n $GRUB2_PW_Checks ]]; then 
	#		echo -e "You need to set password for UEFI booting"

	#		grub2-setpassword
	#		grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
	#		if [[ $GRUB2_PW_Checks != $str_forComparing_18 ]]; then
	#			echo -e "PASSWORD SET SUCCESSFUL!"
	#			echo -e "${GREEN}Remediataed:${NC} Authentication upon UEFI booting"
	#			SUCCESS_NUM=$((SUCCESS_NUM + 1))
	#		fi

	#	else
	#		echo -e "This system has password for UEFI booting, Nice!!"
	#		echo -e "${GREEN}Hardening:${NC} Authentication upon UEFI booting"
	#		SUCCESS_NUM=$((SUCCESS_NUM + 1))
	#	fi
	#else
	#	echo -e "${GREEN}This is BIOS Booting System.${NC}"
	#	SUCCESS_NUM=$((SUCCESS_NUM + 1))
	#fi

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

NIS_Server_Remove() {
	# V-204443
	### Ensure NIS Server is not enabled ###

	Title_str="'ypserv' Package (NIS-Server) Remove"
	showHardening_num "${Title_str}"


	yum list installed ypserv
	ypserv_check=$?

	if [[ "$ypserv_check" -eq 0 ]]; then
		yum remove ypserv -y
		
		yum list installed ypserv
		ypserv_check=$?
		
		if [[ "$ypserv_check" -eq 1 ]]; then
			echo -e "${GREEN}Hardening:${NC} This system has no 'ypserv' package"
			success_func
		else
			echo -e "${RED}UnableToRemediate:${NC} Removing 'ypserv' is Failed"
			fail_func
		fi

	else
		echo -e "${GREEN}Hardening:${NC} Ensure NIS Server is not installed"
		success_func
	fi

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

RSH_Server_Remove() {
	# V-204442
	### Ensure rsh server is not enabled ###

	Title_str="'rsh-server' Package Remove"
	showHardening_num "${Title_str}"

	yum list installed rsh-server
	rsh_server_check=$?

	if [[ "$rsh_server_check" -eq 0 ]]; then
		yum remove rsh-server -y
		
		yum list installed rsh-server
		rsh_server_check=$?
		
		if [[ "$rsh_server_check" -eq 1 ]]; then
			echo -e "${GREEN}Hardening:${NC} This system has no 'rsh-server' package"
			success_func
		else
			echo -e "${RED}UnableToRemediate:${NC} Removing 'rsh-server' is Failed"
			fail_func
		fi

	else
		echo -e "${GREEN}Hardening:${NC} This systeme has no 'rsh server' package"
		success_func
	fi

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

Gpgcheck_Activating() {
	# V-204447
	### Ensure gpgcheck is globally activated ###

	Title_str="Setting 'GPGCHECK' is globally activated"
	showHardening_num "${Title_str}"

	GC_Activation_result="$(egrep -q "^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$" /etc/yum.conf && sed -ri "s/^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$/\1gpgcheck=1\2/" /etc/yum.conf || echo "gpgcheck=1" >> /etc/yum.conf)"
	GC_Activation_result=$?

	grep_gpgcheck_result="$(grep gpgcheck /etc/yum.conf)"
	Log_str_GC_Result="[/etc/yum.conf]"$"\n"$grep_gpgcheck_result

	YUM_REPO_LIST=$(ls /etc/yum.repos.d/ | grep repo$)

	gpgcheck_result_temp=0
	for reponame in $YUM_REPO_LIST; do
		file=/etc/yum.repos.d/$reponame

		GC_Activation_Repo_result="$(egrep -q "^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$" $file && sed -ri "s/^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$/\1gpgcheck=1\2/" $file || echo "gpgcheck=1" >> $file)"
		GC_Activation_Repo_result=$?
		#echo -e "GC_Activation_Repo_result : $GC_Activation_Repo_result"

		grep_gpgcheck_result="$(grep gpgcheck $file)"
		Log_str_GC_Result=$Log_str_GC_Result$'\n'[$file]$'\n'$grep_gpgcheck_result

		if [[ "$GC_Activation_Repo_result" -eq 0 ]]; then
			((gpgcheck_result_temp=gpgcheck_result_temp + 1))
			#echo -e "gpgcheck_result_temp : $gpgcheck_result_temp"
		fi
	done

	repo_count="$(ls /etc/yum.repos.d/ | grep repo$ | wc -l)"
	#echo -e "repo_count : $repo_count"
	if [[ "$GC_Activation_result" -eq 0 ]] && [[ "$gpgcheck_result_temp" -eq "$repo_count" ]]; then
		echo -e "${GREEN}Hardening:${NC} Ensure gpgcheck is globally activated"
		success_func
	else
		echo -e "${RED}UnableToRemediate:${NC} Ensure gpgcheck is globally activated"
		fail_func
	fi

	# list making
	echo -e "['gpgcheck' value RESULT]" | tee -a ${RESULT_FILE_NAME} > '/dev/null'
	echo -e "$Log_str_GC_Result" | tee -a ${RESULT_FILE_NAME} > '/dev/null'

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

Localpkg_Gpgcheck_Activating() {
	# V-204448
	### Ensure localpkg_gpgcheck is globally activatied ###

	Title_str="Setting 'Local Package GPGCHECK' is globally activatied"
	showHardening_num "${Title_str}"

	#echo -e "${YELLOW}This is Hold${NC}"
	#HOLD_NUM=$((HOLD_NUM + 1))

	success_func 

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

Verification_VirusScan_Program() {
	# V-214801
	### Ensure using virus scan program ###

	Title_str="Verification of Using 'Virus Scan Program'"
	showHardening_num "${Title_str}"	
	
	ps -ef | grep "klnagent64" | grep -v grep 

	KICS_agent_check=$?
	if [[ "$KICS_agent_check" -eq 1 ]]; then
		echo -e "${RED}AgentDown:${NC} This system's KICS agent is down now."
		fail_func
	else
		echo -e "${GREEN}Hardening:${NC} KICS is currently running as a virus scan program."
		success_func
	fi

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
	    if [[ "${disableAutoLogin_checks}" -eq 0 ]]; then	# There is string of "AutomaticLoginEnable"
		sed -i "s/^AutomaticLoginEnable=.*/AutomaticLoginEnable=False/g" /etc/gdm/custom.conf
	    else
		sed -i "/^\[daemon\]/a\AutomaticLoginEnable=False" /etc/gdm/custom.conf
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

SSH_Weak_Conf_Remediation() {
	Title_str="SSH Weak Configuration Remediation"
	showHardening_num "${Title_str}"

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


	# 현재 시스템에 설정되어 있는 MAC Algorithms
	current_MACs=$(sshd -T | grep -oP '(?<=^macs\s)\S+')

	# 제외되어야 할 MAC Algorihtms
	TOBE_DISABLED_MACs=("umac-64-etm@openssh.com" "umac-64@openssh.com" "umac-128@openssh.com" "hmac-sha1" "hmac-sha1-etm@openssh.com" "hmac-sha2-256" "hmac-sha2-512")

	MACs_append_str="macs $(Filtering_Weak_Conf "$current_MACs" ${TOBE_DISABLED_MACs[@]})"

	# /etc/ssh/sshd_config에 Ciphers 설정이 들어가 있는지 판단
	grep_result="$(grep -e "^macs" /etc/ssh/sshd_config)"

	# MACs 설정이 없다면
	if [[ -z $grep_result ]]; then
		echo "$MACs_append_str" >> /etc/ssh/sshd_config
	# MACs 설정이 있다면
	else
		sed -i "s/^macs.*/$MACs_append_str/g" /etc/ssh/sshd_config
	fi


	# 현재 시스템에 설정되어 있는 Cipher Algorithms
	current_Ciphers=$(sshd -T | grep -oP '(?<=^ciphers\s)\S+')

	# 제외되어야 할 Cipher Algorihtms
	TOBE_DISABLED_Ciphers=("aes128-cbc" "aes192-cbc" "aes256-cbc" "blowfish-cbc" "cast128-cbc" "3des-cbc" "ecdsa-sha2-nistp256" "ssh-rsa")
	
	Ciphers_append_str="ciphers $(Filtering_Weak_Conf "$current_Ciphers" ${TOBE_DISABLED_Ciphers[@]})"

	# /etc/ssh/sshd_config에 Ciphers 설정이 들어가 있는지 판단
	grep_result="$(grep -e "^ciphers" /etc/ssh/sshd_config)"

	# Ciphers 설정이 없다면
	if [[ -z $grep_result ]]; then
		echo "$Ciphers_append_str" >> /etc/ssh/sshd_config
	# Ciphers 설정이 있다면
	else
		sed -i "s/^ciphers.*/$Ciphers_append_str/g" /etc/ssh/sshd_config
	fi


	# Weak HostKeyAlgorithm을 사용하는 private-key 파일 사용 제외
	sed -i "s/^HostKey \/etc\/ssh\/ssh_host_\(rsa\|dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g" /etc/ssh/sshd_config

	# ssh server 노드의 ed25519만 사용 - Weak HostKeyAlgorithms 제외하기 위함
	HostKeyAlgoConfig_str="HostKeyAlgorithms ssh-ed25519"
	# sshd_config에 HostKeyAlgorithms 설정이 존재하지 않는다면 isNotHostKeyAlgoConfig 값이 1이 됨
	grep -E '^HostKeyAlgorithms.*' /etc/ssh/sshd_config > /dev/null
	isNotHostKeyAlgoConfig=$?

	# sshd_config에 HostKeyAlgorithms 설정이 없는 경우
	if [[ $isNotHostKeyAlgoConfig -eq 1 ]]; then
		echo "$HostKeyAlgoConfig_str" >> /etc/ssh/sshd_config
	
	# sshd_config에 HostKeyAlgorihtms 설정이 있는 경우
	else
		sed -i "s/^HostKeyAlgorithms.*/$HostKeyAlgoConfig_str/g" /etc/ssh/sshd_config
	fi

	systemctl restart sshd

	success_func
	echo -e "SSH Weak Configuration Hardening was ${GREEN}performed successfully!${NC}"

	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

function Hardening_Machine() {
	PermitEmptyPasswords_No
	NoEmptyPassword_Setting
	TelnetServer_Remove
	#SNMP_CommunityStrings_Change
	TFTP_Server_Remove
	Vsftpd_Disable
	#RPM_Verifying_Hashes
	#Setting_SSH_Protocol2
	#FileInfo_Matching_VendorValue
	#Grub2_FipsMode_Setting
	Lock_NullPW_Accounts
	Setting_SystemAccount_NonLogin
	Verification_Vendor_Supported_Release
	CAD_Key_Disabling_FILE
	CAD_Key_Disabling_Systemctl
	#Setting_UEFI_Authentication
	#NIS_Server_Remove
	RSH_Server_Remove
	Gpgcheck_Activating
	#Localpkg_Gpgcheck_Activating
	Verification_VirusScan_Program
	GDM_AutomaticLogin_Disabling
	SSH_Weak_Conf_Remediation
}

function Hardening_Server() {
	PermitEmptyPasswords_No
	NoEmptyPassword_Setting
	TelnetServer_Remove
	#SNMP_CommunityStrings_Change
	TFTP_Server_Remove
	Vsftpd_Disable
	#RPM_Verifying_Hashes
	#Setting_SSH_Protocol2
	#FileInfo_Matching_VendorValue
	#Grub2_FipsMode_Setting
	Lock_NullPW_Accounts
	Setting_SystemAccount_NonLogin
	Verification_Vendor_Supported_Release
	CAD_Key_Disabling_FILE
	CAD_Key_Disabling_Systemctl
	#Setting_UEFI_Authentication
	NIS_Server_Remove
	RSH_Server_Remove
	Gpgcheck_Activating
	#Localpkg_Gpgcheck_Activating
	Verification_VirusScan_Program
	GDM_AutomaticLogin_Disabling
	SSH_Weak_Conf_Remediation
}


