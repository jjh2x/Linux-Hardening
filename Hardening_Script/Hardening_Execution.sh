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

Vsftpd_Remove() {
	# V-204620
	### 'Ensure FTP Server is not enabled' ###

	Title_str="'vsftpd' Package Remove"
	showHardening_num "${Title_str}"

	FTP_Checks="$(yum list installed vsftpd)"
	FTP_Checks=$?
	if [[ "$FTP_Checks" -eq 1 ]]; then
		echo -e "${GREEN}Hardening:${NC} This system has no vsfptd packge"
		success_func
	else
		yum remove vsftpd -y
		yum list installed | grep vsftpd
		FTP_Checks=$?
		if [[ "$FTP_Checks" -eq 1 ]]; then
			echo -e "${GREEN}Hardening:${NC} Ensure FTP Server is Removed and not enabled successfully!"
			success_func
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

		7)
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

		7)
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


VSFTPD_Anonymous_Disable() {
	# Disabling Anonymous FTP
	Title_str="(Added) Disabling Anonymous FTP"
	showHardening_num "${Title_str}"
	
	sed -ri "s/^(\s*)anonymous_enable\s*=\s*\S+(\s*#.*)?\s*/\1anonymous_enable=NO\2/" /etc/vsftpd/vsftpd.conf
	
	anonyFTP_dis_result="$(egrep "^(\s*)anonymous_enable=NO(\s*)" /etc/vsftpd/vsftpd.conf)"
	anonyFTP_dis_result=$?
	
	if [[ "$anonyFTP_dis_result" -eq 0 ]]; then
		success_func
	else
		fail_func
	fi
	
	showResult_num
	STATUS_NUM=$((STATUS_NUM + 1))
}

function Hardening_Machine() {
	PermitEmptyPasswords_No
	NoEmptyPassword_Setting
	TelnetServer_Remove
	#SNMP_CommunityStrings_Change
	TFTP_Server_Remove
	#Vsftpd_Remove
	#VSFTPD_Anonymous_Disable
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
}

function Hardening_Server() {
	PermitEmptyPasswords_No
	NoEmptyPassword_Setting
	TelnetServer_Remove
	#SNMP_CommunityStrings_Change
	TFTP_Server_Remove
	Vsftpd_Remove
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
}


