clean this up:

#! /bin/bash

PASSWORD='!@#123qweQWE'

printinfo(){
  echo "Team Number: 17-0197"
  echo "UID: WVV7-DSWG-7XYD"
  echo "Decyption Key: trKHLF10Q8n"
}

installEnableUfw() {
  apt install ufw
  ufw enable
}

enableUfwBasicSettings() {
  ufw deny incoming
  ufw allow outgoing
}

runClamAV() {
  apt update
  apt install clamav
  freshclam
  clamscan -r --infected --bell /
}

setPasswordAge() {
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/g' /etc/login.defs
  sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/g' /etc/login.defs
}

changeUserPassword() {
  # Get all users with UID >= 1000 (typical for regular users)
  users=$(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd)

  # Prepare the options for whiptail
  options=()
  for user in $users; do
    options+=("$user" "" OFF)
  done

  # Display the whiptail checklist
  selected_users=$(whiptail --checklist \
    "Select users to change passwords:" 20 60 10 \
    "${options[@]}" \
    3>&1 1>&2 2>&3)

  # Check if user canceled the operation
  if [ $? -ne 0 ]; then
    echo "Operation canceled."
    exit 1
  fi

  # Remove quotes from the selected_users string
  selected_users=$(echo "$selected_users" | tr -d '"')

  # Change passwords for selected users
  for user in $selected_users; do
    echo "Changing password for $user"
    echo "$user:$PASSWORD" | chpasswd
  done

  echo "Password change operations completed."
}

checkAuthorizedUsers() {
  NC='\033[0m' # No Color
  RED='\033[0;31m'
  inputFile="allowedusers.txt"

  normalUsers=''
  adminUsers=''
  unauthorizedUsers=''

  systemusers=$(awk -F':' '($3 >= 1000 && $3 < 60000) {print $1}' /etc/passwd)

  if [ ! -f "$inputFile" ]; then
    echo "No input file"
    exit 1
  fi

  # Loop through all normal users
  for user in $systemusers; do
    # Check if the user is already in the input file
    if grep -q "^$user$" "$inputFile"; then
      # Check if the user is an admin
      if groups "$user" | grep -q -E '(sudo|wheel)'; then
        adminUsers="$adminUsers\n$user"
      else
        normalUsers="$normalUsers\n$user"
      fi
    else
      unauthorizedUsers="$unauthorizedUsers\n${RED}WARNING: USER: $user NOT IN allowedusers.txt${NC}"
    fi
  done
  echo "Normal Users:"
  echo -e $normalUsers
  echo "++++++++++"
  echo "Admin Users:"
  echo -e $adminUsers
  echo "---------"
  echo "Unauthorized Users:"
  echo -e $unauthorizedUsers
}

#august just added (to check)
configurePAMPasswordRequirements() {
  local configFile="/etc/pam.d/common-password"
  local pamLine1="auth\trequired\tpam_pwquality.so remember=5 retry=3"
  local pamLine2="auth\t[success=23 default=ignore] pam_unix.so nullok"

  echo "Configuring PAM password requirements in $configFile..."

# Backup the configuration file
  backupFile="${configFile}.bak"
  if sudo cp "$configFile" "$backupFile"; then
    echo "Backup of $configFile created at $backupFile"
  else
    echo "Failed to create backup of $configFile. Aborting."
    exit 1
  fi

  # Add the required lines if not already present
  if ! grep -qF "$pamLine1" "$configFile"; then
    echo -e "$pamLine1" | sudo tee -a "$configFile" > /dev/null
    echo "Added line: $pamLine1"
  else
    echo "Line already exists: $pamLine1"
  fi

  if ! grep -qF "$pamLine2" "$configFile"; then
    echo -e "$pamLine2" | sudo tee -a "$configFile" > /dev/null
    echo "Added line: $pamLine2"
  else
    echo "Line already exists: $pamLine2"
  fi

  echo "PAM password requirements configuration completed."
}

secure_linux_setup() {
  echo "=== Setting Up Google Authenticator for SSH ==="
  sudo apt install -y libpam-google-authenticator
  google-authenticator

  echo "Configuring PAM for SSH Google Authenticator..."
  echo "auth required pam_google_authenticator.so" | sudo tee -a /etc/pam.d/sshd
  sudo sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
  sudo systemctl restart ssh

  echo "=== Setting Up Encrypted Directory Using eCryptfs ==="
  sudo apt install -y ecryptfs-utils
  sudo mkdir /encrypted
  echo "Mounting encrypted filesystem..."
  sudo mount -t ecryptfs /encrypted /encrypted <<EOF
passphrase_passwd
passphrase_passwd_verify
filename_encryption_enable=y
filename_encryption_disable=n
key_bytes=32
cipher=aes
EOF

  echo "=== Restricting SSH Access Using Hosts Allow/Deny ==="
  echo "sshd: 192.168.1.0/24" | sudo tee -a /etc/hosts.allow
  echo "ALL: ALL" | sudo tee -a /etc/hosts.deny

  echo "=== Setting Up SELinux for Enhanced Access Control ==="
  sudo apt install -y selinux-basics selinux-policy-default
  sudo selinux-activate
  sudo selinux-activate
  echo "Rebooting to apply SELinux changes..."
  sudo reboot

  echo "=== Configuring Secure Time Synchronization with Chrony ==="
  sudo apt install -y chrony
  echo -e "server 0.pool.ntp.org iburst\nserver 1.pool.ntp.org iburst\nserver 2.pool.ntp.org iburst\nserver 3.pool.ntp.org iburst" | sudo tee -a /etc/chrony/chrony.conf
  sudo systemctl restart chronyd

  echo "=== All Security Enhancements Applied Successfully ==="
}


updatePrograms() {
  CHOICES=$(whiptail --separate-output --checklist "Choose options" 10 75 5 \
    "1" "Firefox" OFF "2" "Libre Office" OFF "3" "Filezilla" OFF "4" "chromium" OFF 3>&1 1>&2 2>&3)

  for CHOICE in $CHOICES; do
    case "$CHOICE" in
    "1")
      echo "Update Firefox"
      ;;
    "2")
      echo "Update Libreoffice"
      ;;
    "3")
      echo "Update Filezilla"
      ;;
    "4")
      echo "Update chromium"
      ;;
    *)
      echo "Unsupported item $CHOICE!" >&2
      exit 1
      ;;
    esac
  done
}

changeConfig() {
  local configFile="$1"
  local setting="$2"
  local value="$3"

  if grep -q "^[#]*\s*$setting" "$configFile"; then
    sed -i "s/^[#]*\s*$setting.*/$setting $value/" "$configFile"
  else
    echo "$setting $value" >> "$configFile"
  fi
}

commencementInstall(){
  CHOICES=$(whiptail --separate-output --checklist "Choose programs to install" 15 75 9 \
    "0" "ALL" OFF "2" "Preform autoremove" OFF "3" "fail2ban" OFF "4" "auditd" OFF "5" "libpam-pwquality" OFF "6" "clamav" OFF "7" "apparmor & apparmor-utils" OFF "8" "ufw" OFF "9" "gufw" OFF 3>&1 1>&2 2>&3)

  for CHOICE in $CHOICES; do
    apt update
    case "$CHOICE" in
    "0")
      echo "Installing all"
      sleep 3
      apt autoremove -y
      apt install fail2ban -y
      apt install auditd -y
      apt install libpam-pwquality -y
      apt install clamav -y
      apt install apparmor apparmor-utils -y
      apt install ufw -y
      apt install gufw -y
      ;;
    "2")
      echo "Autoremoving..."
      sleep 3
      apt autoremove
      ;;
    "3")
      echo "Installing fail2ban"
      apt install fail2ban -y
      ;;
    "4")
      echo "Installing auditd"
      apt install auditd -y
      ;;
    "5")
      echo "Installing libpam-pwqaulity"
      apt install libpam-pwquality -y
      ;;
    "6")
      echo "Installing clamav"
      apt install clamav -y
      ;;
    "7")
      echo "Installing apparmour & apparmor-utils"
      apt install apparmor apparmor-utils -y
      ;;
    "8")
      echo "Installing ufw"
      apt install ufw -y
      ;;
    "9")
      echo "Installing gufw"
      apt install gufw -y
      ;;
    *)
      echo "Unsupported item $CHOICE!" >&2
      exit 1
      ;;
    esac
  done
}

commencementEnable() {
   systemctl enable ssh
   systemctl start ssh

   systemctl enable NetworkManager
   systemctl start NetworkManager

   systemctl enable rsyslog
   systemctl start rsyslog

   systemctl enable systemd-journald
   systemctl start systemd-journald

   dpkg-reconfigure --priority=low unattended-upgrades
   systemctl enable unattended-upgrades
   systemctl start unattended-upgrades
   systemctl enable systemd-timesyncd
   systemctl start systemd-timesyncd

   systemctl enable ntp
   systemctl start ntp

   systemctl enable apparmor
   systemctl start apparmor

   systemctl enable cron
   systemctl start cron

   systemctl enable systemd-tmpfiles-clean.timer
   systemctl start systemd-tmpfiles-clean.timer

   systemctl enable apt-daily.timer
   systemctl start apt-daily.timer

   systemctl enable apt-daily-upgrade.timer
   systemctl start apt-daily-upgrade.timer

   systemctl enable vsftpd
   systemctl start vsftpd

   systemctl enable auditd
   systemctl start auditd

   systemctl enable fail2ban
   systemctl start fail2ban
}

commencementPermissions() {
  chmod 644 /etc/passwd
  chmod 400 /etc/shadow
  chmod 440 /etc/sudoers
  # disable root login
  passwd -l root
}

commencementUFW() {
  ufw enable
  ufw default deny incoming ## Could be bugged
  ufw default allow outgoing
}

commencementSnap() {
  snap refresh
  killall snap-store
  snap refresh
  echo "Please open snap store now"
  sleep 10
}


commencementConfigureSSHD(){
  changeConfig "/etc/ssh/sshd_config" "PermitRootLogin" "no"
  changeConfig "/etc/ssh/sshd_config" "PermitEmptyPasswords" "no"
  changeConfig "/etc/ssh/sshd_config" "X11Forwarding" "no"
  changeConfig "/etc/ssh/sshd_config" "MaxAuthTries" "3"
  changeConfig "/etc/ssh/sshd_config" "ClientAliveInterval" "300"
  changeConfig "/etc/ssh/sshd_config" "ClientAliveCountMax" "2"
  changeConfig "/etc/ssh/sshd_config" "Port" "2222" # Maybe Change Later Depends
}

commencementConfigurePasswordRequirements(){
  # Password quality
  pwqualityFile="/etc/security/pwquality.conf"

  changeConfig "$pwqualityFile" "minlen =" "14"
  changeConfig "$pwqualityFile" "dcredit =" "2"
  changeConfig "$pwqualityFile" "ucredit =" "2"
  changeConfig "$pwqualityFile" "ocredit =" "2"
  changeConfig "$pwqualityFile" "lcredit =" "2"
  changeConfig "$pwqualityFile" "minclass =" "1"

  # Disable nullok
  sed -i 's/\s*nullok\b//g' /etc/pam.d/common-auth
}

commencementConfigureJaill(){
  configureSshdParam(){
    local configFile="$1"
    local setting="$2"
    local value="$3"
  }
}

check_sudo_activity() {
  # Display relevant lines from /etc/sudoers (without comments)
  echo "=== Sudoers File Entries Matching 'ALL' or 'NOPASSWD' ==="
  sudo cat /etc/sudoers | grep -v '^#' | grep -E 'ALL|NOPASSWD'

  # Display recent sudo activity in the auth log
  echo -e "\n=== Sudo Sessions Opened from /var/log/auth.log ==="
  sudo grep 'sudo' /var/log/auth.log | grep 'session opened'

  # Display login details for users in the sudo group
  echo -e "\n=== Recent Login Information for Sudo Group Members ==="
  last | grep -E "$(getent group sudo | cut -d: -f4 | sed 's/,/|/g')"
}

commencement() {
 ## This always has to be run first DO NOT MOVE
# commencementInstall
# commencementEnable
# commencementPermissions
# commencementUFW
# commencementSnap
# check_sudo_activity
# secure_linux_setup
# commencementConfigurePasswordRequirements
 ## DO NOT RUN! THIS WILL BREAK AUTHENTICATION
}

welcome() {
  echo ".--.      .--.     ,-----.     .--.      .--. ";
  echo "|  |_     |  |   .'  .-,  '.   |  |_     |  | ";
  echo "| _( )_   |  |  / ,-.|  \ _ \  | _( )_   |  | ";
  echo "|(_ o _)  |  | ;  \  '_ /  | : |(_ o _)  |  | ";
  echo "| (_,_) \ |  | |  _\`,/ \ _/  | | (_,_) \ |  | ";
  echo "|  |/    \|  | : (  '\_/ \   ; |  |/    \|  | ";
  echo "|  '  /\  \`  |  \ \`\"/  \  ) /  |  '  /\  \`  | ";
  echo "|    /  \    |   '. \_/\`\`\".'   |    /  \    | ";
  echo "\`---'    \`---\`     '-----'     \`---'    \`---\` ";
  echo "                                              ";
  PS3="Select the operation: "

  select opt in info commencement clamscan usrcheck changepass; do

    case $opt in
    info)
      printinfo
      ;;
    clamscan)
      runClamAV
      ;;
    commencement)
      commencement
      ;;
    usrcheck)
      checkAuthorizedUsers
      ;;
    changepass)
      changeUserPassword
      ;;
    *)
      echo "Invalid option $REPLY"
      ;;
    esac
  done

}

# enable password requrements (VERY BROKE)
#
# ssh config (DONE)
# snap / snap store updates (DONE)
# install run virus scanning software (clam av) (DONE)
# install and enable ufw (DONE)
# updates (DONE)
# Disable root (sudo passwd -l root) (DONE)
# secure importaint directories (shadow passwd sudoers) (DONE)
# Check all users against authorized users in readme (DONE)
# Add option to change a user password to the defualt secure one (DONE)
#
welcome