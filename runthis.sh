#!/bin/bash

PASSWORD='!@#123qweQWE'

# Print system information
printinfo() {
  echo "Team Number: 17-0197"
  echo "UID: WVV7-DSWG-7XYD"
  echo "Decryption Key: trKHLF10Q8n"
}

# Install and enable UFW
installEnableUfw() {
  apt update
  apt install -y ufw
  ufw enable
}

# Basic UFW settings: allow outgoing, deny incoming
enableUfwBasicSettings() {
  ufw deny incoming
  ufw allow outgoing
}

# Run ClamAV antivirus scan
runClamAV() {
  apt update
  apt install -y clamav
  freshclam
  clamscan -r --infected --bell /
}

# Set password aging policies
# Maximum password age is set to 90 days and minimum age to 7 days
setPasswordAge() {
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/g' /etc/login.defs
  sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/g' /etc/login.defs
}

# Change password for selected users
# Displays a whiptail dialog to select users and change their passwords
changeUserPassword() {
  # Get all users with UID >= 1000 (typical for regular users)
  users=$(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd)

  # Prepare the options for whiptail
  options=()
  for user in $users; do
    options+=("$user" "" OFF)
  done

  # Display the whiptail checklist to select users to change passwords
  selected_users=$(whiptail --checklist "Select users to change passwords:" 20 60 10 "${options[@]}" 3>&1 1>&2 2>&3)

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

# Check authorized users against a predefined list
checkAuthorizedUsers() {
  NC='\033[0m' # No Color
  RED='\033[0;31m' # Red color for unauthorized users
  inputFile="allowedusers.txt"

  normalUsers=''
  adminUsers=''
  unauthorizedUsers=''

  # Check if allowed users file exists
  if [ ! -f "$inputFile" ]; then
    echo "No input file"
    exit 1
  fi

  # Get all system users with UID between 1000 and 60000
  systemusers=$(awk -F':' '($3 >= 1000 && $3 < 60000) {print $1}' /etc/passwd)

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

  # Output lists of users
  echo "Normal Users:"
  echo -e "$normalUsers"
  echo "++++++++++"
  echo "Admin Users:"
  echo -e "$adminUsers"
  echo "---------"
  echo "Unauthorized Users:"
  echo -e "$unauthorizedUsers"
}

# Configure PAM password requirements
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

# Update selected programs
updatePrograms() {
  CHOICES=$(whiptail --separate-output --checklist "Choose options" 10 75 5 \
    "1" "Firefox" OFF "2" "Libre Office" OFF "3" "Filezilla" OFF "4" "Chromium" OFF 3>&1 1>&2 2>&3)

  for CHOICE in $CHOICES; do
    case "$CHOICE" in
      "1") echo "Updating Firefox"; apt update && apt install -y firefox ;;
      "2") echo "Updating LibreOffice"; apt update && apt install -y libreoffice ;;
      "3") echo "Updating Filezilla"; apt update && apt install -y filezilla ;;
      "4") echo "Updating Chromium"; apt update && apt install -y chromium ;;
      *) echo "Unsupported item $CHOICE!" >&2; exit 1 ;;
    esac
  done
}

# Change configuration in specific files
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

# Install selected programs
commencementInstall() {
  CHOICES=$(whiptail --separate-output --checklist "Choose programs to install" 15 75 9 \
    "0" "ALL" OFF "2" "Perform autoremove" OFF "3" "fail2ban" OFF "4" "auditd" OFF "5" "libpam-pwquality" OFF "6" "clamav" OFF "7" "AppArmor" OFF "8" "ufw" OFF "9" "gufw" OFF 3>&1 1>&2 2>&3)

  apt update
  for CHOICE in $CHOICES; do
    case "$CHOICE" in
      "0") echo "Installing all"; apt install -y fail2ban auditd libpam-pwquality clamav apparmor ufw gufw ;;
      "2") echo "Performing autoremove"; apt autoremove -y ;;
      "3") echo "Installing fail2ban"; apt install -y fail2ban ;;
      "4") echo "Installing auditd"; apt install -y auditd ;;
      "5") echo "Installing libpam-pwquality"; apt install -y libpam-pwquality ;;
      "6") echo "Installing clamav"; apt install -y clamav ;;
      "7") echo "Installing AppArmor"; apt install -y apparmor ;;
      "8") echo "Installing ufw"; apt install -y ufw ;;
      "9") echo "Installing gufw"; apt install -y gufw ;;
      *) echo "Unsupported item $CHOICE!" >&2; exit 1 ;;
    esac
  done
}

# Enable selected system services
commencementEnable() {
  for service in ssh NetworkManager rsyslog systemd-journald unattended-upgrades systemd-timesyncd ntp apparmor cron systemd-tmpfiles-clean.timer apt-daily.timer apt-daily-upgrade.timer vsftpd auditd fail2ban; do
    systemctl enable $service
    systemctl start $service
  done
}

# Set permissions for important system files and disable root login
commencementPermissions() {
  chmod 644 /etc/passwd
  chmod 400 /etc/shadow
  chmod 440 /etc/sudoers
  passwd -l root # disable root login
}

# Configure SSHD settings
commencementConfigureSSHD() {
  changeConfig "/etc/ssh/sshd_config" "PermitRootLogin" "no"
  changeConfig "/etc/ssh/sshd_config" "PermitEmptyPasswords" "no"
  changeConfig "/etc/ssh/sshd_config" "X11Forwarding" "no"
  changeConfig "/etc/ssh/sshd_config" "MaxAuthTries" "3"
  changeConfig "/etc/ssh/sshd_config" "ClientAliveInterval" "300"
  changeConfig "/etc/ssh/sshd_config" "ClientAliveCountMax" "2"
  changeConfig "/etc/ssh/sshd_config" "Port" "2222"
}

# Configure password requirements including password quality and disabling nullok
commencementConfigurePasswordRequirements() {
  configurePAMPasswordRequirements

  pwqualityFile="/etc/security/pwquality.conf"
  changeConfig "$pwqualityFile" "minlen" "14"
  changeConfig "$pwqualityFile" "dcredit" "2"
  changeConfig "$pwqualityFile" "ucredit" "2"
  changeConfig "$pwqualityFile" "ocredit" "2"
  changeConfig "$pwqualityFile" "lcredit" "2"
  changeConfig "$pwqualityFile" "minclass" "1"

  # Disable nullok in authentication
  sed -i 's/\s*nullok\b//g' /etc/pam.d/common-auth
}

# Commence all necessary configurations (to be run initially)
commencement() {
  commencementInstall
  commencementEnable
  commencementPermissions
  commencementConfigurePasswordRequirements
}

# Display the welcome menu for selecting operations
welcome() {
  echo "Welcome to the Security Configuration Script"
  PS3="Select the operation: "

  select opt in info commencement clamscan usrcheck changepass; do
    case $opt in
      info) printinfo ;;
      clamscan) runClamAV ;;
      commencement) commencement ;;
      usrcheck) checkAuthorizedUsers ;;
      changepass) changeUserPassword ;;
      *) echo "Invalid option $REPLY" ;;
    esac
  done
}

# enable password requrements (VERY BROKE)
# ssh config (DONE)
# snap / snap store updates (DONE)
# install run virus scanning software (clam av) (DONE)
# install and enable ufw (DONE)
# updates (DONE)
# Disable root (sudo passwd -l root) (DONE)
# secure importaint directories (shadow passwd sudoers) (DONE)
# Check all users against authorized users in readme (DONE)
# Add option to change a user password to the defualt secure one (DONE)

welcome