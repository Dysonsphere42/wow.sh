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

commencementInstall(){
  CHOICES=$(whiptail --separate-output --checklist "Choose programs to install" 15 75 9 \
    "0" "ALL" OFF "2" "Preform autoremove" OFF "3" "fail2ban" OFF "4" "auditd" OFF "5" "libpam-pwquality" OFF "6" "clamav" OFF "7" "apparmor & apparmor-utils" OFF "8" "ufw" OFF "9" "gufw" OFF 3>&1 1>&2 2>&3)

  for CHOICE in $CHOICES; do
    apt update
    case "$CHOICE" in
    "0")
      echo "Installing all"
      sleep 3
      apt autoremove
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
  ufw defualt deny incoming ## Could be bugged
  ufw default allow outgoing
}

commencementSnap() {
  snap refresh
  killall snap-store
  snap refresh
  echo "Please open snap store now"
  sleep 10
}

commencement() {
  ## This always has to be run first DO NOT MOVE
 commencementInstall
 commencementEnable
 commencementPermissions
 commencementUFW
 commencementSnap
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

  select opt in info commencement update usrcheck changepass; do

    case $opt in
    info)
      printinfo
      ;;
    update)
      echo "Update"
      updatePrograms
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

# install run virus scanning software (clam av)
# enable password requrements
# ssh config
# snap / snap store updates (DONE)
#
# install and enable ufw (DONE)
# updates (DONE)
# Disable root (sudo passwd -l root) (DONE)
# secure importaint directories (shadow passwd sudoers) (DONE)
# Check all users against authorized users in readme (DONE)
# Add option to change a user password to the defualt secure one (DONE)
#
welcome
