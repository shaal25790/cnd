#!/bin/bash
# Author: Shady Alshamy
# Purpose: To execute checks using the IoC file, generate logs and a report, and upload the outputs to a central server.

SECURITY_DIR="/opt/security" # Define the security directory
WORKING_DIR="$SECURITY_DIR/working" # Define the working directory

ERROR_DIR="$SECURITY_DIR/errors"
ERROR_FILE="$ERROR_DIR/error-$(date +%Y%m%d).tgz"

IOC_FILE="IOC-$(date +%Y%m%d).ioc" # Define the location of the IoC file
IOC_GPG_FILE="IOC-$(date +%Y%m%d).gpg" # Define the location of the signed IoC file

REPORT_FILE="$WORKING_DIR/iocreport-$(date +%Y%m%d).txt" # Define the location of the report file
> $REPORT_FILE # Remove the content of the file in case it's not empty
TMP_LOG="$WORKING_DIR/matches.log.tmp"

# Print a message to both STDOUT & files 
log() { 
    if [[ -z "$2" ]]; then
        more_files=""
    else
        more_files="$2"
    fi
    echo $1 | tee -a $REPORT_FILE $more_files # output to both stdout and file
}

# Create necessary folders if they don't exist
setup() {
    # Only setup when no security dir
    if [ ! -d "$SECURITY_DIR" ]; then 
        echo -e "\n >>> SETUP & PREPARE"
        # Folders don't exist? create 'em and give permissions
        if [ ! -d "$SECURITY_DIR" ]; then
            sudo mkdir $SECURITY_DIR
            sudo chmod 555 $SECURITY_DIR # Read-only folder
            echo "CREATED FOLDER '$SECURITY_DIR', given READ-ONLY permissions"
        fi
        if [ ! -d "$WORKING_DIR" ]; then
            sudo mkdir $WORKING_DIR
            sudo chmod 777 $WORKING_DIR # Both read & write permissions
            echo "CREATED FOLDER '$WORKING_DIR', given all permissions"
        fi
        if [ ! -d "$ERROR_DIR" ]; then
            sudo mkdir $ERROR_DIR
            sudo chmod 777 $ERROR_DIR
            echo "CREATED FOLDER '$ERROR_DIR', given all permissions"
        fi
        
        if [ ! -d "$SECURITY_DIR/bin" ]; then
            sudo mkdir $SECURITY_DIR/bin
            sudo chmod 777 $SECURITY_DIR/bin
            echo "CREATED FOLDER '$SECURITY_DIR/bin', given all permissions"
            
            # Create the validate tool
            echo '#!/bin/bash
                # Define the expected SHA-256 hash of the IoC file
                expected_hash=$1
                WORKING_DIR=$2
                IOC_FILE=$3

                # Calculate the SHA-256 hash of the IoC file
                actual_hash=$(sha256sum "$WORKING_DIR/$IOC_FILE" | awk '\''{ print $1 }'\'')

                # Check if the actual hash matches the expected hash
                if [[ $actual_hash != $expected_hash ]]; then
                    echo "ERROR: The integrity of the IoC file could not be validated"
                    exit 1
                else
                    echo "IoC file integrity VALIDATED SUCCUSSFULLY."
                fi' > $SECURITY_DIR/bin/validate.sh # call it like so: ./validate.sh "expectedhash" $WORKING_DIR $IOC_FILE
            sudo chmod 777 $SECURITY_DIR/bin/validate.sh # Both read & write permissions

            echo -e "VALIDATE TOOL CREATED"

            # Create the strcheck tool
            echo '#!/bin/bash
                # The given string we receive for checking
                str_hash=$1
                WORKING_DIR=$2
                IOC_FILE=$3

                # Calculate the SHA-256 hash of the IoC file
                actual_hash=$(sha256sum "$WORKING_DIR/$IOC_FILE" | awk '\''{ print $1 }'\'')

                # Check if the actual hash matches the str_hash
                if [[ $actual_hash != $str_hash ]]; then
                    echo "ERROR: The hash of the IoC file does not match the given string"
                    exit 1
                else
                    echo "IoC file hash MATCHES the given string."
                fi' > $SECURITY_DIR/bin/strcheck.sh # call it like so: ./strcheck.sh "strhash" $WORKING_DIR $IOC_FILE
            sudo chmod 777 $SECURITY_DIR/bin/strcheck.sh # Both read & write permissions

            echo -e "STRCHECK TOOL CREATED"
        fi
    else
        echo -e "SETUP ALREADY DONE. MOVING ON..\n"
    fi
    
    echo -e "\n 1 >>> SCRIPT SETUP COMPLETE..\n"
}

# Download the IoC file
download_ioc() {
    # Check if we already have today's file 
    if [[ -f "$WORKING_DIR/$IOC_FILE" ]]; then
        echo "$WORKING_DIR/$IOC_FILE Already downloaded. Moving on."
    else
        # Define the URL of the IoC file
        local ioc_url=$1
        echo -e "Downloading from url: $ioc_url \n"

        # Check if the URL starts with https
        if [[ $ioc_url != https* ]]; then
            log "ERROR: The URL must start with https." 
            exit 1
        fi

        # Download the IoC file & the signed file in the working directory
        sudo wget -O "$WORKING_DIR/$IOC_FILE" "$ioc_url"
        echo -e " >>> IOC FILE DOWNLOADED\n"
        sudo wget -O "$WORKING_DIR/$IOC_GPG_FILE" "$ioc_url"
        echo -e " >>> GPG FILE DOWNLOADED\n"

        # Check if the download was successful
        if [[ $? -ne 0 ]]; then
            log "ERROR: Failed to download the IoC file."
            exit 1
        fi
    fi
    
    echo -e "\n 2 >>> IOC & GPG FILES DOWNLOAD..\n\n"
}

# Validate the IoC file
validate_tools() {
    # Define the expected SHA-256 hash of the IoC file
    local expected_hash=$1

    # Calculate the SHA-256 hash of the IoC file
    local actual_hash=$(sha256sum "$WORKING_DIR/$IOC_FILE" | awk '{ print $1 }')

    # Check if the actual hash matches the expected hash
    if [[ $actual_hash != $expected_hash ]]; then
        log "ERROR: The integrity of the IoC file could not be validated."
        exit 1
    fi
    echo -e "\n 3 >>> TOOLS VALIDATION DONE.\n\n"
}

# Validate the IoC file, by checking if file name matches the datestamp
validate_datestamp() {
    # Get datestamp inside IoC file
    second_line=$(sed -n '2p' "$WORKING_DIR/$IOC_FILE" | tr -d '\r\n')
    # Get file name without path 
    base_name=$(basename "$WORKING_DIR/$IOC_FILE") 
    # Get datestamp in file name
    date_stamp=${base_name:4:8} 
    # datestamp in file name matches the one in IoC file ?
    if [[ "$date_stamp" == "$second_line" ]]; then 
        echo "Datestamp validation OK"
    else
        log "WARN: Datestamp does not match the value in the IoC file."
    fi
}

# All the checkings here
check_iocs() {
    # remember to exclude the working dir from the checks, so it does not find values in the ioc file itselft

    # validate_tools
    validate_datestamp

    # Read the IoC file line by line
    while IFS= read -r line; do
        if [[ $line != \#* ]]; then # Ignore comments
            IFS=' ' read -r -a array <<< "$line" # Split the line into an array
            echo "LINE: $line"

            # # Check the integrity of the validation tool
            # if [[ ${array[0]} == "VALIDATE" ]]; then
            #     # Get the hash and directory of validate tool
            #     local hash=${array[1]}
            #     local tool="$SECURITY_DIR/bin/validate.sh"
            #     # Call the validation tool, passing the hash found, to check integrity of the IoC
            #     "$tool" $hash $WORKING_DIR $IOC_FILE
            # fi

            if [[ ${array[0]} == "IOC" ]]; then # Check if the line starts with IOC
                # Get the hash and directory
                local hash=$(echo "${array[1]}" | tr -d '\r\n')
                local directory=$(echo "${array[2]}" | tr -d '\r\n')
                
                # LET's GO! Check if the hash appears in the specified directory
                echo " directory: $directory, hash: $hash"
                if [[ -d "$directory" ]]; then
                    output=$(sudo find "$directory" -type f -not -path "/proc/*" -not -path "/run/*" -not -path "/sys/*" -exec sha256sum {} \; | grep "$hash")
                    if [[ $? -eq 0 ]]; then # If the hash was found, log a warning
                        log "WARN: IOCHASHVALUE '$hash' found in $output" "$TMP_LOG"
                    fi                  
                else
                    log "Directory '$directory' does not exist."
                fi
            fi

            if [[ ${array[0]} == "STR" ]]; then # Check if the line starts with STR
                local str=${array[1]}
                local directory=$(echo "${array[2]}" | tr -d '\r\n')
                if [[ -d "$directory" ]]; then
                    # Check if the STR is found in on of the files in the corresponding directory
                    sudo find "$directory" -type f -exec grep -l -F "$str" {} \; | while read -r filename
                    do
                        log "WARN: STRVALUE '$str' found in $filename" "$TMP_LOG"
                    done

                else
                    log "Directory '$directory' does not exist."
                fi
            fi
        fi
    done < "$WORKING_DIR/$IOC_FILE"
    echo -e "\n 4 >>> IOC CHECK DONE.\n\n"
}

# collect system information
collect_sys_info() {
    # Get currently listening ports (with no DNS/port name resolution)
    listening_ports=$(netstat -tuln)

    # Get current firewall rules (with no DNS/port name resolution)
    firewall_rules=$(iptables -L)

    # Validate that all files installed in /sbin, bin, /usr/sbin, /usr/bin and /usr/lib match the valid hashes in the system package database
    # CODE

    # Report files in /var/www (and subdirectories) that have been created in the last 48 hours
    new_files=$(find /var/www -type f -ctime -2)

    # List any SUID/GID files in the same path regardless of modification time
    suid_gid_files=$(find /var/www \( -perm -4000 -o -perm -2000 \))

    # Ensure that file systems mounted on /var/www/images and /var/www/uploads are set as non-executable (i.e. scripts cannot run from them)
    # CODE
    echo -e "\n 5 >>> SYSTEM INFO COLLECTED.\n\n"
} 

# generate a report
generate_report() {
    # Call the collect_sys_info function to collect system information
    collect_sys_info

    # Write the collected information to the report file
    echo "Listening Ports:" >> "$REPORT_FILE"
    echo "$listening_ports" >> "$REPORT_FILE"
    echo "Firewall Rules:" >> "$REPORT_FILE"
    echo "$firewall_rules" >> "$REPORT_FILE"
    echo "New Files:" >> "$REPORT_FILE"
    echo "$new_files" >> "$REPORT_FILE"
    echo "SUID/GID Files:" >> "$REPORT_FILE"
    echo "$suid_gid_files" >> "$REPORT_FILE"

    echo -e "\n 6>>> REPORT GENERATED.\n\n"
}

# upload outputs to a central server
upload_outputs() {
    # Define the remote server, user identity, and destination directory
    local remote_server=$2
    local user_identity=$3
    local destination_dir="/submission/$(hostname)/$(date +%Y)/$(date +%m)/"

    # Define the path to the SSH identity file
    local ssh_identity_file="$SECURITY_DIR/${user_identity}.id"

    # Upload the outputs to the central server
    rsync -avz -e "ssh -i $ssh_identity_file" "$REPORT_FILE" "${user_identity}@${remote_server}:${destination_dir}"

    # Check if the upload was successful
    if [[ $? -ne 0 ]]; then
        echo "ERROR: Failed to upload the outputs to the central server"
        exit 1
    fi
    echo -e "\n 7 >>> OUTPUT UPLOADED SUCCESSFULLY.\n\n"

    # also include the file if present /opt/security/errors/error-yyymmmdd.tgz
}

# validate the backup on the remote server
validate_backup() {
    # Define the remote server, user identity, and destination directory
    local remote_server=$1
    local user_identity=$2
    local destination_dir="/submission/$(hostname)/$(date +%Y)/$(date +%m)/"

    # Define the path to the SSH identity file
    local ssh_identity_file="$SECURITY_DIR/${user_identity}.id"

    # Define the key ID to use for validation
    local key_id="tht2023@tht.noroff.no"

    # Validate the backup on the remote server
    ssh -i "$ssh_identity_file" "${user_identity}@${remote_server}" "gpg --verify ${destination_dir}${REPORT_FILE}.sig ${destination_dir}${REPORT_FILE}"

    # Check if the validation was successful
    if [[ $? -ne 0 ]]; then
        echo "ERROR: Failed to validate the backup on the remote server"
        exit 1
    fi
    echo -e "\n 8 >>> BACKUP VALIDATED.\n\n"
}

# clean up after the script
clean_up() {
    
    # remove temporary files (matches.log in working dir)
    # compress errors into a tgz file

	echo -e "\n 9 >>> CLEAN UP COMPLETE.\n\n"
}
# shaal25790@stud.noroff.no # shady@noroff2023
# ./tth-IOC.sh "https://raw.githubusercontent.com/shaal25790/cnd/main/IOC-20231122.ioc" "logs.tth.loc.org" "shaal25790"
# Main script execution
echo -e "\n\n============================ MAIN EXECUTION ==============================\n"
setup

echo -e "\n================ download_ioc ================="
download_ioc $1

echo -e "\n================ check_iocs ================="
check_iocs
exit 

echo -e "\n================ generate_report ================="
generate_report

echo -e "\n================ upload_outputs ================="
upload_outputs

echo -e "\n================ validate_backup ================="
validate_backup

echo -e "\n================ clean_up ================="
clean_up

echo -e "\n================ ALL DONE ! ================="