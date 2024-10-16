#!/bin/bash

PROGRAM_NAME="nmap_scanner"
LOG_DIR="$HOME/$PROGRAM_NAME"
OUTPUT_DIR="$LOG_DIR/results"
TIMESTAMP=$(date +%F_%H-%M-%S)
FINAL_CVE_FILE="$OUTPUT_DIR/cve_vulnerabilities_$TIMESTAMP.csv"
JSON_OUTPUT_FILE="$OUTPUT_DIR/nmap_scan_$TIMESTAMP.json"
HTML_OUTPUT_FILE="$OUTPUT_DIR/nmap_scan_$TIMESTAMP.html"
SEARCHSPLOIT_LOG="$OUTPUT_DIR/searchsploit_log_$TIMESTAMP.txt"
TEMP_CVE_FILE="$OUTPUT_DIR/cve_vulnerabilities_temp_$TIMESTAMP.csv"
LOG_FILE="$LOG_DIR/scan_log_$TIMESTAMP.log"

mkdir -p "$OUTPUT_DIR"

REQUIRED_CMDS=("nmap" "whiptail" "searchsploit" "msfconsole" "xmllint" "xsltproc" "ip" "mail")
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: Required command '$cmd' not found. Please install it before running the script."
        exit 1
    fi
done

display_ascii_art() {
    clear
    
    echo "=========================================================================="
    echo " "
    echo "  Improvements: read in web module"
    echo "  Liscence: GPL3" 
    echo "  AUTHOR: SATUNIX" 
    echo "  DIFFICULTY: EASY" 
    echo "  PURPOSE: Legal and Ethical Hacking Purposes. I got sick of doing all of 
    this manually in boxes and ctfs so I made it a script." 
    echo "  Disclaimer: No warranty, No Liability, Free to Use" 
    echo "  Date: 16/10/2023"
    echo " "
    echo "              Welcome to the Nmap Automated Scanner Script"
    echo " "
    echo "=========================================================================="
}

display_menu() {
    local title="$1"
    local prompt="$2"
    shift 2
    local options=("$@")
    local choice

    while true; do
        choice=$(whiptail --title "$title" --menu "$prompt" 20 78 10 "${options[@]}" 3>&1 1>&2 2>&3)
        if [ $? -eq 0 ] && [ -n "$choice" ]; then
            echo "$choice"
            break
        else
            whiptail --msgbox "You must make a selection. Please try again." 8 60
        fi
    done
}

get_input() {
    local title="$1"
    local prompt="$2"
    local default="$3"
    local input

    while true; do
        input=$(whiptail --title "$title" --inputbox "$prompt" 10 60 "$default" 3>&1 1>&2 2>&3)
        if [ $? -eq 0 ] && [ -n "$input" ]; then
            echo "$input"
            break
        else
            whiptail --msgbox "Input cannot be empty. Please try again." 8 60
        fi
    done
}

get_confirmation() {
    whiptail --title "$1" --yesno "$2" 10 60
    return $?
}

setup_logging() {
    touch "$LOG_FILE"
    echo "Log created at $LOG_FILE"
}

get_targets() {
    while true; do
        TARGET_INPUT_METHOD=$(display_menu "Target Input Method" "Choose how to input targets:" \
            "1" "Enter target IP/Range" \
            "2" "Import targets from a file" \
            "3" "Use current network subnet")

        case "$TARGET_INPUT_METHOD" in
            1)
                TARGETS=$(get_input "Target Input" "Enter the target IP/Range (e.g., 192.168.1.0/24):" "")
                MAIN_TARGET="$TARGETS"
                break
                ;;
            2)
                TARGET_FILE=$(get_input "Target File Input" "Enter the path to the file containing targets:" "$HOME/targets.txt")
                if [ -f "$TARGET_FILE" ]; then
                    TARGETS=$(tr '\n' ' ' < "$TARGET_FILE")
                    MAIN_TARGET=$(head -n 1 "$TARGET_FILE")
                    break
                else
                    whiptail --msgbox "File not found: $TARGET_FILE. Please try again." 8 60
                fi
                ;;
            3)
                INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
                SUBNET=$(ip -o -f inet addr show "$INTERFACE" | awk '{print $4}')
                TARGETS="$SUBNET"
                MAIN_TARGET=$(echo "$SUBNET" | sed 's/\/.*//')
                break
                ;;
            *)
                whiptail --msgbox "Invalid selection. Please try again." 8 60
                ;;
        esac
    done
}

choose_nmap_options() {
    SCAN_OPTIONS=""
    while true; do
        SCAN_OPTION=$(display_menu "Nmap Scan Options" "Choose additional Nmap options:" \
            "1" "Fragment Packets (-f)" \
            "2" "Set Timing Template (1-5)" \
            "3" "Enable OS detection (-O)" \
            "4" "Enable Service detection (-sV)" \
            "5" "Run Traceroute (--traceroute)" \
            "6" "Verbose output (-v)" \
            "7" "Custom Nmap options" \
            "8" "Specify ports to scan" \
            "9" "Continue with selected options")

        case $SCAN_OPTION in
            1) SCAN_OPTIONS+=" -f";;
            2)
                TIMING=$(get_input "Timing Template" "Enter timing template (1-5, 5 is fastest):" "3")
                if [[ "$TIMING" =~ ^[1-5]$ ]]; then
                    SCAN_OPTIONS+=" -T$TIMING"
                else
                    whiptail --msgbox "Invalid timing template. Please enter a number between 1 and 5." 8 60
                fi
                ;;
            3) SCAN_OPTIONS+=" -O";;
            4) SCAN_OPTIONS+=" -sV";;
            5) SCAN_OPTIONS+=" --traceroute";;
            6) SCAN_OPTIONS+=" -v";;
            7)
                CUSTOM_OPTIONS=$(get_input "Custom Nmap Options" "Enter custom Nmap options:" "")
                SCAN_OPTIONS+=" $CUSTOM_OPTIONS"
                ;;
            8)
                PORTS=$(get_input "Port Selection" "Enter ports to scan (e.g., 1-65535 or 80,443):" "")
                SCAN_OPTIONS+=" -p $PORTS"
                ;;
            9) break;;
            *) whiptail --msgbox "Invalid option. Please try again." 8 60;;
        esac
    done
}

choose_nmap_scripts() {
    while true; do
        SCRIPTS=$(get_input "Nmap Scripts" "Enter Nmap scripts to run (comma-separated), or leave blank for default vuln scripts:" "vuln")
        if [ -n "$SCRIPTS" ]; then
            SCRIPT_OPTION="--script=$SCRIPTS"
            break
        else
            whiptail --msgbox "Script input cannot be empty. Please try again." 8 60
        fi
    done
}

choose_spoofing_method() {
    while true; do
        SPOOF_OPTION=$(display_menu "Spoofing Method" "Choose a spoofing option:" \
            "1" "Spoof MAC Address" \
            "2" "Spoof IP Address" \
            "3" "Spoof Both MAC and IP" \
            "4" "No Spoofing")

        case $SPOOF_OPTION in
            1)
                SPOOF_MAC=$(get_input "MAC Spoofing" "Enter the MAC address to spoof ('random' for random):" "random")
                SCAN_OPTIONS+=" --spoof-mac $SPOOF_MAC"
                break
                ;;
            2)
                SPOOF_IP=$(get_input "IP Spoofing" "Enter the IP address to spoof:" "")
                SCAN_OPTIONS+=" --source-ip $SPOOF_IP"
                break
                ;;
            3)
                SPOOF_MAC=$(get_input "MAC Spoofing" "Enter the MAC address to spoof ('random' for random):" "random")
                SPOOF_IP=$(get_input "IP Spoofing" "Enter the IP address to spoof:" "")
                SCAN_OPTIONS+=" --spoof-mac $SPOOF_MAC --source-ip $SPOOF_IP"
                break
                ;;
            4) break;;
            *) whiptail --msgbox "Invalid option. Please try again." 8 60;;
        esac
    done
}

choose_output_formats() {
    OUTPUT_FORMATS=""
    while true; do
        FORMAT_OPTION=$(display_menu "Output Formats" "Choose output formats (Select one at a time):" \
            "1" "XML (Default for Metasploit)" \
            "2" "JSON" \
            "3" "HTML" \
            "4" "Continue")

        case $FORMAT_OPTION in
            1)
                OUTPUT_FORMATS+=" -oX $OUTPUT_DIR/nmap_scan_$TIMESTAMP.xml"
                ;;
            2)
                OUTPUT_FORMATS+=" -oJ $JSON_OUTPUT_FILE"
                ;;
            3)
                OUTPUT_FORMATS+=" -oX $OUTPUT_DIR/nmap_scan_$TIMESTAMP.xml"
                OUTPUT_FORMATS+=" && xsltproc $OUTPUT_DIR/nmap_scan_$TIMESTAMP.xml -o $HTML_OUTPUT_FILE"
                ;;
            4) break;;
            *) whiptail --msgbox "Invalid option. Please try again." 8 60;;
        esac
    done
}

confirm_scan() {
    get_confirmation "Confirmation" "Ready to run the Nmap scan with the following settings:\n\nTargets: $TARGETS\nOptions: $SCAN_OPTIONS\nScripts: $SCRIPT_OPTION\nOutput Formats: $OUTPUT_FORMATS\n\nContinue?"
    if [ $? -ne 0 ]; then
        whiptail --msgbox "Scan canceled by user." 8 60
        main_menu
    fi
}

run_nmap_scan() {
    echo "Running Nmap scan with the following command:"
    echo "nmap$SCAN_OPTIONS $SCRIPT_OPTION $TARGETS $OUTPUT_FORMATS"
    eval "nmap$SCAN_OPTIONS $SCRIPT_OPTION $TARGETS $OUTPUT_FORMATS" | tee "$LOG_FILE"
    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        whiptail --msgbox "Nmap scan failed. Please check your options and try again." 8 60
        main_menu
    fi
}

parse_cve_output() {
    echo "Parsing Nmap XML output for CVEs..."
    local xml_file="$OUTPUT_DIR/nmap_scan_$TIMESTAMP.xml"
    if [ ! -f "$xml_file" ]; then
        whiptail --msgbox "XML output file not found. Skipping CVE parsing." 8 60
        return
    fi

    xmllint --xpath "//script[@id='vulners']" "$xml_file" 2>/dev/null | \
    grep -oP 'id="CVE-\d{4}-\d{4,7}"' | cut -d'"' -f2 | sort -u > "$TEMP_CVE_FILE"

    if [ ! -s "$TEMP_CVE_FILE" ]; then
        whiptail --msgbox "No CVEs found in the scan results." 8 60
        return
    fi

    echo "CVE parsing complete. Intermediate output saved to $TEMP_CVE_FILE"
}

run_searchsploit() {
    echo "Running SearchSploit on CVEs..."
    echo "CVE,CVSS Score,Description,EDB-ID" > "$FINAL_CVE_FILE"
    while read -r cve; do
        cvss="N/A"
        desc="N/A"
        edb_ids=$(searchsploit --cve "$cve" -w 2>/dev/null | \
                  grep 'https://www.exploit-db.com/exploits' | \
                  awk '{print $NF}' | sed 's#.*/##' | paste -sd ';' -)

        echo "$cve,$cvss,\"$desc\",\"$edb_ids\"" >> "$FINAL_CVE_FILE"
    done < "$TEMP_CVE_FILE"
    echo "SearchSploit results saved to $FINAL_CVE_FILE"
}

import_metasploit() {
    echo "Importing Nmap results into Metasploit..."
    local xml_file="$OUTPUT_DIR/nmap_scan_$TIMESTAMP.xml"
    if [ -f "$xml_file" ]; then
        msfconsole -q -x "db_import $xml_file; exit"
    else
        whiptail --msgbox "XML output file not found. Skipping Metasploit import." 8 60
    fi
}

detect_web_servers() {
    echo "Detecting web servers from Nmap scan results..."
    local xml_file="$OUTPUT_DIR/nmap_scan_$TIMESTAMP.xml"
    if [ ! -f "$xml_file" ]; then
        whiptail --msgbox "XML output file not found. Cannot detect web servers." 8 60
        return
    fi

    WEB_SERVER_IP_PORTS=()
    while read -r host; do
        ip=$(echo "$host" | grep -oP 'addr="\K[^"]+')
        ports=$(echo "$host" | xmllint --xpath 'string(//ports/port[state/@state="open" and (service/@name="http" or service/@name="https" or service/@tunnel="ssl")]/@portid)' - 2>/dev/null)
        IFS=' ' read -ra port_array <<< "$ports"
        for port in "${port_array[@]}"; do
            if [ -n "$port" ]; then
                WEB_SERVER_IP_PORTS+=("$ip:$port")
            fi
        done
    done < <(xmllint --xpath '//host[address/@addrtype="ipv4"][ports/port[state/@state="open" and (service/@name="http" or service/@name="https" or service/@tunnel="ssl")]]' "$xml_file" 2>/dev/null)

    if [ ${#WEB_SERVER_IP_PORTS[@]} -eq 0 ]; then
        echo "No web servers detected."
        return
    else
        echo "Detected web servers:"
        printf '%s\n' "${WEB_SERVER_IP_PORTS[@]}"
    fi

    get_confirmation "Web Servers Detected" "Do you want to run further preliminary web testing on the detected web servers?"
    if [ $? -eq 0 ]; then
        WEB_SERVERS_FILE="$OUTPUT_DIR/web_servers_$TIMESTAMP.txt"
        printf '%s\n' "${WEB_SERVER_IP_PORTS[@]}" > "$WEB_SERVERS_FILE"
        echo "Running preliminary web testing script on detected web servers..."
        if [ -x "$(command -v web_preliminary_testing.sh)" ]; then
            web_preliminary_testing.sh "$WEB_SERVERS_FILE"
        else
            whiptail --msgbox "Web preliminary testing script 'web_preliminary_testing.sh' not found or not executable." 8 60
        fi
    else
        echo "Skipping preliminary web testing."
    fi
}

send_email_notification() {
    EMAIL_OPTION=$(display_menu "Email Notification" "Do you want to receive an email with the scan results?" \
        "1" "Yes" \
        "2" "No")

    if [ "$EMAIL_OPTION" == "1" ]; then
        EMAIL_ADDRESS=$(get_input "Email Address" "Enter your email address:" "")
        if [[ "$EMAIL_ADDRESS" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$ ]]; then
            echo "Sending email to $EMAIL_ADDRESS..."
            mail -s "Nmap Scan Results" "$EMAIL_ADDRESS" < "$FINAL_CVE_FILE"
            echo "Email sent."
        else
            whiptail --msgbox "Invalid email address. Skipping email notification." 8 60
        fi
    fi
}

print_next_steps() {
    echo "Scan done, read below"
    echo "------------------------------------------------"
    echo "1. Review the CSV report:"
    echo "   $FINAL_CVE_FILE"
    echo ""
    echo "2. Open Metasploit to explore imported data:"
    echo "   msfconsole"
    echo ""
    echo "3. Use relevant exploit modules for any vulnerable service."
    echo "------------------------------------------------"
    echo "Additional outputs:"
    [ -f "$JSON_OUTPUT_FILE" ] && echo "   JSON output: $JSON_OUTPUT_FILE"
    [ -f "$HTML_OUTPUT_FILE" ] && echo "   HTML report: $HTML_OUTPUT_FILE"
}

# Main menu function with suggested improvements
main_menu() {
    display_ascii_art
    setup_logging
    get_targets
    choose_nmap_options
    choose_nmap_scripts
    choose_spoofing_method
    choose_output_formats
    confirm_scan
    # ask for JSON webhook details and to read the docs for the webhook messaging service over HTTPS 
    # useful for when the user doesnt have their own mail server (noob lol) 
    run_nmap_scan
    parse_cve_output
    run_searchsploit
    import_metasploit
    detect_web_servers 
    
    send_email_notification
    
    print_next_steps
}

# Start here (at the end)
main_menu
