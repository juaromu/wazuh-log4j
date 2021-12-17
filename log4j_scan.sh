###########################
######## Script to detect log4j module load in JVM.
######## Modified from script developed by Intezer to format output and integrate with Wazuh agent.
######## Output formatted to JSON and appended to Wazuh's active responses log.
### Aurora Networks Managed Services
### https://www.auroranetworks.net
### info@auroranetworks.net
#############################
#!/bin/bash
# Static active response parameters
# Static active response parameters
LOCAL=`dirname $0`
#------------------------- Active Response Log File -------------------------#

LOG_FILE="/var/ossec/logs/active-responses.log"
scan_output() {
        now=$(date)
        pid=$1
        log4j_version=$2
        has_jndilookupclass=$3
        jar_path=$4
        process_cmd_line=$(tr "\000" " " < /proc/${pid}/cmdline)
        container_id=$(grep -Po -m 1 "((.*/docker/\K.*)|(.*/k8s.io/\K.*))" /proc/${pid}/cgroup)
        if [[ -n ${container_id} ]]; then
                 scan_output='{"scan_date":"'"$now"'", "process_id":"'"$pid"'", "log4j_version":"'"$log4j_version"'", "has_jndilookupclass":"'"$has_jndilookupclass"'", "jar_path":"'"$jar_path"'", "container_id":"'"$container_id"'", "process_cmd_line":"'"$process_cmd_line"'"}'
                 while read -r line; do
                   echo $line >> ${LOG_FILE}
                   sleep 0.1
                 done <<< "$scan_output"
        fi
        if [[ -n ${container_id} ]]; then
                 scan_output='{"scan_date":"'"$now"'", "process_id":"'"$pid"'", "log4j_version":"'"$log4j_version"'", "has_jndilookupclass":"'"$has_jndilookupclass"'", "jar_path":"'"$jar_path"'", "container_id":"'"$container_id"'", "process_cmd_line":"'"$process_cmd_line"'"}'
                 while read -r line; do
                   echo $line >> ${LOG_FILE}
                   sleep 0.1
                 done <<< "$scan_output"
        else
                 scan_output='{"scan_date":"'"$now"'", "process_id":"'"$pid"'", "log4j_version":"'"$log4j_version"'", "has_jndilookupclass":"'"$has_jndilookupclass"'", "jar_path":"'"$jar_path"'","process_cmd_line":"'"$process_cmd_line"'"}'
                 while read -r line; do
                   echo $line >> ${LOG_FILE}
                   sleep 0.1
                 done <<< "$scan_output"
        fi
}

main() {
        # go over all running processes with loaded jar files
        find /proc/*/fd/ -type l 2>/dev/null | while read line; do
                # print a spinner
                sp="/-\|"
                printf "\b${sp:i++%${#sp}:1}"

                # resolve the file descriptor target
                link_target=$(readlink ${line})

                # skip non jar files
                if [[ "$link_target" != *.jar ]]; then
                        continue
                fi

                # resolve an absulte path via procfs to support containerized processes
                proc_base=${line%/*/*}
                pid=${proc_base##*/}
                abs_path=$proc_base/root$link_target


                if [[ "$abs_path" =~ log4j-core.*jar ]]; then
                        # log4j-core is loaded
                        found_log4j=true
                        log4j_jar_name=${abs_path%.*}
                        log4j_version=${log4j_jar_name##*-*-}
                else
                        log4j_match=$(grep -aio -m 1 "log4j-core.*jar" ${abs_path})
                        # skip files without log4j
                        if [[ -z "$log4j_match" ]]; then
                                continue
                        else
                                found_log4j=true
                                log4j_jar_name=${log4j_match%.*}
                                log4j_version=${log4j_jar_name##*-*-}
                        fi
                fi

                # skip files we already found
                if [[ ${matched_files[@]} =~ $abs_path ]]; then
                        continue
                else
                        matched_files+=($abs_path)
                fi

                # look for vulnerable JndiLooup class inside the jar
                # thanks @CyberRaiju for the inspiration https://twitter.com/CyberRaiju/status/1469505677580124160
                if grep -q -l -r -m 1 JndiLookup.class $abs_path; then
                        has_jndilookupclass=true
                else
                        has_jndilookupclass=false
                fi

                scan_output $pid $log4j_version $has_jndilookupclass $link_target
        done
}
main
