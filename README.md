**FIND log4j VULNERABLE SOFTWARE USING WAZUH**

## 

## Intro

How to use Wazuh to find and report running software affected by log4j vulnerabilities.

The script included here is a modified version of the [script](https://email.intezer.com/e3t/Btc/DL+113/cFVL-04/VVs_8H33c_sWN25wfhbfCjCWW4dVnpw4C7WTzN2NZZ3L3lLBGV1-WJV7CgZq3W1dm3-F97kvzJMPm1s24zvY8W5l2dq43FNnyxW6BYqDv2sg8LrW8NYFSM37l51zW8xQqJW8k1qn4W6_c9QY8sWvJbW3SBjyh1MZMGrVdWz9m1gNlRSVVsJ708lM76lW32ZwmP3f4vBPW7CXPdz5lhLktVczYLv5r3khgW6pw_mH44Sr6fW6vYMfS2HWB50N2Q3xKQ1v_4PV8L1yT93CRNYW35n_gq7vPkfvW432Mq477YMW4MW7S3LM-1j-W1gSJ455NsQDlVN1t8K3D4NPHN7S8BgFWpqZtN68phrm9T3Cw34H81) developed by the security company [Intezer](https://www.intezer.com/). In this version of the script the output is formatted to JSON and appended to Wazuh’s active responses log file.


## Wazuh Capability:

Wodle Command configured to run periodic security scans in all required machines.

Wazuh remote commands execution must be enabled in the Wazuh agent.


## Workflow

1. Bash script to be run via wodle command will find .jar extension in running processes, including Docker images.
2. The process ID, log4j version, JNDI enabled condition and process command line will be collected.
3. The output is formatted to JSON and appended to the agent’s active responses log file.

Remote commands execution must be enabled in the agent (Docker host), file “local_internal_options.conf”:


```
# Wazuh Command Module - If it should accept remote commands from the manager
wazuh_command.remote_commands=1
```


Edit /var/ossec/etc/shared/**_your_linux_group_**/agent.conf and add the remote command:


```
<wodle name="command">
  <disabled>no</disabled>
  <tag>log4j-scan</tag>
  <command>/usr/bin/bash /var/ossec/wodles/command/log4j_scan.sh</command>
  <interval>24h</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```


Content of “log4j_scan.sh”:


```
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
```


Scan detection rules:


```
<!--
  -  log4j Scan Rules
-->
<group name="vulnerability-detector,log4j,">
    <rule id="96605" level="13">
        <decoded_as>json</decoded_as>
        <field name="scan_date">\.+</field>
        <field name="process_id">\.+</field>
        <field name="log4j_version">\.+</field>
        <description>log4j Alert - Vulnerable Packages - JNDI Lookup Class:  $(has_jndilookupclass)</description>
        <options>no_full_log</options>
    </rule>
</group>
```


Scan output example:


```
{
   "scan_date":"Fri 17 Dec 2021 08:31:12 PM UTC",
   "process_id":"77077",
   "log4j_version":"2.11.1",
   "has_jndilookupclass":"true",
   "jar_path":"/usr/share/elasticsearch/lib/log4j-core-2.11.1.jar",
   "process_cmd_line":"/usr/share/elasticsearch/jdk/bin/java -Xshare:auto -Des.networkaddress.cache.ttl=60 -Des.networkaddress.cache.negative.ttl=10 -XX:+AlwaysPreTouch -Xss1m -Djava.awt.headless=true -Dfile.encoding=UTF-8 -Djna.nosys=true -XX:-OmitStackTraceInFastThrow -XX:+ShowCodeDetailsInExceptionMessages -Dio.netty.noUnsafe=true -Dio.netty.noKeySetOptimization=true -Dio.netty.recycler.maxCapacityPerThread=0 -Dio.netty.allocator.numDirectArenas=0 -Dlog4j.shutdownHookEnabled=false -Dlog4j2.disable.jmx=true -Djava.locale.providers=SPI,COMPAT -Xms1g -Xmx1g -XX:+UseG1GC -XX:G1ReservePercent=25 -XX:InitiatingHeapOccupancyPercent=30 -Djava.io.tmpdir=/tmp/elasticsearch-17442157478472768084 -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/var/lib/elasticsearch -XX:ErrorFile=/var/log/elasticsearch/hs_err_pid%p.log -Xlog:gc*,gc+age=trace,safepoint:file=/var/log/elasticsearch/gc.log:utctime,pid,tags:filecount=32,filesize=64m -XX:MaxDirectMemorySize=536870912 -Des.path.home=/usr/share/elasticsearch -Des.path.conf=/etc/elasticsearch -Des.distribution.flavor=oss -Des.distribution.type=deb -Des.bundled_jdk=true -cp /usr/share/elasticsearch/lib/elasticsearch-7.10.2.jar /usr/share/elasticsearch/lib/elasticsearch-cli-7.10.2.jar /usr/share/elasticsearch/lib/elasticsearch-core-7.10.2.jar /usr/share/elasticsearch/lib/elasticsearch-geo-7.10.2.jar /usr/share/elasticsearch/lib/elasticsearch-launchers-7.10.2.jar /usr/share/elasticsearch/lib/elasticsearch-plugin-classloader-7.10.2.jar /usr/share/elasticsearch/lib/elasticsearch-secure-sm-7.10.2.jar /usr/share/elasticsearch/lib/elasticsearch-x-content-7.10.2.jar /usr/share/elasticsearch/lib/HdrHistogram-2.1.9.jar /usr/share/elasticsearch/lib/hppc-0.8.1.jar /usr/share/elasticsearch/lib/jackson-core-2.10.4.jar /usr/share/elasticsearch/lib/jackson-dataformat-cbor-2.10.4.jar /usr/share/elasticsearch/lib/jackson-dataformat-smile-2.10.4.jar /usr/share/elasticsearch/lib/jackson-dataformat-yaml-2.10.4.jar /usr/share/elasticsearch/lib/java-version-checker-7.10.2.jar /usr/share/elasticsearch/lib/jna-5.5.0.jar /usr/share/elasticsearch/lib/joda-time-2.10.4.jar /usr/share/elasticsearch/lib/jopt-simple-5.0.2.jar /usr/share/elasticsearch/lib/jts-core-1.15.0.jar /usr/share/elasticsearch/lib/log4j-api-2.11.1.jar /usr/share/elasticsearch/lib/log4j-core-2.11.1.jar /usr/share/elasticsearch/lib/lucene-analyzers-common-8.7.0.jar /usr/share/elasticsearch/lib/lucene-backward-codecs-8.7.0.jar /usr/share/elasticsearch/lib/lucene-core-8.7.0.jar /usr/share/elasticsearch/lib/lucene-grouping-8.7.0.jar /usr/share/elasticsearch/lib/lucene-highlighter-8.7.0.jar /usr/share/elasticsearch/lib/lucene-join-8.7.0.jar /usr/share/elasticsearch/lib/lucene-memory-8.7.0.jar /usr/share/elasticsearch/lib/lucene-misc-8.7.0.jar /usr/share/elasticsearch/lib/lucene-queries-8.7.0.jar /usr/share/elasticsearch/lib/lucene-queryparser-8.7.0.jar /usr/share/elasticsearch/lib/lucene-sandbox-8.7.0.jar /usr/share/elasticsearch/lib/lucene-spatial3d-8.7.0.jar /usr/share/elasticsearch/lib/lucene-spatial-extras-8.7.0.jar /usr/share/elasticsearch/lib/lucene-suggest-8.7.0.jar /usr/share/elasticsearch/lib/snakeyaml-1.26.jar /usr/share/elasticsearch/lib/spatial4j-0.7.jar /usr/share/elasticsearch/lib/t-digest-3.2.jar /usr/share/elasticsearch/lib/tools org.elasticsearch.bootstrap.Elasticsearch -p /var/run/elasticsearch/elasticsearch.pid --quiet "
}
```

