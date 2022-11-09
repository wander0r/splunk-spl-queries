
# Query Rapid7 asset data for installed software and their host with asset IP

eventtype="r7assetdata" earliest=@d | dedup dest_host ip | makemv delim=";" installed_software | mvexpand installed_software 
| eval normalized_installed_software=replace(installed_software,"(\d+\.){1,3}\d+","")
| stats dc(dest_host) dc(ip) values(installed_software) count by normalized_installed_software

# Query Cisco ASA logs to report on egress IP and port for further egress filtering
index=net sourcetype=cisco:asa eventtype="approvedPorts" dest_ip!=10.* earliest=-10d@d Cisco_ASA_action=allowed  rule=FROM_INSIDE
| dedup src_ip dest_ip
| eval clientip=dest_ip
| lookup dnslookup clientip AS dest_ip OUTPUT clienthost AS reverselookup
| stats  values(dest_ip)  values(src_port) values(src_ip) values(reverselookup) count by dest_port    
| sort-count

# Query for Splunk Heavy and Universal Forwarder Types
`sim_get_forwarder_tcpin` hostname=* version=*
                        | eval source_uri = hostname.":".sourcePort
                        | eval dest_uri = host.":".destPort
                        | eval connection = source_uri."->".dest_uri
                        | stats values(fwdType) as fwdType, values(sourceIp) as sourceIp, latest(version) as version,  values(os) as os, values(arch) as arch, dc(dest_uri) as dest_count, dc(connection) as connection_count, avg(tcp_KBps) as avg_tcp_kbps, avg(tcp_eps) as avg_tcp_eps by hostname, guid
                        | eval avg_tcp_kbps = round(avg_tcp_kbps, 2)
                        | eval avg_tcp_eps = round(avg_tcp_eps, 2)
                        | `sim_rename_forwarder_type(fwdType)`
                        | rename hostname as Instance, fwdType as "Forwarder Type", sourceIp as IP, version as "Splunk Version", os as OS, arch as Architecture, guid as GUID, dest_count as "Receiver Count", connection_count as "Connection Count", avg_tcp_kbps as "Average KB/s", avg_tcp_eps as "Average Events/s"

# Query DHCP Logs for Host Mac Address and IP Address assignments
index=windows sourcetype=DhcpSrvLog (description=*successful OR description=assign) eventtype!=voiceSubnet
| lookup us_asia_internal_subnets vlan AS dest_ip OUTPUTNEW site_name AS Location
| dedup dest_nt_host
| convert ctime(_time) as Date timeformat=%m/%d/%y
| eval Time=strftime(_time,"%H:%M:%S %p")
| join dest_ip [ search index=windows description=assign | fields dest_ip,dest_mac ]
| eval Authenticity=case(match(dest_nt_host,"\d\d\d\d\d\d-(D|L).(?i)ewbc.net") OR match(dest_nt_host, "(win7).*(a).(?i)ewbc.net") OR match(dest_nt_host, "(?i)\d\d\d(L|W).(?i)ewbc.net") OR match(dest_nt_host,"\d\d\d\d\d\d-(TC).(?i)ewbc.net"), "VALID",1=1,"NOT VALID")
| rename dest_ip as "IP Address" dest_mac as "MAC Address" dest_nt_host as "Hostname" signature as "Description"
| search Authenticity="VALID"
| table "Date" "Time" "IP Address" "MAC Address" "Hostname" Authenticity Location
| sort ctime(_time)