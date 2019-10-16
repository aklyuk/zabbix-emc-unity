# zabbix-emc-unity
Python script for monitoring EMC Unity storages



In template "Template EMC Unity REST-API" in section "Macros" need set these macros:
- {$API_USER}
- {$API_PASSWORD}
- {$API_PORT}
- {$SUBSCRIBED_PERCENT}
- {$USED_PERCENT}

In agent configuration file, **/etc/zabbix/zabbix_agentd.conf** must be set parameter **ServerActive=xxx.xxx.xxx.xxx**



- In Linux-console need run this command to make discovery. Script must return value 0 in case of success.
```bash
./unity_get_state.py --api_ip=xxx.xxx.xxx.xxx --api_port=443 --api_user=user --api_password='password' --storage_name="storage-name_in_zabbix" --discovery
```
- On zabbix proxy or on zabbix servers need run **zabbix_proxy -R config_cache_reload** (zabbix_server -R config_cache_reload)

- In Linux-console need run this command to get value of metrics. Scripts must return value 0 in case of success.
```bash
./unity_get_stateNEW.py --api_ip=xxx.xxx.xxx.xxx --api_port=443 --api_user=user --api_password='password' --storage_name="storage-name_in_zabbix" --status
```
If you have executed this script from console from user root or from another user, please check access permission on file **/tmp/unity_state.log**. It must be allow read, write to user zabbix.
