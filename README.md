# zabbix-emc-unity
Python script for monitoring EMC Unity storages

**User on Unity** must be:
- Level - Read-only user
- Role - Administrator

In template "Template EMC Unity REST-API" in section "Macros" need set these macros - {$API_USER}, {$API_PASSWORD}, {$API_PORT}, {$SUBSCRIBED_PERCENT}, {$USED_PERCENT}

In Linux-console need run this command
./unity_get_state.py --api_ip=xxx.xxx.xxx.xxx --api_port=443 --api_user=user --api_password='password' --storage_name="storage-name_in_zabbix" --discovery
to make discovery. Script must return value 0 in case of success

In Linux-console need run this command
./unity_get_stateNEW.py --api_ip=xxx.xxx.xxx.xxx --api_port=443 --api_user=user --api_password='password' --storage_name="storage-name_in_zabbix" --status
to get value of metrics. Scripts must return value 0 in case of success
