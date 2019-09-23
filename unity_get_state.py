#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import time
import argparse
import sys
import json
import subprocess
import logging
import logging.handlers
import requests
import urllib3
urllib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Создаем лог-объект
LOG_FILENAME = "/tmp/unity_state.log"
unity_logger = logging.getLogger("unity_logger")
unity_logger.setLevel(logging.INFO)

# Устанавливаем хэндлер
unity_handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=1024*1024*1024, backupCount=5)
unity_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Устанавливаем форматтер для хэндлера
unity_handler.setFormatter(unity_formatter)

# Добавляем хэндлер к лог-объекту
unity_logger.addHandler(unity_handler)


def api_connect(api_user, api_password, api_ip, api_port):
	api_login_url = "https://{0}:{1}/api/types/loginSessionInfo".format(api_ip, api_port)
	session_unity = requests.Session()
	session_unity.auth = (api_user, api_password)
	session_unity.headers = {'X-EMC-REST-CLIENT': 'true', 'Content-type': 'application/json', 'Accept': 'application/json'}

	try:
		login = session_unity.get(api_login_url, verify=False)
	except Exception as oops:
		unity_logger.error("Connection Error Occurs: {0}".format(oops))
		sys.exit("50")

	if login.status_code <> 200:
		unity_logger.error("Connection Return Code = {0}".format(login.status_code))
		sys.exit("60")
	elif login.text.find("isPasswordChangeRequired") >= 0: # Если в выводе логина найдена строка isPasswordChangeRequired, логин произошел успешно
		unity_logger.info("Connection established")
		return session_unity
	else:
		unity_logger.error("Login Something went wrong")
		sys.exit("70")



def api_logout(api_ip, session_unity):
	api_logout_url = "https://{0}/api/types/loginSessionInfo/action/logout".format(api_ip)
	session_unity.headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

	try:
		logout = session_unity.post(api_logout_url, verify=False)
	except Exception as oops:
		unity_logger.error("Logout Error Occurs: {0}".format(oops))
		sys.exit("150")

	if logout.status_code <> 200:
		unity_logger.error("Logout status = {0}".format(logout.status_code))
		sys.exit("160")
	elif logout.text.find("Logout successful") >= 0:
		unity_logger.info("Logout successful")
	else:
		unity_logger.error("Logout Something went wrong")
		sys.exit("170")


def convert_to_zabbix_json(data):
        output = json.dumps({"data": data}, indent = None, separators = (',',': '))
        return output



def send_data_to_zabbix(zabbix_data, storage_name):
        sender_command = "/usr/bin/zabbix_sender"
        config_path = "/etc/zabbix/zabbix_agentd.conf"
        time_of_create_file = int(time.time())
        temp_file = "/tmp/{0}_{1}.tmp".format(storage_name, time_of_create_file)

        with open(temp_file, "w") as f:
                f.write("")
                f.write("\n".join(zabbix_data))

        send_code = subprocess.call([sender_command, "-vv", "-c", config_path, "-s", storage_name, "-T", "-i", temp_file], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        os.remove(temp_file)
        return send_code



def discovering_resources(api_user, api_password, api_ip, api_port, storage_name, list_resources):
	api_session = api_connect(api_user, api_password, api_ip, api_port)

	something = []
	try:
		for resource in list_resources:
			resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name".format(api_ip, api_port, resource)
			resource_info = api_session.get(resource_url, verify=False)
			resource_info = json.loads(resource_info.content.decode('utf8'))

			discovered_resource = []
			for one_object in resource_info['entries']:
				if ['lun', 'pool'].count(resource) == 1:
					one_object_list = {}
					one_object_list["{#ID}"] = one_object['content']['id']
					one_object_list["{#NAME}"] = one_object['content']['name'].replace(' ', '_')
					discovered_resource.append(one_object_list)
				else:
					one_object_list = {}
	                                one_object_list["{#ID}"] = one_object['content']['id']
					discovered_resource.append(one_object_list)
			converted_resource = convert_to_zabbix_json(discovered_resource)
			timestampnow = int(time.time())
			something.append("%s %s %s %s" % (storage_name, resource, timestampnow, converted_resource))
	except Exception as pizdec:
		unity_logger.error("Error occurs in discovering")
		sys.exit("1000")

	api_session_logout = api_logout(api_ip, api_session)
	return send_data_to_zabbix(something, storage_name)



def get_status_resources(api_user, api_password, api_ip, api_port, storage_name, list_resources):
	api_session = api_connect(api_user, api_password, api_ip, api_port)

	state_resources = [] # В этот список будут складываться состояние каждого ресурса (объекта) в формате zabbix
	try:
		for resource in list_resources:
			# Генерируем разные URI для разных ресурсов
			if ['pool'].count(resource) == 1:
				resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health,sizeTotal,sizeUsed,sizeSubscribed".format(api_ip, api_port, resource)
			elif ['lun'].count(resource) == 1:
				resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health".format(api_ip, api_port, resource)
			else:
				resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health,needsReplacement".format(api_ip, api_port, resource)

			# Получаем информацию об одном ресурсе
			resource_info = api_session.get(resource_url, verify=False)
			resource_info = json.loads(resource_info.content.decode('utf8'))
			timestampnow = int(time.time())

			if ['ethernetPort', 'fcPort', 'sasPort'].count(resource) == 1:
				for one_object in resource_info['entries']:
					key_health = "health.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
					key_status = "link.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
					state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))

					# Получаем состояние линков интерфейсов из дескрипшена
					descriptionIds = str(one_object['content']['health']['descriptionIds'][0]) # Конвертируем дескрипшн в строку
					if descriptionIds.find("LINK_UP") >= 0: # Из дескрипшена узнаем, линк в апе или в дауне
						link_status = 10
					elif descriptionIds.find("LINK_DOWN") >=0:
						link_status = 11

					state_resources.append("%s %s %s %s" % (storage_name, key_status, timestampnow, link_status))

			elif ['lun'].count(resource) == 1:
				for one_object in resource_info['entries']:
					key_health = "health.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_')) # Используем имя луна вместо ID в ключе
					state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))
			elif ['pool'].count(resource) == 1:
				for one_object in resource_info['entries']:
					key_health = "health.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_')) # Используем имя луна вместо ID в ключе
					key_sizeUsedBytes = "sizeUsedBytes.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))
					key_sizeTotalBytes = "sizeTotalBytes.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))
					key_sizeSubscribedBytes = "sizeSubscribedBytes.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))

	                                state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))
					state_resources.append("%s %s %s %s" % (storage_name, key_sizeUsedBytes, timestampnow, one_object['content']['sizeUsed']))
					state_resources.append("%s %s %s %s" % (storage_name, key_sizeTotalBytes, timestampnow, one_object['content']['sizeTotal']))
					state_resources.append("%s %s %s %s" % (storage_name, key_sizeSubscribedBytes, timestampnow, one_object['content']['sizeSubscribed']))
			else:
				for one_object in resource_info['entries']:
					# Получаем состояние ресурсов из дескрипшена
					descriptionIds = str(one_object['content']['health']['descriptionIds'][0]) # Конвертируем дескрипшн в строку
					if descriptionIds.find("ALRT_COMPONENT_OK") >= 0:
						running_status = 8
					elif descriptionIds.find("ALRT_DISK_SLOT_EMPTY") >= 0:
						running_status = 6
					else:
						running_status = 5

					key_health = "health.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
					key_status = "running.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
					state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))
					state_resources.append("%s %s %s %s" % (storage_name, key_status, timestampnow, running_status))
	except Exception as pizdec:
		unity_logger.error("Error occured in get state")
		sys.exit("1000")

	api_session_logout = api_logout(api_ip, api_session)
        return send_data_to_zabbix(state_resources, storage_name)



def main():
	# Парсим аргументы		
        unity_parser = argparse.ArgumentParser()
        unity_parser.add_argument('--api_ip', action="store", help="Where to connect", required=True)
        unity_parser.add_argument('--api_port', action="store", required=True)
        unity_parser.add_argument('--api_user', action="store", required=True)
        unity_parser.add_argument('--api_password', action="store", required=True)
        unity_parser.add_argument('--storage_name', action="store", required=True)

        group = unity_parser.add_mutually_exclusive_group(required=True)
        group.add_argument('--discovery', action ='store_true')
        group.add_argument('--status', action='store_true')
        arguments = unity_parser.parse_args()


	list_resources = ['battery', 'ssd', 'ethernetPort', 'fcPort', 'sasPort', 'fan', 'powerSupply', 'storageProcessor', 'lun', 'pool', 'dae', 'dpe', 'ioModule', 'lcc', 'memoryModule', 'ssc', 'uncommittedPort', 'disk']
        if arguments.discovery:
                result_discovery = discovering_resources(arguments.api_user, arguments.api_password, arguments.api_ip, arguments.api_port, arguments.storage_name, list_resources)
                print result_discovery
        elif arguments.status:
                result_status = get_status_resources(arguments.api_user, arguments.api_password, arguments.api_ip, arguments.api_port, arguments.storage_name, list_resources)
                print result_status


if __name__ == "__main__":
        main()

