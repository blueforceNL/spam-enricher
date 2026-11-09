# ----------------------------------------------------------|
# Configuration file logic for spam enricher                |
# ----------------------------------------------------------|

from configparser import ConfigParser
import os

CONFIG_PATH = "/etc/spam-enricher"
DEFAULT_DB_ADDR = "localhost"
DEFAULT_DB_NAME = "spam_analyzer"
DEFAULT_DB_USER = "spam-analyzer"
DEFAULT_DB_PWD = "ChangeMe"
DEFAULT_MODULES = "vpnapi,ipintel,ip2proxy"
DEFAULT_TTL_DAYS = "60"
DEFAULT_QUEUE_BLOCK_SIZE = "10"
DEFAULT_MAX_INACTIVE_QUEUE = "65536"

# Reads configuration file from the config directory.
def load_configuration_file(path):
	config_object = ConfigParser()
	config_object.read(path)
	return config_object

# Creates a new default configuration.
def create_default_configuration(path):
	# Create default configuration.
	config_object = ConfigParser()
	config_object["ENRICHER"] = {
		"database_addr" : DEFAULT_DB_ADDR,
		"database_name" : DEFAULT_DB_NAME,
		"database_user" : DEFAULT_DB_USER,
		"database_passwd" : DEFAULT_DB_PWD,
		"ttl_days" : DEFAULT_TTL_DAYS,
		"queue_block_size" : DEFAULT_QUEUE_BLOCK_SIZE,
		"max_inactive_queue" : DEFAULT_MAX_INACTIVE_QUEUE
	}

	config_object["MODULES"] = {
		"names" : DEFAULT_ENRICHER_LIST
	}

	config_object["vpnapi"] = {
		"enabled" : "yes",
		"supported_types" : "ip",
		"api_key" : "ChangeMe",
		"quota" : "10000",
		"delay" : "3",
	}

	config_object["ipintel"] = {
		"enabled" : "no",
		"supported_types" : "ip",
		"contact" : "ChangeMe",
		"quota" : "0",
		"delay" : "60",
	}

	config_object["ip2proxy"] = {
		"enabled" : "yes",
		"supported_types" : "ip",
		"quota" : "2147483647", # Symbolic cap
		"delay" : "1",
		"db_name" : "ip2location",
		"db_user" : "enricher",
		"db_pass" : "ChangeMe"
	}

	# Write default configuration to the config directory.
	with open(path, 'w') as config_file:
		config_object.write(config_file)

	return config_object

# Converts comma-separated list notation to actual list.
def convert_csv_to_list(line):
	return [ field for field in line.split(',') ]

# Gets the configuration, newly created default or loaded from disk.
def load_or_create_config():
	# Create subdirectory for the configuration if it doesn't exist.
	os.makedirs(CONFIG_PATH, exist_ok=True)

	# Load configuration file from /etc/spam-analyzer/analyzer.comf. If it doesn't exist, create a new default one.
	conf_path = os.path.join(CONFIG_PATH, "enricher.conf")
	if os.path.exists(conf_path):
		config_object = load_configuration_file(conf_path)
	else:
		# Create default configuration.
		config_object = create_default_configuration(conf_path)

	# Obtain enricher modules config object.
	modules_config = config_object["MODULES"]

	# Test whether the configuration file contains configuration sections for all specified enrichers.
	enrichers = convert_csv_to_list(modules_config["names"])
	for name in enrichers:
		if name not in config_object:
			# Create default empty config object with status disabled.
			config_object[name] = { "enabled" : "no" }
			config_object[name]["supported_types"] = ""

	# Finally, return the config object to the caller.
	return config_object
