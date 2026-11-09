# ---------------------------------------------------------|
# Spam enricher component that calls on external enricher  |
# sources to get and cache information on indicators.      |
# ---------------------------------------------------------|

import argparse
import json
import mysql.connector
import sys
import datetime
import os
import git
import re
import time
import shutil
import logging
import ipaddress
import validators
import importlib
from systemd import journal
from enricher_config import load_or_create_config,convert_csv_to_list

MAX_BLOCK_SIZE = 500

# ----------------------------------------------------------|
# Database functions.                                       |
# ----------------------------------------------------------|

# Executes a mutation query (INSERT, UPDATE, etc) to the MySQL database server.
def execute_mutation_sql_query(db, q, params):
	cursorObject = db.cursor()
	cursorObject.execute(q, params)
	db.commit()
	return cursorObject.lastrowid

# Executes a SELECT query that returns results.
def execute_select_sql_query(db, q):
	cursorObject = db.cursor(buffered=True)
	cursorObject.execute(q)
	db.commit()
	return cursorObject.fetchall()

# -----------------------------------------------------------

# Prints error message to STDERR.
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# Obtains version number from the number of commits in the local Git repo.
def obtain_version_number():
	try:
		repo = git.Repo(".")
		version = int(repo.git.rev_list('--count', 'HEAD'))
	except git.exc.InvalidGitRepositoryError:
		version = 0
	return version

# Attempt connection to the MySQL database server.
def connect_mysql_database(addr, username, password, dbname):
	try:
		database = mysql.connector.connect(host=addr, user=username, passwd=password, database=dbname, connect_timeout=10)
	except mysql.connector.Error:
		return None

	# Check and print connection info.
	return database if database.is_connected() else None

# Checks whether string is valid hostname, taken from https://stackoverflow.com/questions/2532053/validate-a-hostname-string.
def is_valid_hostname(hostname):
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False

    labels = hostname.split(".")

    # the TLD must be not all-numeric
    if re.match(r"[0-9]+$", labels[-1]):
        return False

    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)

# Gets the type of indicator based on given input.
def get_indicator_type(ioc):
	# Check whether the indicator is a valid IP-address.
	try:
		# Parse the IoC as IP address to see if it is valid. It must however also be solely IPv4. We don't support IPv6 for now.
		ip = ipaddress.ip_address(ioc)
		return "ip" if ip.version == 4 else None
	except ValueError:
		pass

	# Still here, so the next check is for an different hash types.
	if re.match("^[0-9a-fA-F]{32}$", ioc):
		return "md5"
	elif re.match("^[0-9a-fA-F]{40}$", ioc):
		return "sha1"
	elif re.match("^[0-9a-fA-F]{64}$", ioc):
		return "sha256"
	elif is_valid_hostname(ioc):
		return "hostname"
	elif validators.url(ioc):
		return "url"

	# Still here so this is an unsupported indicator type.
	else:
		return None

# Obtains the number of entries currently in the inactive queue. Needed to keep the backlog under control.
def get_number_of_inactive_entries():
	count_result = execute_select_sql_query(database, "SELECT COUNT(*) FROM inactive_enricher_queue")
	count = count_result[0][0]
	return count

# Tests whether the quotas for enrichers should be reset, and performs the operations if so.
# The criterium is if the current time is past midnight UTC.
def check_and_reset_quotas(enrichers):
	for enricher,params in enrichers.items():
		# Get the enricher state currently in the database.
		result = execute_select_sql_query(database, "SELECT id,name,quota,last_quota_reset FROM enricher_state WHERE name = '%s'" % enricher)
		if len(result) == 0:
			# Enricher state does not exist yet, so create it.
			query = "INSERT INTO enricher_state (name,quota,last_request) VALUES (%s,%s,NOW())"
			execute_mutation_sql_query(database, query, (enricher, params[2]))
		else:
			# Get yesterday's date.
			yesterday = datetime.datetime.now().date() - datetime.timedelta(days = 1)

			# If the quota was last reset yesterday or NULL, reset the quota for this enricher.
			has_been_reset = False
			state_row = result[0]
			last_quota_reset = state_row[3]
			if last_quota_reset == None or yesterday >= last_quota_reset.date():
				# Reset the quota for this enricher and insert the current timestamp in the enricher state to make sure it will be reset again tomorrow.
				query = "UPDATE enricher_state SET quota = %s, last_quota_reset = %s WHERE id = %s"
				execute_mutation_sql_query(database, query, (params[2], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), state_row[0]))
				has_been_reset = True

				# Log message about the resetting of the quota.
				logger.info("Reset quota for enricher: %s as we are past midnight. New quota: %i" % (enricher, params[2]))

			# If the quota is negative, reset it as well, but to zero. Maybe we have a little bug.
			elif state_row[2] < 0:
				# Reset the quota for this enricher.
				query = "UPDATE enricher_state SET quota = 0 WHERE id = %s"
				execute_mutation_sql_query(database, query, (state_row[0],))
				has_been_reset = True
				logger.info("Set quota for enricher: %s to zero as the current quota was negative. Might have a bug here!" % enricher)

			if has_been_reset:
				# The quota was reset. Now get the first 'quota' entries from the inactive queue and move them back to the end of the primary queue.
				inactive_entries_result = execute_select_sql_query(database, "SELECT id,indicator,mail_id FROM inactive_enricher_queue WHERE enrichers = '%s' ORDER BY id LIMIT %i" % (enricher, int(params[2])))
				for queue_entry in inactive_entries_result:
					# Get queue entry parameters.
					id = queue_entry[0]
					indicator = queue_entry[1]
					mail_id = queue_entry[2]

					# Re-insert into primary queue.
					query = "INSERT INTO enricher_queue (added,indicator,checksum,mail_id,enrichers) VALUES (NOW(),%s,CRC32(%s),%s,%s)"
					execute_mutation_sql_query(database, query, (indicator, indicator, mail_id, enricher))

					# Delete from inactive entries queue.
					execute_mutation_sql_query(database, "DELETE FROM inactive_enricher_queue WHERE id = %s", (id,))

				# Log some information to the journal.
				logger.info("Moved %i inactive entries for enricher %s back to primary queue." % (len(inactive_entries_result), enricher))

# ----------------------------------------------------------|
# Main spam enricher code                                   |
# ----------------------------------------------------------|

# Do initial tasks for starting the enricher. We initialize a logger that targets systemd.
logger = logging.getLogger("spam-enricher")
journald_handler = journal.JournaldLogHandler()
journald_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
logger.setLevel(logging.INFO)
logger.addHandler(journald_handler)

# Parse command line arguments.
parser = argparse.ArgumentParser(description='Spam enricher')
parser.add_argument('indicator', nargs='?')
parser.add_argument('-l', action='store_true', dest='list_enrichers', help='List enabled enricher modules')
args = parser.parse_args()

# Test whether the enricher is run in debug mode with a specific indicator.
debug = False
if args.indicator or args.list_enrichers:
	debug = True
	logger.setLevel(logging.DEBUG)
	logger.addHandler(logging.StreamHandler(sys.stdout))

# Load configuration from the enricher.
try:
	config_object = load_or_create_config()
	enricher_config = config_object["ENRICHER"]
	modules_config = config_object["MODULES"]
except KeyError:
	eprint("Could not open config file, one or more required key/value pairs are missing! Review the config file and try again.")
	exit(1)

# Check whether the TTL days parameter is configured.
if "ttl_days" not in enricher_config:
	logger.error("The 'ttl_days' parameter was not found in the configuration! Please create this entry with the number of days as an integer value.")
	exit(1)

# Check whether the TTL days parameter is an integer value.
if not enricher_config["ttl_days"].isdigit():
	logger.error("The 'ttl_days' parameter must be a the number of days as integer value! Current value: %s" % enricher_config["ttl_days"])
	exit(1)

# Get upper bound of inactive entries to keep it under control.
if "max_inactive_queue" not in enricher_config:
	logger.error("The 'max_inactive_queue' parameter was not found in the configuration! Please create this entry with the number of entries as integer value.")
	exit(1)

# Check whether the max inactive queue parameter is an integer value.
if not enricher_config["max_inactive_queue"].isdigit():
	logger.error("The 'max_inactive_queue' parameter must be a the number of days as integer value! Current value: %s" % enricher_config["max_inactive_queue"])
	exit(1)

max_inactive_queue = int(enricher_config["max_inactive_queue"])

# Obtain the version number of the enricher from the automatically generated version file.
spam_enricher_version = obtain_version_number()
logger.info("Starting spam enricher version %i." % spam_enricher_version)

# Parse supported types of indicators for configured enricher modules.
enrichers = {}
for enricher in convert_csv_to_list(modules_config["names"]):
	# Start with the configured enabled variable.
	specific_config = config_object[enricher]
	enabled = True if specific_config["enabled"] == "yes" else False

	# Attempt to import the procedures for this module.
	# If it succeeds, we will allow the module to be enabled.
	proc = None
	if enabled:
		try:
			# Attempt to import the module source for this enricher.
			mod = importlib.import_module(enricher)

			# Check whether the enrich method is part of the module we just imported.
			if not hasattr(mod, "execute_enrichment"):
				logger.error("Module: %s was loaded successfully but enrichment method could not be located!" % enricher)
				enabled	= False
			else:
				# Get method handle to call upon enrichment.
				proc = getattr(mod, "execute_enrichment")
		except ModuleNotFoundError:
			logger.error("Module for enricher: %s could not be found! Enricher is disabled." % enricher)
			enabled = False

		# Store the parameters for this enricher, but only if it is set to enabled.
		supported_types = convert_csv_to_list(specific_config["supported_types"])
		quota = int(specific_config["quota"]) if "quota" in specific_config else "not configured"
		delay = int(specific_config["delay"]) if "delay" in specific_config else "not configured"
		enrichers[enricher] = (enabled, supported_types, quota, delay, proc)

# Test whether we requested a list of enrichers.
if args.list_enrichers:
	logger.info("Listing configured listeners...")
	for name,params in enrichers.items():
		logger.info("Listener: %s, enabled: %s, supported_types: %s, quota: %s, delay: %s" % (name, params[0], params[1], params[2], params[3]))

	# Finished listing, exit now.
	exit(0)

# Start some measurements.
start_time = datetime.datetime.now()

# Check whether debug mode was requested.
if debug:
	indicator = args.indicator
	type = get_indicator_type(indicator)
	if not type:
		logger.error("Type of specified indicator: %s could not be determined! Unsupported indicator type." % indicator)
		exit(1)

	# Finalize by exiting. This way we don't need the extra indent for everything below. :)
	exit(0)

# Open connection to the database.
logger.info("Connecting to MySQL database server at: %s" % enricher_config["database_addr"])
database = connect_mysql_database(enricher_config["database_addr"], enricher_config["database_user"], enricher_config["database_passwd"], enricher_config["database_name"])
if database is not None:
	logger.info("Successfully connected to MySQL database at %s!" % enricher_config["database_addr"])
else:
	logger.error("Failed to connect to MySQL server at: %s!" % enricher_config["database_addr"])
	exit(1)

# Check the enricher state table in the database. Any enrichers not there yet must be created and states reset if necessary.
check_and_reset_quotas(enrichers)

# Start main loop. This loop polls the database for new entries in the queue table for enrichment requests.
ttl_days = int(enricher_config["ttl_days"])
while True:
	# Allow breaking of the loop using a keyboard interrupt.
	try:
		# Query the enricher_queue table to check for new entries. We pick the ones with the lowest ID to process first.
		# To avoid doing too many database queries, we select up to 5 new queue items in one query.
		queue_entries_result = execute_select_sql_query(database, "SELECT id,indicator,enrichers,mail_id FROM enricher_queue ORDER BY id LIMIT %i" % int(enricher_config["queue_block_size"]))
		for queue_entry in queue_entries_result:
			id = queue_entry[0]
			indicator = queue_entry[1]
			mail_id = queue_entry[3]

			# Construct a list of selected enrichers to call for this scheduled item.
			if queue_entry[2] == "*":
				selected_enrichers = [ enr for enr in enrichers.keys() ]
			else:
				selected_enrichers = [ enr for enr in queue_entry[2].split(',') ]

			# Get indicator type.
			type = get_indicator_type(indicator)
			if type:
				# Execute all supported enrichers for this indicator.
				for enricher in selected_enrichers:
					# Check whether the enricher specified in the database is actually loaded. If not, it will trigger an exception and we just want to drop the entry.
					# Disabled enrichers would cause this, for example.
					if enricher not in enrichers:
						continue

					# Check whether this enricher supports the type of indicator we have.
					params = enrichers[enricher]
					if type in params[1]:
						# Get the current state for this enricher.
						state_result = execute_select_sql_query(database, "SELECT id,quota,last_request FROM enricher_state WHERE name = '%s'" % enricher)
						if len(state_result) == 0:
							logger.error("Unexpected error: state for enricher: %s is missing from the database! Disabling the enricher." % enricher)
							enrichers[enricher] = (False, params[1], params[2], params[3], params[4])
							continue

						# Obtain quota and last request timestamp.
						state = state_result[0]
						state_id = state[0]
						current_quota = state[1]
						last_request_ts = state[2]

						# Compute threshold timestamp using delay.
						threshold_timestamp = datetime.datetime.now() + datetime.timedelta(seconds=-params[3])

						# Check whether the quota for today has been consumed. If so, this entry would be placed at the bottom of the queue
						# over an over for the entire day, which is very inefficient. Therefore, we move it to the inactive queue until the quota is available again.
						if current_quota == 0:
							# Insert this enrichment request back at the end of the inactive entries queue. That way we will not hog the CPU while inactive.
							query = "INSERT INTO inactive_enricher_queue (added,indicator,checksum,mail_id,enrichers) VALUES (NOW(),%s,CRC32(%s),%s,%s)"
							execute_mutation_sql_query(database, query, (indicator, indicator, mail_id, enricher))
						# If the quota has not been consumed but the request needs to wait until the next request can be done, we will place it at the bottom of the queue.
						elif last_request_ts > threshold_timestamp:
							query = "INSERT INTO enricher_queue (added,indicator,checksum,mail_id,enrichers) VALUES (NOW(),%s,CRC32(%s),%s,%s)"
							execute_mutation_sql_query(database, query, (indicator, indicator, mail_id, enricher))
						else:
							# Execute enrichment procedure for this indicator. For context we pass the module-specific config object.
							result = params[4](database, mail_id, ttl_days, config_object[enricher], indicator)

							# If the enrichment procedure returns True in a boolean value, it means the cached result was still valid.
							status_code = 0
							if result:
								if isinstance(result, bool):
									logger.info("Cached enrichment result for %s: %s with %s still valid, no API calls performed." % (type, indicator, enricher))
								else:
									# Check whether the result is True or False, meaning the database insertion failed.
									status_code = result[1]
									if result[0]:
										logger.info("Performed successful enrichment for %s: %s with %s (status = %i)." % (type, indicator, enricher, status_code))
									else:
										logger.info("Enrichment failed for %s: %s with %s (status = %i)! Failed to insert entry into database." % (type, indicator, enricher, status_code))

									# Update the enricher state for this enricher.
									this_request_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
									query = "UPDATE enricher_state SET quota = %s, last_request = %s, status_code = %s WHERE id = %s"
									execute_mutation_sql_query(database, query, (current_quota - 1, this_request_str, status_code, state_id))
							else:
								# An error occurred before or during the API call.
								logger.error("External enrichment for %s: %s using %s failed!" % (type, indicator, enricher))
			else:
				logger.error("Type of specified indicator: %s could not be determined! Unsupported indicator type (skipping)." % indicator)

			# Delete the row from the enricher_queue table and move on to the next.
			execute_mutation_sql_query(database, "DELETE FROM enricher_queue WHERE id = %s", (id,))

		# If one or more enrichers have available quota, check the inactive entries queue to see if anything can be shifted back to the active queue for processing.
		for enricher,params in enrichers.items():
			# Get the current state for this enricher.
			state_result = execute_select_sql_query(database, "SELECT id,quota,last_request FROM enricher_state WHERE name = '%s'" % enricher)
			if len(state_result) == 0:
				logger.error("Unexpected error: state for enricher: %s is missing from the database! Disabling the enricher." % enricher)
				enrichers[enricher] = (False, params[1], params[2], params[3], params[4])
				continue

			# Obtain current remaining quota from state.
			state = state_result[0]
			current_quota = state[1]

			# Is there are no queries left to execute today, we will skip this one.
			if current_quota == 0:
				continue

			# Check available quota against what is already inside the active queue for this enricher.
			# If this is less than the still available quota, we can still move some over from the inactive queue but the number needs to be adjusted.
			queue_entries_result = execute_select_sql_query(database, "SELECT COUNT(*) FROM enricher_queue WHERE enrichers ='%s'" % enricher)
			if len(queue_entries_result) != 1:
				logger.error("Executed COUNT(*) query but did not receive a single entry! This should not happen.")
				continue

			number_of_entries = queue_entries_result[0][0]
			if number_of_entries < current_quota:
				current_quota -= number_of_entries
			else:
				# Don't move anything more back from the inactive queue for now. There is more in the active queue than the enricher has quota left.
				continue

			# The quota for some sources might be very, very large and therefore, it could hog the enricher entirely if it tried to move all that much.
			# We make sure to only move a certain maximum block size at a given time.
			if current_quota > MAX_BLOCK_SIZE:
				current_quota = MAX_BLOCK_SIZE

			# Still here, so there is quota remaining. Query the inactive queue for entries specifying this enricher.
			inactive_entries_result = execute_select_sql_query(database, "SELECT id,indicator,mail_id FROM inactive_enricher_queue WHERE enrichers = '%s' ORDER BY id LIMIT %i" % (enricher, current_quota))
			for queue_entry in inactive_entries_result:
				# Get queue entry parameters.
				id = queue_entry[0]
				indicator = queue_entry[1]
				mail_id = queue_entry[2]

				# Re-insert into primary queue.
				query = "INSERT INTO enricher_queue (added,indicator,checksum,mail_id,enrichers) VALUES (NOW(),%s,CRC32(%s),%s,%s)"
				execute_mutation_sql_query(database, query, (indicator, indicator, mail_id, enricher))

				# Delete from inactive entries queue.
				execute_mutation_sql_query(database, "DELETE FROM inactive_enricher_queue WHERE id = %s", (id,))

			# Has anything been moved?
			if len(inactive_entries_result) > 0:
				logger.info("Some quota remaining for enricher: %s so %i entries were taken from inactive queue." % (enricher, current_quota))

		# Perform a check for whether the enricher states need to be reset. Once past midnight UTC this must be done.
		check_and_reset_quotas(enrichers)

		# Check whether the inactive queue overflows its boundaries and needs to be truncated.
		num_inactive = get_number_of_inactive_entries()
		if num_inactive > max_inactive_queue:
			num_to_remove = num_inactive - max_inactive_queue
			ids_result = execute_select_sql_query(database, "SELECT id FROM inactive_enricher_queue ORDER BY id LIMIT %i" % num_to_remove)
			if len(ids_result) > 0:
				max_id = ids_result[-1][0]
				execute_mutation_sql_query(database, "DELETE FROM inactive_enricher_queue WHERE id <= %s", (max_id,))
				logger.info("Deleted %i entries from the inactive queue to stay within configured bounds." % num_to_remove)

		# Sleep a little bit to avoid hogging the CPU.
		time.sleep(1/2)

	# Catch keyboard interrupt exception to break out of the loop.
	except KeyboardInterrupt:
		logger.info("Received SIGINT, stopping")
		break

# Exit and print statistics.
end_time = datetime.datetime.now()
logger.info("Total runtime: %f days" % ((end_time - start_time).total_seconds() / 86400))
