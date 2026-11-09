# ---------------------------------------------------------|
# Queue manipulation component, allows one to add and      |
# remove mail IDs from the spam enricher queue. Also       |
# gives functionality to query the queue.                  |
# ---------------------------------------------------------|

import argparse
import mysql.connector
import sys
import datetime
from enricher_config import load_or_create_config

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

# Attempt connection to the MySQL database server.
def connect_mysql_database():
	try:
		database = mysql.connector.connect(host=enricher_config["database_addr"], user=enricher_config["database_user"],
			passwd=enricher_config["database_passwd"], database=enricher_config["database_name"], connect_timeout=10)
	except mysql.connector.Error:
		return None

	# Check and print connection info.
	return database if database.is_connected() else None

# ----------------------------------------------------------|
# Main enricher queue controller code.                      |
# ----------------------------------------------------------|

# Parse command line arguments.
parser = argparse.ArgumentParser(description='Spam enricher queue controller')
operations_group = parser.add_mutually_exclusive_group(required=True)
operations_group.add_argument('-a', nargs='+', dest='add_indicators', help='Add one or more indicators to the queue')
operations_group.add_argument('-c', action='store_true', dest='clear', help='Purge all indicators currently scheduled (empty the queue)')
operations_group.add_argument('-d', action='store_true', dest='deduplicate', help='Removes duplicate entries from the queue (troubleshooting option, SLOW)')
operations_group.add_argument('-i', action='store_true', dest='get_inactive', help='Moves inactive entries back into the primary queue (troubleshooting option)')
operations_group.add_argument('-l', action='store_true', dest='list', help='List all indicators currently scheduled')
operations_group.add_argument('-q', action='store_true', dest='query', help='Query statistics on the queue')
operations_group.add_argument('-r', nargs='+', dest='remove_indicators', help='Remove one or more indicators from the queue')
parser.add_argument('-e', nargs='?', dest='enricher', help='Enricher selected to either add or delete entries with in the queue.')
parser.add_argument('-n', nargs='?', dest='limit', help='Limit number of items in query, such as restoring inactive entries.')
parser.add_argument('-v', action='store_true', dest='verbose', help='verbose mode, print additional information')
args = parser.parse_args()

# Check whether verbose mode was selected.
verbose = True if args.verbose else False

# Load configuration from the enricher.
try:
	config_object = load_or_create_config()
	enricher_config = config_object["ENRICHER"]
except KeyError:
	print("ERROR: Could not open config file, one or more required key/value pairs are missing! Review the config file and try again.")
	exit(1)

# Open connection to the database to retrieve and update information.
database = connect_mysql_database()
if database is None:
	print("ERROR: Failed to connect to MySQL server at: %s!" % enricher_config["database_addr"])
	exit(1)

# -----------------------------------------------------------

# Check whether the specified enricher (if specified) actually exists in the database.
if args.enricher:
	enricher_state_result = execute_select_sql_query(database, "SELECT id FROM enricher_state WHERE name = '%s'" % args.enricher)
	if len(enricher_state_result) == 0:
		print("ERROR: Enricher specified using -e: '%s' does not exist in the database! Exiting." % args.enricher)
		exit(1)

# Perform the chosen operation on the queue.
if args.add_indicators:
	# Obtain the indicators from the command line and check whether they are already in the queue or not.
	enricher = args.enricher if args.enricher else '*'
	indicators = args.add_indicators
	for indicator in indicators:
		query = "SELECT id FROM enricher_queue WHERE checksum = CRC32('%s')" % indicator
		if args.enricher:
			query += " AND enrichers LIKE '%%%s%%'" % args.enricher
		queue_entries_result = execute_select_sql_query(database, query)
		if len(queue_entries_result) > 0:
			if verbose:
				print("INFO: Indicator: %s already exists in the queue. Skipping." % indicator)
			continue
		else:
			# First check if the checksum/enricher combination already exists in the inactive enricher queue. Otherwise the probability is high
			# that the spam-enricher will move the new entry to the inactive queue in case of overused quota resulting in duplicates.
			query = query.replace("enricher_queue", "inactive_enricher_queue")
			queue_entries_result = execute_select_sql_query(database, query)
			if len(queue_entries_result) > 0:
				if verbose:
					print("INFO: Indicator: %s already exists in the inactive queue. Skipping." % indicator)
				continue

			# Indicator is not yet in the queue, so append it to the queue. We leave the mail ID at NULL indicating this entry was added manually.
			query = "INSERT INTO enricher_queue (added,indicator,checksum,enrichers) VALUES (%s,%s,CRC32(%s),%s)"
			queue_timestamp = datetime.datetime.now()
			qt_string = queue_timestamp.strftime("%Y-%m-%d %H:%M:%S")
			execute_mutation_sql_query(database, query, (qt_string,indicator,indicator,enricher))
			if verbose:
				print("INFO: Added indicator: %s to the queue." % indicator)
elif args.remove_indicators:
	indicators = args.remove_indicators
	for indicator in indicators:
		queue_entries_result = execute_select_sql_query(database, "SELECT id FROM enricher_queue WHERE indicator = '%s'" % indicator)
		if len(queue_entries_result) == 0:
			if verbose:
				print("INFO: Indicator: %s does not exist in the queue. Skipping." % indicator)
			continue
		else:
			# Indicator exists in the queue, so remove it from the queue.
			execute_mutation_sql_query(database, "DELETE FROM enricher_queue WHERE indicator = %s", (indicator,))
			if verbose:
				print("INFO: Removed all entries for indicator: %s from the queue." % indicator)
elif args.query:
	# Obtain the number of entries and unique indicators currently in the queue.
	queue_entries_result = execute_select_sql_query(database, "SELECT COUNT(*),COUNT(DISTINCT indicator) FROM enricher_queue")
	count_row = queue_entries_result[0]
	print("INFO: %i entries in the queue covering %i unique indicators." % (count_row[0], count_row[1]))

	# Get configured maximum for inactive queue.
	max_inactive_queue = int(enricher_config["max_inactive_queue"])

	# Obtain the number of currently inactive entries and unique indicators currently too.
	queue_entries_result = execute_select_sql_query(database, "SELECT COUNT(*),COUNT(DISTINCT indicator) FROM inactive_enricher_queue")
	count_row = queue_entries_result[0]
	print("INFO: %i entries currently inactive for %i unique indicators. (maximum number configured = %i)" % (count_row[0], count_row[1], max_inactive_queue))

	# Query enricher states too. We will print them.
	print("INFO: Enricher states currently in database.")
	state_entries_result = execute_select_sql_query(database, "SELECT name,quota,last_request,status_code,last_quota_reset FROM enricher_state")
	for row in state_entries_result:
		# Get configured parameters from the config.
		if row[0] in config_object:
			cfg = config_object[row[0]]

			# Print information on the current state including module configuration.
			if cfg["enabled"] == "no":
				print("INFO: %s (disabled) has %i remaining quota. Last request at: %s (status code = %i). Configured quota = %s, delay = %s, last quota reset = %s." % (row[0], row[1], row[2], row[3] if row[3] != None else 0, cfg["quota"], cfg["delay"], row[4]))
			else:
				print("INFO: %s has %i remaining quota. Last request at: %s (status code = %i). Configured quota = %s, delay = %s, last quota reset = %s." % (row[0], row[1], row[2], row[3] if row[3] != None else 0, cfg["quota"], cfg["delay"], row[4]))
		else:
			# Print information on the current state of the enricher in the database.
			print("INFO: %s (missing from config) has %i remaining quota. Last request at: %s (status code = %i)." % (row[0], row[1], row[2], row[3]))
elif args.list:
	# Retrieve a list of indicators currently in the queue.
	queue_entries_result = execute_select_sql_query(database, "SELECT id,added,indicator,mail_id,enrichers FROM enricher_queue")
	if len(queue_entries_result) == 0:
		print("INFO: Spam enricher queue is empty.")
	else:
		# Print a CSV-formatted list of indicators in the queue.
		print("id,added,indicator,mail_id,enrichers")
		for queue_entry in queue_entries_result:
			mail_id = queue_entry[3] if queue_entry[3] is not None else "NULL"
			print("%i,%s,%s,%s,%s" % (queue_entry[0], queue_entry[1], queue_entry[2], mail_id, queue_entry[4]))
elif args.clear:
	# Clear the queue entirely: remove all indicators scheduled.
	execute_mutation_sql_query(database, "DELETE FROM enricher_queue", ())
	if args.verbose:
		print("INFO: Cleared the enricher queue.")
elif args.deduplicate:
	# Execute a query to retrieve all duplicate entries.
	dupes_result = execute_select_sql_query(database, "SELECT MIN(id),checksum FROM enricher_queue GROUP BY checksum,enrichers HAVING COUNT(checksum) > 1")
	i = 0
	total = len(dupes_result)
	for dupes_entry in dupes_result:
		# Get duplicate values.
		min_id = dupes_entry[0]
		checksum = dupes_entry[1]

		# Execute a query to delete all other entries having the same checksum. This way we don't lock the table with a huge query and stay in control.
		execute_mutation_sql_query(database, "DELETE FROM enricher_queue WHERE checksum = %s AND id <> %s", (checksum, min_id))
		i += 1
		if args.verbose:
			print("INFO: (%i/%i) Deleted duplicates with checksum: %i from active queue" % (i, total, checksum))

	# Execute the same queries in the inactive queue.
	dupes_result = execute_select_sql_query(database, "SELECT MIN(id),checksum FROM inactive_enricher_queue GROUP BY checksum,enrichers HAVING COUNT(checksum) > 1")
	i = 0
	total = len(dupes_result)
	for dupes_entry in dupes_result:
		# Get duplicate values.
		min_id = dupes_entry[0]
		checksum = dupes_entry[1]

		# Execute a query to delete all other entries having the same checksum. This way we don't lock the table with a huge query and stay in control.
		execute_mutation_sql_query(database, "DELETE FROM inactive_enricher_queue WHERE checksum = %s AND id <> %s", (checksum, min_id))
		i += 1
		if args.verbose:
			print("INFO: (%i/%i) Deleted duplicates with checksum: %i from inactive queue" % (i, total, checksum))

elif args.get_inactive:
	# The limit argument must be set.
	if not args.limit:
		print("ERROR: You must specify the number of entries to restore using the -n switch!")
		exit(1)

	# We need the enricher too.
	if not args.enricher:
		print("ERROR: You must specify the enricher to filter using the -e switch!")
		exit(1)

	# Query inactive entries.
	inactive_entries_result = execute_select_sql_query(database, "SELECT id,indicator,mail_id FROM inactive_enricher_queue WHERE enrichers = '%s' ORDER BY id LIMIT %i" % (args.enricher, int(args.limit)))
	for queue_entry in inactive_entries_result:
		# Get queue entry parameters.
		id = queue_entry[0]
		indicator = queue_entry[1]
		mail_id = queue_entry[2]

		# Re-insert into primary queue.
		query = "INSERT INTO enricher_queue (added,indicator,checksum,mail_id,enrichers) VALUES (NOW(),%s,CRC32(%s),%s,%s)"
		execute_mutation_sql_query(database, query, (indicator, indicator, mail_id, args.enricher))

		# Delete from inactive entries queue.
		execute_mutation_sql_query(database, "DELETE FROM inactive_enricher_queue WHERE id = %s", (id,))
	if args.verbose:
		# Log some information to the console.
		print("INFO: Moved %i inactive entries for enricher %s back to primary queue." % (len(inactive_entries_result), args.enricher))
else:
	print("ERROR: No operation specified!")
	exit(1)
