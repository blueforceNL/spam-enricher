import urllib.request
import datetime
import mysql.connector

# ----------------------------------------------------------|
# Database functions.                                       |
# ----------------------------------------------------------|

# Attempt connection to the MySQL database server.
def connect_mysql_database(addr, username, password, dbname):
	try:
		database = mysql.connector.connect(host=addr, user=username, passwd=password, database=dbname, connect_timeout=10)
	except mysql.connector.Error:
		return None

	# Check and print connection info.
	return database if database.is_connected() else None

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

# ----------------------------------------------------------|
# IP2Proxy specific functions.                              |
# ----------------------------------------------------------|

# Enriches an IP address with IP2Proxy information, querying the database locally.
def ip2proxy_enrich(database, ip):
	# Query the local database with the given IP address.
	result = execute_select_sql_query(database, "SELECT * FROM (SELECT ip_from FROM ip2location_px2 WHERE ip_from <= INET_ATON('%s') ORDER BY ip_from DESC LIMIT 1) lower_bound INNER JOIN ip2location_px2 ON lower_bound.ip_from = ip2location_px2.ip_from WHERE ip2location_px2.ip_to >= INET_ATON('%s') LIMIT 1" % (ip, ip))
	if len(result) == 0:
		return None

	# Unpack the result and return it. Since the database contains consecutive IP-ranges, we assume there is only one row.
	ip2proxy_result = result[0]
	result_dict = {}
	result_dict["proxy_type"] = ip2proxy_result[3]
	result_dict["country_code"] = ip2proxy_result[4]
	result_dict["country_name"] = ip2proxy_result[5]
	return result_dict

# Gets the latest timestamp in which an IP-address most recently enriched by IP2Proxy.
def get_ip2proxy_latest_timestamp(database, ip):
	ip_results = execute_select_sql_query(database, "SELECT MAX(response_time) FROM ip2proxy WHERE INET_NTOA(ip_address) = '%s'" % ip)
	if len(ip_results) == 0:
		# No timestamp found, so this IP-address probably has never been enriched before.
		return None
	else:
		latest_row = ip_results[0]
		return latest_row[0]

# External enrichment function for the IP2Proxy intel source.
# Returns True if successful or False otherwise.
def execute_enrichment(database, mail_id, ttl_days, config, indicator):
	# Get last enrichment timestamp first, if any.
	latest = get_ip2proxy_latest_timestamp(database, indicator)
	threshold_date = datetime.datetime.now() + datetime.timedelta(days=-ttl_days)
	if latest and latest > threshold_date:
		# Just return True: enrichment still falls within cache period.
		return True

	# Open connection to IP2Location database.
	ip2_db = connect_mysql_database('localhost', config["db_user"], config["db_pass"], config["db_name"])
	if not ip2_db:
		return False

	# Execute the enrichment request. None result means no results in the database. It does not mean something failed.
	# It just means the local database does not contain any information about this IP address.
	result = ip2proxy_enrich(ip2_db, indicator)
	if not result:
		return (True, 0)

	# Define the insertion query.
	query = "INSERT INTO ip2proxy (response_time,ip_address,proxy_type,country_code,country_name) VALUES (NOW(),INET_ATON(%s),%s,%s,%s)"

	# Execute the insertion query.
	inserted_row_id = execute_mutation_sql_query(database, query, (indicator, result["proxy_type"], result["country_code"], result["country_name"]))
	return (inserted_row_id != 0, 0)
