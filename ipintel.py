import urllib.request
import datetime

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

# ----------------------------------------------------------|
# IPIntel specific functions.                               |
# ----------------------------------------------------------|

# Enriches an IP address with IPIntel (probabilistic VPN/Proxy indicator).
def ipintel_enrich(contact, ip):
	# Query IPIntel with given IP and contact info.
	try:
		f = urllib.request.urlopen("http://check.getipintel.net/check.php?ip=%s&contact=%s" % (ip, contact))
	except urllib.error.HTTPError:
		return None

	# Check whether the result is an error or an actual value.
	if f.status == 200:
		return (f.status, float(f.read()))
	else:
		return None

# Gets the latest timestamp in which an IP-address most recently enriched by IPIntel.
def get_ipintel_latest_timestamp(database, ip):
	ip_results = execute_select_sql_query(database, "SELECT MAX(response_time) FROM ipintel WHERE INET_NTOA(ip_address) = '%s'" % ip)
	if len(ip_results) == 0:
		# No timestamp found, so this IP-address probably has never been enriched before.
		return None
	else:
		latest_row = ip_results[0]
		return latest_row[0]

# External enrichment function for the IPIntel intel source.
# Returns True if successful or False otherwise.
def execute_enrichment(database, mail_id, ttl_days, config, indicator):
	# Get last enrichment timestamp first, if any.
	latest = get_ipintel_latest_timestamp(database, indicator)
	threshold_date = datetime.datetime.now() + datetime.timedelta(days=-ttl_days)
	if latest and latest > threshold_date:
		# Just return True: enrichment still falls within cache period.
		return True

	# Execute the enrichment request.
	result = ipintel_enrich(config["contact"], indicator)
	if not result:
		return False

	# Define the insertion query.
	query = "INSERT INTO ipintel (response_time,ip_address,value) VALUES (NOW(),INET_ATON(%s),%s)"

	# Execute the insertion query.
	verdict = result[1]
	inserted_row_id = execute_mutation_sql_query(database, query, (indicator, verdict))
	return (inserted_row_id != 0, result[0])
