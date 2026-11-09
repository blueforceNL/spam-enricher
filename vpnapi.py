import urllib.request
import datetime
import json

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
# VPNAPI.io specific functions.                             |
# ----------------------------------------------------------|

# Requests enrichment from VPNAPI.io.
def vpnapi_io_enrich(api_key, ip):
	# Query VPNAPI.io with given API key and specified IP address.
	try:
		f = urllib.request.urlopen("https://vpnapi.io/api/%s?key=%s" % (ip, api_key))
	except urllib.error.HTTPError:
		return (f.status, None)

	# Load JSON output into dictionary and return it.
	return (f.status, json.loads(f.read()))

# Gets the latest timestamp in which an IP-address most recently enriched by VPNAPI.io.
def get_vpnapi_io_latest_timestamp(database, ip):
	ip_results = execute_select_sql_query(database, "SELECT MAX(response_time) FROM vpnapi WHERE INET_NTOA(ip_address) = '%s'" % ip)
	if len(ip_results) == 0:
		# No timestamp found, so this IP-address probably has never been enriched before.
		return None
	else:
		latest_row = ip_results[0]
		return latest_row[0]

# External enrichment function for the VPNAPI.io intel source.
# Returns True if successful or False otherwise.
def execute_enrichment(database, mail_id, ttl_days, config, indicator):
	# Get last enrichment timestamp first, if any.
	latest = get_vpnapi_io_latest_timestamp(database, indicator)
	threshold_date = datetime.datetime.now() + datetime.timedelta(days=-ttl_days)
	if latest and latest > threshold_date:
		# Just return True: enrichment still falls within cache period.
		return True

	# Execute the enrichment request.
	result = vpnapi_io_enrich(config["api_key"], indicator)
	if not result[1]:
		return (False, result[0])

	# If the IP-address is not part of the result, we will not do anything.
	json_result = result[1]
	if "ip" not in json_result:
		return False

	# Construct the query.
	query = "INSERT INTO vpnapi (response_time,ip_address,vpn,proxy,tor,relay,city,region,country,continent,region_code,country_code,continent_code,latitude,longitude,time_zone,locale_code,metro_code,is_in_european_union,network,asn,as_org) VALUES (NOW(),INET_ATON(%s),%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"

	# Get nested result objects.
	security = json_result["security"]
	location = json_result["location"]
	network = json_result["network"]

	# Perform sanity checking and consolidate result fields into database-suitable values.
	vpn = 1 if "vpn" in security and security["vpn"] else 0
	proxy = 1 if "proxy" in security and security["proxy"] else 0
	tor = 1 if "tor" in security and security["tor"] else 0
	relay = 1 if "relay" in security and security["relay"] else 0
	city = location["city"] if "city" in location else ""
	region = location["region"] if "region" in location else ""
	country = location["country"] if "country" in location else ""
	continent = location["continent"] if "continent" in location else ""
	region_code = location["region_code"] if "region_code" in location else ""
	country_code = location["country_code"] if "country_code" in location else ""
	continent_code = location["continent_code"] if "continent_code" in location else ""
	latitude = location["latitude"] if "latitude" in location else ""
	longitude = location["longitude"] if "longitude" in location else ""
	time_zone = location["time_zone"] if "time_zone" in location else ""
	locale_code = location["locale_code"] if "locale_code" in location else ""
	metro_code = location["metro_code"] if "metro_code" in location else ""
	is_in_eu = 1 if "is_in_european_union" in location and location["is_in_european_union"] else 0

	# Retrieve information from the network sub-object if applicable.
	net = ""
	asn = ""
	as_org = ""
	if network:
		net = network["network"] if "network" in network else ""
		asn = network["autonomous_system_number"] if "autonomous_system_number" in network else ""
		as_org = network["autonomous_system_organization"] if "autonomous_system_organization" in network else ""

	# Truncate potentially long strings that may trigger an unexpected MySQL error. Do some error handling to make sure we don't reference NULL.
	if city:
		city = city[:63] if len(city) > 63 else city

	if region:
		region = region[:63] if len(region) > 63 else region

	if country:
		country = country[:63] if len(country) > 63 else country

	if continent:
		continent = continent[:63] if len(continent) > 63 else continent


	# Latitude and longitude values are not None in the output so we have to fix them manually in case of non-existing data.
	if latitude == "":
		latitude = None
	if longitude == "":
		longitude = None

	# Execute the query with all countless fields.
	inserted_row_id = execute_mutation_sql_query(database, query, (json_result["ip"], vpn, proxy, tor, relay, city, region, country, continent, region_code, country_code, continent_code, latitude, longitude, time_zone, locale_code, metro_code, is_in_eu, net, asn, as_org))
	return (inserted_row_id != 0, result[0])
