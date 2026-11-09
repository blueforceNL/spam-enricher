#!/bin/bash
# ---------------------------------------------
# Downloads most recent IP2PROXY Lite database
# and inserts the entries into the database
# locally for the enricher to use.
# ---------------------------------------------

TOKEN="k9AXzBedZw2vmBFE2odJ44qe4upnOCMSxus2vctCzRyfvjuDFaG7R2zn7IPO8bAS"
PRODUCT="PX2LITE"
LOCAL_ZIP_FILE_NAME="/root/PX2.LITE.zip"
DB_USER="ip2location"
DB_PASS="!nf3ct3dL0lz!"
DB_TABLE="ip2location_px2"

# Change directory to /root/ first.
cd /root/

# Download database file into local .zip.
wget "https://www.ip2location.com/download?token=$TOKEN&file=$PRODUCT" -O $LOCAL_ZIP_FILE_NAME

# Check whether the file that came back is actually a Zip archive.
f=$(file $LOCAL_ZIP_FILE_NAME)
if [[ $f != *"Zip archive data"* ]]; then
	echo "Downloaded file is not a Zip file!"
	xxd $LOCAL_ZIP_FILE_NAME
	exit 1
fi

# Unzip the downloaded file and store filenames extracted.
extracted_files=$(unzip -o $LOCAL_ZIP_FILE_NAME | grep inflating | grep -Eo ":\s+.*?$" | tr -d ':')

# Rename the extracted CSV file to match the table name.
cp IP2PROXY-LITE-PX2.CSV "$DB_TABLE.csv"

# Insert new entries from the downloaded CSV file.
mysqlimport --local -d --ignore-lines=0 --lines-terminated-by='\n' --fields-terminated-by=',' --fields-enclosed-by='"' --user="$DB_USER" --password="$DB_PASS" ip2location "$DB_TABLE.csv"

# Remove the extracted files.
for x in $extracted_files; do
	rm -v $x
done

# Remove renamed file as well.
rm -v "$DB_TABLE.csv"

# Remove the downloaded Zip file.
#rm -v $LOCAL_ZIP_FILE_NAME
