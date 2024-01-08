#!/bin/bash

domain=$1
RED="\033[1;31m"
RESET="\033[0m"
GREEN="\033[1;32m"
RESETA="\033[0m"

info_path=$domain/info
subdomain_path=$domain/subdomains
screenshot_path=$domain/screenshots
recon_path=$domain/recon
nuclei_path=$domain/nuclei-results

if [ ! -d "$domain" ];then
    mkdir $domain
fi

if [ ! -d "$info_path" ];then
    mkdir $info_path
fi

if [ ! -d "$subdomain_path" ];then
    mkdir $subdomain_path
fi

if [ ! -d "$screenshot_path" ];then
    mkdir $screenshot_path
fi

if [ ! -d "$recon_path" ];then
    mkdir $recon_path
fi

if [ ! -d "$nuclei_path" ];then
    mkdir $nuclei_path
fi

echo -e "${RED} [+] Checkin' who it is...${RESET}"
whois $1 > $info_path/whois.txt
echo -e "${GREEN} [+] Whois Check Completed.${RESETA}" 

echo -e "${RED} [+] Launching subfinder...${RESET}"
subfinder -d $domain > $subdomain_path/found.txt
echo -e "${GREEN} [+] Subdomains Enumerated via Subfinder.${RESETA}" 

echo -e "${RED} [+] Running assetfinder...${RESET}"
assetfinder $domain | grep $domain >> $subdomain_path/found.txt
echo -e "${GREEN} [+] Subdomains Enumerated via Assetfinder.${RESETA}"

#echo -e "${RED} [+] Running Amass. This could take a while...${RESET}"
#amass enum -d $domain >> $subdomain_path/found.txt

echo -e "${RED} [+] Checking what's alive...${RESET}"
cat $subdomain_path/found.txt | grep $domain | sort -u | httprobe -prefer-https | grep https | sed 's/https\?:\/\///' | tee -a $subdomain_path/alive.txt
echo -e "${GREEN} [+] HTTP Probe Check Completed.${RESETA}"

echo -e "${RED} [+] Taking dem screenshotz...${RESET}"
gowitness file -f $subdomain_path/alive.txt -P $screenshot_path/ --no-http
echo -e "${GREEN} [+] Screenshots of Alive Domain Taken.${RESETA}"

# Function to create directories if they don't exist
create_directory() {
    if [ ! -d "$1" ]; then
        mkdir -p "$1"
    fi
}

# Create subdirectories within the recon directory
create_directory "$recon_path/scans"
create_directory "$recon_path/httprobe"
create_directory "$recon_path/potential_takeovers"
create_directory "$recon_path/wayback"
create_directory "$recon_path/wayback/params"
create_directory "$recon_path/wayback/extensions"

# Create empty files if they don't exist
touch "$recon_path/httprobe/alive.txt"
touch "$recon_path/final.txt"

echo "[+] Harvesting subdomains with assetfinder..."
assetfinder "$domain" >> "$recon_path/assets.txt"
cat "$recon_path/assets.txt" | grep "$domain" >> "$recon_path/final.txt"
rm "$recon_path/assets.txt"

#echo "[+] Double checking for subdomains with amass..."
#amass enum -d "$domain" >> "$recon_path/f.txt"
#sort -u "$recon_path/f.txt" >> "$recon_path/final.txt"
#rm "$recon_path/f.txt"

echo "[+] Probing for alive domains..."
cat "$recon_path/final.txt" | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> "$recon_path/httprobe/a.txt"
sort -u "$recon_path/httprobe/a.txt" > "$recon_path/httprobe/alive.txt"
rm "$recon_path/httprobe/a.txt"

echo "[+] Checking for possible subdomain takeover..."

if [ ! -f "$recon_path/potential_takeovers/potential_takeovers.txt" ]; then
    touch "$recon_path/potential_takeovers/potential_takeovers.txt"
fi

subjack -w "$recon_path/final.txt" -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o "$recon_path/potential_takeovers/potential_takeovers.txt"

echo "[+] Scanning for open ports..."
nmap -iL "$recon_path/httprobe/alive.txt" -T4 -oA "$recon_path/scans/scanned.txt"
echo -e "${GREEN} [+] Nmap Scans to check Open Ports Completed.${RESETA}"

echo "[+] Scraping Wayback data for each domain in final.txt..."
while IFS= read -r subdomain; do
    gau "$subdomain" >> "$recon_path/wayback/wayback_output.txt"
done < "$recon_path/final.txt"
echo -e "${GREEN} [+] Wayback Archives Checked on all Subdomains${RESETA}"
 
echo "[+] Harvesting subdomains with assetfinder..."
assetfinder $domain >> $recon_path/assets.txt
cat $recon_path/assets.txt | grep $1 >> $recon_path/final.txt
rm $recon_path/assets.txt
 
#echo "[+] Double checking for subdomains with amass..."
#amass enum -d $domain >> $recon_path/f.txt
#sort -u $recon_path/f.txt >> $recon_path/final.txt
#rm $recon_path/f.txt
 
echo "[+] Probing for alive domains..."
cat $recon_path/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> $recon_path/httprobe/a.txt
sort -u $recon_path/httprobe/a.txt > $recon_path/httprobe/alive.txt
rm $recon_path/httprobe/a.txt
 
echo "[+] Checking for possible subdomain takeover..."
 
if [ ! -f "$recon_path/potential_takeovers/potential_takeovers.txt" ];then
	touch $recon_path/potential_takeovers/potential_takeovers.txt
fi

subjack -w $recon_path/final.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o $recon_path/potential_takeovers/potential_takeovers.txt
 
echo "[+] Scanning for open ports..."
nmap -iL $recon_path/httprobe/alive.txt -T4 -oA $recon_path/scans/scanned.txt
 
echo "[+] Scraping wayback data..."
cat $recon_path/final.txt | waybackdomains >> $recon_path/wayback/wayback_output.txt
sort -u $recon_path/wayback/wayback_output.txt
 
echo "[+] Pulling and compiling all possible params found in wayback data..."
cat $recon_path/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $recon_path/wayback/params/wayback_params.txt
for line in $(cat $recon_path/wayback/params/wayback_params.txt);do echo $line'=';done
 
echo "[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output..."
for line in $(cat $recon_path/wayback/wayback_output.txt);do
	ext="${line##*.}"
	if [[ "$ext" == "js" ]]; then
		echo $line >> $recon_path/wayback/extensions/js1.txt
		sort -u $recon_path/wayback/extensions/js1.txt >> $recon_path/wayback/extensions/js.txt
	fi
	if [[ "$ext" == "html" ]];then
		echo $line >> $recon_path/wayback/extensions/jsp1.txt
		sort -u $recon_path/wayback/extensions/jsp1.txt >> $recon_path/wayback/extensions/jsp.txt
	fi
	if [[ "$ext" == "json" ]];then
		echo $line >> $recon_path/wayback/extensions/json1.txt
		sort -u $recon_path/wayback/extensions/json1.txt >> $recon_path/wayback/extensions/json.txt
	fi
	if [[ "$ext" == "php" ]];then
		echo $line >> $recon_path/wayback/extensions/php1.txt
		sort -u $recon_path/wayback/extensions/php1.txt >> $recon_path/wayback/extensions/php.txt
	fi
	if [[ "$ext" == "aspx" ]];then
		echo $line >> $recon_path/wayback/extensions/aspx1.txt
		sort -u $recon_path/wayback/extensions/aspx1.txt >> $recon_path/wayback/extensions/aspx.txt
	fi
	if [[ "$ext" == "csv" ]];then
		echo $line >> $recon_path/wayback/extensions/csv1.txt
		sort -u $recon_path/wayback/extensions/csv1.txt >> $recon_path/wayback/extensions/csv.txt
	fi
	if [[ "$ext" == "xlsx" ]];then
		echo $line >> $recon_path/wayback/extensions/xlsx1.txt
		sort -u $recon_path/wayback/extensions/xlsx1.txt >> $recon_path/wayback/extensions/xlsx.txt
	fi
	if [[ "$ext" == "doc" ]];then
		echo $line >> $recon_path/wayback/extensions/doc1.txt
		sort -u $recon_path/wayback/extensions/doc1.txt >> $recon_path/wayback/extensions/doc.txt
	fi
	if [[ "$ext" == "pdf" ]];then
		echo $line >> $recon_path/wayback/extensions/pdf1.txt
		sort -u $recon_path/wayback/extensions/pdf1.txt >> $recon_path/wayback/extensions/pdf.txt
	fi
	if [[ "$ext" == "docx" ]];then
		echo $line >> $recon_path/wayback/extensions/docx1.txt
		sort -u $recon_path/wayback/extensions/docx1.txt >> $recon_path/wayback/extensions/docx.txt
	fi
	if [[ "$ext" == "xml" ]];then
		echo $line >> $recon_path/wayback/extensions/xml1.txt
		sort -u $recon_path/wayback/extensions/xml1.txt >> $recon_path/wayback/extensions/xml.txt
	fi
done

#echo "[+] Running eyewitness against all compiled domains..."
#python3 EyeWitness/EyeWitness.py --web -f $recon_path/httprobe/alive.txt -d $recon_path/eyewitness --resolve