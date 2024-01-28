This script is created to obtain Virus Total scan result and Whois information for list of IP or Domains.

Before run script. Use pip3 install -r requirements.txt command to install all dependencies. You can find file requirements.txt in folder containing script and it's modules.

To  run script use "python3" command for Unix OS or "python" for Windows

Usage examples:

# Get Whois and Virus total information about IP/Domains from list ..\domain.txt and save it to res.csv without printing it in the terminal
python3 .\get_ip_domain_info.py -src ..\domain.txt -o res.csv -k "Your Virus Total API key" -ds

# Show Whois information about IP/Domains from list ..\domain.txt
python .\get_ip_domain_info.py --src ..\domain.txt -w

# Show Virus Total verdict and Whois info and also save Virus Total API key
python.exe .\get_ip_domain_info.py --src .\src.csv -k "Your Virus Total API key" -sk

# After save Virus Total API key with -sk option (like in previous example) -k option is not necessary anymore
python.exe .\get_ip_domain_info.py --src .\src.csv -o res.csv

Key is saved to the file key.txt in script folder

Options:
  -h, --help            show this help message and exit
  -src SRC_FILE_PATH, --src_file_path SRC_FILE_PATH
                        Source file path (Required)
  -o OUT_FILE_PATH, --out_file_path OUT_FILE_PATH
                        Output result file path
  -k VT_API_KEY, --vt_api_key VT_API_KEY
                        Virus Total API key. Necessary in case if you are going to submit your IP/Domain list to the Virus Total
  -vt, --virus_total    Virus Total report. By default Whois and Virus Total options are on (-w -vt)
  -w, --whois           Whois report. By default Whois and Virus Total options are on (-w -vt)
  -ds, --dont_show      Don't show result's in the terminal
  -p, --premium         Option for premium Virus Total subscription owners which reduces delay between requests
  -sk, --save_key       Save key in script to avoid -k option in future. Saves Virus Total API key passed after -k option