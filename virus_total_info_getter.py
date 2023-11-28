import argparse
import time
from tabulate import tabulate

# Custom modules
from modules import whois_lookup_ipwhois, work_with_file, virus_total, validation, utils

# Script args
parser = argparse.ArgumentParser()

# Required args
parser.add_argument('-src','--src_file_path', help='Source file path (Required)', required=True, type=validation.Validation.validate_file)

# Optional args
parser.add_argument('-o', '--out_file_path', help='Output result file path', type= str)
parser.add_argument('-k', '--vt_api_key', help='Virus Total API key. Necessary in case if you are going to submit your IP/Domain list to the Virus Total', type = str)
parser.add_argument('-vt', '--virus_total', help='Virus Total report. By default Whois and Virus Total options are on (-w -vt)', action='store_true')
parser.add_argument('-w', '--whois', help='Whois report. By default Whois and Virus Total options are on (-w -vt)', action='store_true')
parser.add_argument('-ds', '--dont_show', help="Don't show result's in the terminal", action='store_true')
parser.add_argument('-p', '--premium', help="Option for premium Virus Total subscription owners which reduces delay between requests", action='store_true')
parser.add_argument('-sk', '--save_key', help="Save key in script to avoid -k option in future. Saves Virus Total API key passed after -k option", action='store_true')
parser.add_argument('-d', '--debug', help="Debug mode. Errors are shown as stacktrace", action='store_true')

# Parse arguments
args = parser.parse_args()

def main():
    # Delay between requests to Virus Total
    if args.premium:
        DELAY = virus_total.VirusTotal.PREMIUM
    else:
        DELAY = virus_total.VirusTotal.FREE
    # Usually request to VT takes 2 sec
    REQ_TIME = 2
    # In free subscription 15 sec delay between requests is needed
    if DELAY == virus_total.VirusTotal.FREE:
        REQ_TIME += 15
    
    result_file_path = args.out_file_path
     
    # Check if output file is writable
    if args.out_file_path:
        try:
            work_with_file.WorkWithFile.write_to_csv(result_file_path,[[]],'')
            print(f'\nResult file {result_file_path} was created')
        except:
            print(f'\nResults can not by saved to {args.out_file_path}. File is opened in other application or can not be created or overwritten')
            exit 
    
    # Virus Total API data
    vt_api_key = args.vt_api_key
    
    if vt_api_key == None:
        vt_api_key = work_with_file.WorkWithFile.read_key_from_file()
        print(f'Key reading from {work_with_file.WorkWithFile.API_KEY_FILE_PATH} ...')
        
    vt = virus_total.VirusTotal(vt_api_key)
    
    if args.save_key:
        work_with_file.WorkWithFile.write_key_to_file(vt_api_key)
        print(f'Key saved to {work_with_file.WorkWithFile.API_KEY_FILE_PATH}')
    
    # Read from file
    file_path = args.src_file_path
    
    data = work_with_file.WorkWithFile.read_file(file_path)
    data = work_with_file.WorkWithFile.clear_data(data)

    data_rows_count = len(data)

    if data_rows_count == 0:
        print('Source file is empty')
        exit()
    
    print(f'\nSource file contains {data_rows_count} lines. Estimated time is {utils.Utils.time_formatter(REQ_TIME * data_rows_count)} , but processing can take more time in case of extra Virus Total requests (if Virus Total has no data about IoC).\n')
    print('Processing data...\n')
    
    # Different report types
    # Whois
    if args.whois and args.virus_total == False:
        banner = '\nWHOIS\n'
        column_names = ['IP','Domain','Country', 'Registrar', 'CIDR', 'Creation date', 'Last update']
        result = whois_lookup_ipwhois.Whois.bulk_get_whois_main_info(data)
        # Virus Total V3 extended info
    else:
        banner = '\nWHOIS & VIRUS TOTAL\n'
        column_names = ['IOC type', 'IP/Domain/Hash','Verdict','Domain'] + virus_total.VirusTotal.MAIN_VT_FIELDS + list(virus_total.VirusTotal.MAIN_IP_WHOIS_FIELDS.keys())
        column_names = [col.title().replace('_', ' ') for col in column_names]
        full_info_flag = True
        
        # Virus Total V3 main info
        if args.virus_total and args.whois == False:        
            banner = '\nVIRUS TOTAL\n'
            column_names = ['IOC type', 'IP/Domain/Hash','Verdict']
            full_info_flag = False  
            
        result = []
        counter = len(data)
        
        for ioc in data:
            counter = counter - 1
                    
            result.append(vt.virus_total_info_check(ioc, full_info = full_info_flag))
            
            if counter != 0:
                print(f'{counter} IoC to check remaining. Estimated time {utils.Utils.time_formatter(counter * REQ_TIME)}.')
                time.sleep(DELAY)
            else:
                print('\nIP information gathering is finished\n')
    
    # Print results in terminal
    if args.dont_show == False:
        print(banner)
        
        columns_count = len(column_names)
        bound = 13
        
        if  columns_count > bound:
            if args.out_file_path:
                print(f'!!! It is a short report. More information you can find in full report stored into {args.out_file_path}\n')
            else:
                print(f'!!! It is a short report. Run script with [ -o OUT_FILE_PATH ] option to store an extended report\n')
            
            # TODO fix hardcoded indexes
            # Between these indexes is situated data about VT score
            tmp_l = 4
            tmp_r = 8
            
            tmp_columns = column_names[:tmp_l] + column_names[tmp_r:bound] #+ column_names[tmp_r:columns_count:9]
            tmp_result = []
            for row in result:
                tmp_result.append(row[:tmp_l] + row[tmp_r:bound]) #+ row[tmp_r:columns_count])
        
            print(tabulate(tmp_result,headers=tmp_columns))
        else:
            print(tabulate(result,headers=column_names))
            
        print()
        
    # Save to file
    if args.out_file_path:
        try:
            result_file_path = args.out_file_path
            work_with_file.WorkWithFile.write_to_csv(result_file_path,result,column_names)
            print(f'Results were saved to file {result_file_path}')
        except:
            print(f'Results were not saved to {result_file_path}. File is opened in other application or can not be created or overwritten')
    
    return 0

if __name__=='__main__':
    # Debug mode
    if args.debug:
         print(f"{'SCRIPT RUNS IN DEBUG MODE':=^20}")
         main()
    else:
        try:
            main()
        except:
            print('\nScript interrupted')