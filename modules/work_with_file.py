import os
import csv
from modules import validation

class WorkWithFile:
    API_KEY_FILE_PATH = r'key.txt'

    @staticmethod
    def write_key_to_file(key: str):
        if validation.Validation.validate_vt_api_key(key):
            with open(WorkWithFile.API_KEY_FILE_PATH,'w') as file:
                file.write(key)
        else:
            print('Wrong Virus Total API key format')
    
    @staticmethod    
    def read_key_from_file():
        try:
            key = None 
            with open(WorkWithFile.API_KEY_FILE_PATH, 'r') as file:
                key = file.readline()

            if validation.Validation.validate_vt_api_key(key):
                return key
            else:
                print('Wrong Virus Total API key format')
                return None
        except:
            print(f'Unable to read key file {WorkWithFile.API_KEY_FILE_PATH}. File does not exist or is corrupted')
            return None
    
    @staticmethod        
    def write_to_csv(file_path: str, data: list, column_names: list, separator = ';'):    
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f, delimiter=separator)
            writer.writerow(column_names)
            writer.writerows(data)    
                
    @staticmethod    
    def get_result_file_path(file_path: str):
        head_tail = os.path.split(file_path)
        file_name = head_tail[1].split('.')
        res_file_name = '/'.join([head_tail[0], f'{file_name[0]}_res.{file_name[1]}'])

        return res_file_name

    @staticmethod
    def clear_data(data: list):
        data = [row.strip() for row in data]
        # remove duplicates
        data = set(data)
        # remove empty values
        data = [row for row in data if row]
        
        return data

    @staticmethod
    def read_file(file_path: str):
        with open(file_path, 'r') as file:
            return file.readlines()