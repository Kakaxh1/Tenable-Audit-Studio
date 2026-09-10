import openpyxl
import re

def parse_excel(excel_path):
    wb = openpyxl.load_workbook(excel_path, data_only=True)
    sheet = wb.active # Usually Sheet1
    
    customizations = {}
    
    for row_idx in range(2, sheet.max_row + 1):
        row = [cell.value for cell in sheet[row_idx]]
        # Skip empty rows or rows without mapped CIS ID
        if len(row) <= 12 or row[12] is None:
            continue
            
        cis_id = str(row[12]).strip()
        agreed_raw = row[7]
        section = row[1]
        
        if agreed_raw is None:
            continue
            
        agreed_str = str(agreed_raw).strip()
        
        # Clean and parse agreed values based on common patterns
        cleaned_val = agreed_str
        
        # Extract number for password policy values and lockout counters
        if re.search(r'^\d+\s+(passwords|days|minutes|logon|invalid|characters)', agreed_str, re.IGNORECASE):
            match = re.match(r'^(\d+)', agreed_str)
            if match:
                cleaned_val = match.group(1)
        elif re.search(r'^(Enabled|Disabled)$', agreed_str, re.IGNORECASE):
            # Normalize to title case (e.g. Enabled, Disabled)
            cleaned_val = agreed_str.capitalize()
        elif agreed_str.lower() in ['success & failure', 'success and failure', 'success, failure']:
            cleaned_val = "Success, Failure"
        elif 'ibm_admin' in agreed_str.lower():
            cleaned_val = "IBM_Admin"
        elif 'ibm_guest' in agreed_str.lower():
            cleaned_val = "IBM_Guest"
        elif agreed_str.lower() == '1 day':
            cleaned_val = "1"
        elif agreed_str.lower() == '8':
            cleaned_val = "8"
        elif agreed_str.lower() == '5':
            cleaned_val = "5"
        else:
            # For multiline agreed values or other values, clean up whitespace
            cleaned_val = agreed_str.split('\n')[0].strip()
            
        customizations[cis_id] = {
            'section': section,
            'heading': row[2],
            'parameter': row[3],
            'description': row[5],
            'agreed_raw': agreed_str,
            'agreed_cleaned': cleaned_val,
            'rationale': row[8],
            'remediation': row[10]
        }

        
    return customizations

if __name__ == '__main__':
    # Test execution
    import sys
    path = r'sample_policy_mapping.xlsx'
    if len(sys.argv) > 1:
        path = sys.argv[1]
    if os.path.exists(path):
        res = parse_excel(path)
        print(f"Parsed {len(res)} customizations.")
    for k in sorted(res.keys())[:10]:
        print(f"  {k} -> {res[k]['agreed_cleaned']} (raw: {repr(res[k]['agreed_raw'])})")
