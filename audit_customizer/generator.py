import re
import os
from .excel_parser import parse_excel

from audit_parser import KEYWORDS

def format_final_output(content):
    keywords = KEYWORDS
    
    def format_item(match):
        lead_space = match.group(1)
        inner = match.group(2).strip()
        
        lines = inner.splitlines()
        formatted_lines = []
        for line in lines:
            stripped_line = line.strip()
            m = re.match(r'^([a-z_]+)(\s*):(.*)', stripped_line)
            if m:
                key, spaces, value = m.groups()
                if key in keywords:
                    num_spaces = 22 - 6 - len(key)
                    if num_spaces < 1:
                        num_spaces = 1
                    formatted_lines.append(f"      {key}" + " " * num_spaces + f":{value}")
                    continue
            
            formatted_lines.append(line)
            
        inner_content = '\n'.join(formatted_lines)
        prefix = "\n" if '\n' in lead_space else ""
        return f"{prefix}    <custom_item>\n{inner_content}\n    </custom_item>"


    content = re.sub(r'(\s*)<custom_item>([\s\S]*?)</custom_item>', format_item, content)
    
    # Remove blank lines between blocks
    content = re.sub(r'</custom_item>\s*\n\s*<custom_item>', '</custom_item>\n    <custom_item>', content)
    content = re.sub(r'</custom_item>\s*\n\s*<if>', '</custom_item>\n    <if>', content)
    content = re.sub(r'</if>\s*\n\s*<custom_item>', '</if>\n    <custom_item>', content)
    content = re.sub(r'</if>\s*\n\s*<if>', '</if>\n    <if>', content)
    
    # Collapse multiple consecutive blank lines to a single blank line
    content = re.sub(r'\n\s*\n\s*\n+', '\n\n', content)
    return content



def customize_audit(baseline_path, excel_path, output_path):
    # Parse customizations from Excel
    customs = parse_excel(excel_path)
    
    # Whitelist of check IDs that must always be kept as-is from the baseline
    always_keep = {'1.2.3', '18.3.1', '2.2.33', '18.10.93.2.1', '18.10.93.2.2'}
    
    # Detect OS version from baseline filename
    baseline_filename = os.path.basename(baseline_path).lower()
    if '2019' in baseline_filename:
        os_version = '2019'
    elif '2022' in baseline_filename:
        os_version = '2022'
    else:
        os_version = '2016'

    # Map baseline check_id to Excel check_id if there are offsets/shifts
    def get_excel_id(check_id):
        if os_version == '2019':
            shifts = {
                '2.3.1.1': '2.3.1.2',      # Guest Status
                '2.3.1.2': '2.3.1.3',      # Limit Blank Passwords
                '2.3.1.3': '2.3.1.4',      # Admin Rename
                '2.3.1.4': '2.3.1.5',      # Guest Rename
                '18.10.18.2': '18.10.17.2',
                '18.10.18.3': '18.10.17.3',
                '18.10.18.5': '18.10.17.4',
            }
            return shifts.get(check_id, check_id)
        elif os_version == '2022':
            shifts = {
                '2.2.3': '2.2.4',
                '2.2.4': '2.2.6',
                '2.2.5': '2.2.8',
                '2.2.7': '2.2.11',
                '2.2.12': '2.2.17',
                '2.2.14': '2.2.20',
                '2.2.15': '2.2.22',
                '2.2.16': '2.2.23',
                '2.2.17': '2.2.24',
                '2.2.18': '2.2.25',
                '2.2.20': '2.2.29',
                '2.2.21': '2.2.30',
                '2.2.25': '2.2.35',
                '2.2.27': '2.2.39',
                '2.2.28': '2.2.40',
                '2.2.30': '2.2.42',
                '2.2.31': '2.2.43',
                '2.2.34': '2.2.46',
                '2.2.35': '2.2.47',
                '2.2.36': '2.2.49',
                '2.3.1.1': '2.3.1.2',      # Guest Status
                '2.3.1.2': '2.3.1.3',      # Limit Blank Passwords
                '2.3.1.3': '2.3.1.4',      # Admin Rename
                '2.3.1.4': '2.3.1.5',      # Guest Rename
                '2.3.8.2': '2.3.8.3',
                '2.3.11.12': '2.3.11.13',
                '17.2.2': '17.2.5',
                '17.2.3': '17.2.6',
                '18.9.19.2': '18.9.19.6',
                '18.9.29.1': '18.9.28.1',
                '18.9.29.2': '18.9.28.2',
                '18.9.29.3': '18.9.28.5',
                '18.9.35.6.3': '18.9.33.6.3',
                '18.9.35.6.4': '18.9.33.6.4',
                '18.9.53.1.1': '18.9.51.1.1',
                '18.10.94.2.1': '18.10.92.2.1',
                '18.10.18.2': '18.10.17.2',
                '18.10.18.3': '18.10.17.3',
                '18.10.18.5': '18.10.17.4',
            }
            return shifts.get(check_id, check_id)
        return check_id

    # Read baseline content
    with open(baseline_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        
    # Parse baseline file into lines to locate the main outer <then> and </then> blocks
    lines = content.splitlines(keepends=True)
    in_custom_item = False
    outer_then_idx = -1
    outer_then_close_idx = -1
    
    for idx, line in enumerate(lines):
        if '<custom_item>' in line:
            in_custom_item = True
        elif '</custom_item>' in line:
            in_custom_item = False
            
        if not in_custom_item:
            if '<then>' in line:
                if outer_then_idx == -1:
                    outer_then_idx = idx
            elif '</then>' in line:
                outer_then_close_idx = idx
                
    if outer_then_idx == -1 or outer_then_close_idx == -1:
        raise ValueError("Could not locate main outer <then> and </then> blocks")
        
    part_before = "".join(lines[:outer_then_idx + 1])
    part_then = "".join(lines[outer_then_idx + 1:outer_then_close_idx])
    part_else = "".join(lines[outer_then_close_idx:])
    
    # 1. Update variables in part_before
    var_match = re.search(r'(#<variables>[\s\S]*?#</variables>)', part_before)
    if var_match:
        var_block = var_match.group(1)
        
        # Customize MAXIMUM_PASSWORD_AGE (1.1.2)
        if '1.1.2' in customs:
            max_age = customs['1.1.2']['agreed_cleaned']
            var_block = re.sub(
                r'(<name>MAXIMUM_PASSWORD_AGE</name>[\s#]*<default>).*?(</default>)',
                f'\\g<1>[1..{max_age}]\\g<2>',
                var_block
            )
            
        # Customize MINIMUM_PASSWORD_LENGTH (1.1.4)
        if '1.1.4' in customs:
            min_len = customs['1.1.4']['agreed_cleaned']
            var_block = re.sub(
                r'(<name>MINIMUM_PASSWORD_LENGTH</name>[\s#]*<default>).*?(</default>)',
                f'\\g<1>[{min_len}..MAX]\\g<2>',
                var_block
            )
            
        # Customize LOCKOUT_RESET (1.2.4)
        if '1.2.4' in customs:
            lockout_reset = customs['1.2.4']['agreed_cleaned']
            var_block = re.sub(
                r'(<name>LOCKOUT_RESET</name>[\s#]*<default>).*?(</default>)',
                f'\\g<1>[{lockout_reset}..MAX]\\g<2>',
                var_block
            )
 
        # Customize LEGAL_NOTICE_TEXT (2.3.7.4)
        if '2.3.7.4' in customs:
            notice_text = customs['2.3.7.4']['agreed_cleaned']
            var_block = re.sub(
                r'(<name>LEGAL_NOTICE_TEXT</name>[\s#]*<default>).*?(</default>)',
                f'\\g<1>{notice_text}\\g<2>',
                var_block
            )
 
        # Customize LEGAL_CAPTION_TEXT (2.3.7.5)
        if '2.3.7.5' in customs:
            caption_text = "W A R N I N G - Unauthorized access to this System/Device is strictly prohibited. Disconnect immediately if you are not an authorized user."
            var_block = re.sub(
                r'(<name>LEGAL_CAPTION_TEXT</name>[\s#]*<default>).*?(</default>)',
                f'\\g<1>{caption_text}\\g<2>',
                var_block
            )
            
        # Replace the variables block in part_before
        part_before = part_before.replace(var_match.group(1), var_block)
        
    # 2. Parse and filter custom_items in part_then
    part_then_lines = part_then.splitlines(keepends=True)
    in_custom_item = False
    in_nested_if = 0
    current_item_lines = []
    new_part_then_lines = []
    kept_count = 0
    kept_ids = set()
    last_outer_kept = False       # whether the last outer custom_item was kept
    nested_if_buffer = []         # buffer for a top-level nested <if> block
    in_nested_if_block = False    # True while buffering a nested <if> block
    nested_if_depth = 0           # depth within a nested <if> block
    
    for line in part_then_lines:
        if not in_custom_item:
            stripped_line = line.strip()
            
            # Detect start of a nested <if> block (depth == 0, not yet buffering)
            if (stripped_line == '<if>' or stripped_line.startswith('<if ')) and not in_nested_if_block:
                # Start buffering this nested if block
                in_nested_if_block = True
                nested_if_depth = 1
                nested_if_buffer = [line]
                in_nested_if = 1
                continue
            
            # Inside a nested <if> buffer
            if in_nested_if_block:
                nested_if_buffer.append(line)
                if stripped_line == '<if>' or stripped_line.startswith('<if '):
                    nested_if_depth += 1
                    in_nested_if += 1
                elif stripped_line == '</if>':
                    nested_if_depth -= 1
                    in_nested_if -= 1
                    if nested_if_depth == 0:
                        in_nested_if_block = False
                        # Only emit if the last outer custom_item was kept
                        if last_outer_kept:
                            new_part_then_lines.extend(nested_if_buffer)
                        nested_if_buffer = []
                continue
            
            if '<custom_item>' in line:
                in_custom_item = True
                current_item_lines = [line]
            else:
                new_part_then_lines.append(line)
        else:
            current_item_lines.append(line)
            if '</custom_item>' in line:
                in_custom_item = False
                item_content = "".join(current_item_lines)
                
                # Parse the description and filter
                inner_match = re.search(r'<custom_item>([\s\S]*?)</custom_item>', item_content)
                if inner_match:
                    item_inner = inner_match.group(1)
                    desc_match = re.search(r'description\s*:\s*"(.*?)"', item_inner)
                    if desc_match:
                        desc = desc_match.group(1)
                        id_match = re.match(r'^([0-9\.]+)\b', desc)
                        if id_match:
                            check_id = id_match.group(1)
                            excel_id = get_excel_id(check_id)
                            if excel_id in customs or check_id in always_keep:
                                last_outer_kept = True
                                kept_ids.add(excel_id)
                                # Customize this item
                                customized_inner = item_inner.strip()
                                if excel_id == '1.1.2' and '1.1.2' in customs:
                                    max_age = customs['1.1.2']['agreed_cleaned']
                                    customized_inner = customized_inner.replace("365", max_age)
                                elif excel_id == '1.1.4' and '1.1.4' in customs:
                                    min_len = customs['1.1.4']['agreed_cleaned']
                                    customized_inner = customized_inner.replace("14", min_len)
                                elif excel_id == '1.2.4' and '1.2.4' in customs:
                                    lockout_reset = customs['1.2.4']['agreed_cleaned']
                                    customized_inner = customized_inner.replace("15", lockout_reset)
                                elif excel_id == '2.3.1.4' and '2.3.1.4' in customs:
                                    admin_name = customs['2.3.1.4']['agreed_cleaned']
                                    customized_inner = re.sub(
                                        r'(value_data\s*:\s*").*?(")',
                                        f'\\g<1>{admin_name}\\g<2>',
                                        customized_inner
                                    )
                                    customized_inner = re.sub(
                                        r'(check_type\s*:\s*)\w+',
                                        r'\g<1>CHECK_EQUAL',
                                        customized_inner
                                    )
                                elif excel_id == '2.3.1.5' and '2.3.1.5' in customs:
                                    guest_name = customs['2.3.1.5']['agreed_cleaned']
                                    customized_inner = re.sub(
                                        r'(value_data\s*:\s*").*?(")',
                                        f'\\g<1>{guest_name}\\g<2>',
                                        customized_inner
                                    )
                                    customized_inner = re.sub(
                                        r'(check_type\s*:\s*)\w+',
                                        r'\g<1>CHECK_EQUAL',
                                        customized_inner
                                    )
                                
                                new_part_then_lines.append(f"    <custom_item>\n      {customized_inner}\n    </custom_item>\n")
                                kept_count += 1
                            else:
                                last_outer_kept = False
                        else:
                            # No CIS ID — don't change last_outer_kept
                            pass
                                    
    # Assemble the customized part_then
    new_part_then = "".join(new_part_then_lines)
    
    # Combine everything back
    output_content = part_before + new_part_then + part_else
    output_content = format_final_output(output_content)
    
    # Write output
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(output_content)
        
    return kept_count, kept_ids

if __name__ == '__main__':
    baseline = r'sample_baseline.audit'
    excel = r'sample_customization.xlsx'
    output = r'sample_output.audit'
    if os.path.exists(baseline) and os.path.exists(excel):
        count, _ = customize_audit(baseline, excel, output)
        print(f"Generated customized audit with {count} checks.")
