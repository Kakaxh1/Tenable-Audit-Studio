import re

# Comprehensive list of keywords for custom_item fields across all Tenable Nessus audit formats
KEYWORDS = {
    'type', 'description', 'info', 'solution', 'see_also', 'reference', 
    'value_type', 'value_data', 'check_type', 'password_policy', 
    'lockout_policy', 'wmi_namespace', 'wmi_request', 'wmi_attribute', 
    'wmi_key', 'reg_key', 'reg_item', 'reg_option', 'key_item', 
    'service_name', 'acl_option', 'rights', 'service_type', 'check_option',
    'audit_policy', 'audit_policy_subcategory', 'group_membership', 'file_option', 'file_item',
    'sql_request', 'sql_types', 'sql_expect', 'cmd', 'expect', 'file', 
    'owner', 'mask', 'system', 'uname', 'regex', 'not_expect', 'severity', 
    'select_type', 'required', 'context', 'item', 'ignore', 'string', 
    'variable', 'default', 'version', 'only_show', 'max_depth'
}

def parse_audit_to_tree(content):
    """
    Parses Nessus audit file content into an Abstract Syntax Tree (AST).
    Preserves all text, spacing, and comments.
    """
    tag_pattern = re.compile(
        r'(</?(?:check_type|group_policy|if|condition|then|else|custom_item|report)\b[^>]*>)',
        re.IGNORECASE
    )
    parts = tag_pattern.split(content)
    
    root = {
        'type': 'root',
        'children': []
    }
    
    stack = [root]
    
    for part in parts:
        if not part:
            continue
        
        if part.startswith('<') and part.endswith('>'):
            is_closing = part.startswith('</')
            if is_closing:
                tag_name = part[2:-1].strip().lower()
                if len(stack) > 1:
                    found_idx = -1
                    for idx in range(len(stack) - 1, 0, -1):
                        if stack[idx]['type'] == tag_name:
                            found_idx = idx
                            break
                    if found_idx != -1:
                        while len(stack) > found_idx + 1:
                            stack.pop()
                        stack.pop()
            else:
                m = re.match(r'<([a-zA-Z0-9_]+)', part)
                if m:
                    tag_name = m.group(1).lower()
                    node = {
                        'type': tag_name,
                        'raw_header': part,
                        'children': []
                    }
                    stack[-1]['children'].append(node)
                    stack.append(node)
        else:
            node = {
                'type': 'text',
                'content': part
            }
            stack[-1]['children'].append(node)
            
    return root

def render_tree(node):
    """
    Serializes the AST node back into string content.
    """
    if node['type'] == 'root':
        return "".join(render_tree(c) for c in node['children'])
    elif node['type'] == 'text':
        return node['content']
    else:
        inner = "".join(render_tree(c) for c in node['children'])
        return node['raw_header'] + inner + f"</{node['type']}>"

def extract_variables(content):
    """
    Extracts variable declarations from the #<variables> block.
    """
    var_match = re.search(r'#<variables>([\s\S]*?)#</variables>', content)
    if not var_match:
        return []
    
    var_block = var_match.group(1)
    lines = [line.lstrip('#').strip() for line in var_block.splitlines()]
    cleaned_block = "\n".join(lines)
    
    var_pattern = re.compile(r'<variable>([\s\S]*?)</variable>', re.IGNORECASE)
    vars_list = []
    for m in var_pattern.finditer(cleaned_block):
        inner = m.group(1)
        name_m = re.search(r'<name>(.*?)</name>', inner, re.IGNORECASE)
        default_m = re.search(r'<default>(.*?)</default>', inner, re.IGNORECASE)
        desc_m = re.search(r'<description>(.*?)</description>', inner, re.IGNORECASE)
        info_m = re.search(r'<info>(.*?)</info>', inner, re.IGNORECASE)
        val_type_m = re.search(r'<value_type>(.*?)</value_type>', inner, re.IGNORECASE)
        
        if name_m:
            vars_list.append({
                'name': name_m.group(1).strip(),
                'default': default_m.group(1).strip() if default_m else '',
                'description': desc_m.group(1).strip() if desc_m else '',
                'info': info_m.group(1).strip() if info_m else '',
                'value_type': val_type_m.group(1).strip() if val_type_m else ''
            })
    return vars_list

def update_variables_in_text(content, variables_map):
    """
    Replaces default values of variables inside the #<variables> block.
    """
    def replace_var_block(match):
        block = match.group(1)
        for name, value in variables_map.items():
            pattern = re.compile(
                rf'(<name>\s*{re.escape(name)}\s*</name>[\s\S]*?<default>)(.*?)(</default>)',
                re.IGNORECASE
            )
            block = pattern.sub(lambda m, val=value: m.group(1) + val + m.group(3), block)
        return block
        
    return re.sub(r'(#<variables>[\s\S]*?#</variables>)', replace_var_block, content)

def parse_custom_item_fields(inner_text):
    """
    Parses key-value fields inside custom_item or report block text.
    """
    fields = {}
    lines = inner_text.splitlines()
    current_key = None
    current_val_lines = []
    
    for line in lines:
        stripped = line.strip()
        if not stripped:
            if current_key:
                current_val_lines.append("")
            continue
            
        m = re.match(r'^([a-z_]+)\s*:(.*)', stripped, re.IGNORECASE)
        if m and m.group(1).lower() in KEYWORDS:
            if current_key:
                fields[current_key] = "\n".join(current_val_lines).strip()
            current_key = m.group(1).lower()
            current_val_lines = [m.group(2).strip()]
        else:
            if current_key:
                current_val_lines.append(stripped)
                
    if current_key:
        fields[current_key] = "\n".join(current_val_lines).strip()
        
    return fields

def update_custom_item_field(item_text, field_name, new_value):
    """
    Updates the value of a specific field (e.g. value_data, sql_expect, expect) inside a custom_item.
    """
    quoted_pattern = re.compile(rf'(\b{re.escape(field_name)}\s*:\s*)"([\s\S]*?)"', re.IGNORECASE)
    if quoted_pattern.search(item_text):
        clean_val = new_value
        if clean_val.startswith('"') and clean_val.endswith('"'):
            clean_val = clean_val[1:-1]
        elif clean_val.startswith("'") and clean_val.endswith("'"):
            clean_val = clean_val[1:-1]
        return quoted_pattern.sub(lambda m, val=clean_val: f'{m.group(1)}"{val}"', item_text)
    
    unquoted_pattern = re.compile(rf'(\b{re.escape(field_name)}\s*:\s*)([^\r\n]+)', re.IGNORECASE)
    if unquoted_pattern.search(item_text):
        return unquoted_pattern.sub(lambda m, val=new_value: f'{m.group(1)}{val}', item_text)
        
    # If field doesn't exist, append it
    return item_text + f'\n    {field_name} : "{new_value}"'

def find_all_custom_items(node, results):
    """
    Finds all custom_item and report nodes recursively.
    """
    if node['type'] in ('custom_item', 'report'):
        results.append(node)
    else:
        for child in node.get('children', []):
            find_all_custom_items(child, results)

def walk_tree(node, current_conditionals, items_list):
    """
    Traverses the tree to collect custom_item compliance checks and their conditionals path.
    Supports Windows (Registry, GPO), Database (SQL_POLICY), Unix/Linux (CMD_EXEC, FILE), and Network audits.
    """
    if node['type'] in ('custom_item', 'report'):
        inner_text = "".join(render_tree(c) for c in node['children'])
        fields = parse_custom_item_fields(inner_text)
        
        desc = fields.get('description', '')
        if desc.startswith('"') and desc.endswith('"'):
            desc = desc[1:-1]
        elif desc.startswith("'") and desc.endswith("'"):
            desc = desc[1:-1]
            
        cis_id = ''
        m = re.match(r'^([0-9\.]+)\b', desc)
        if m:
            cis_id = m.group(1)
            
        # Determine expected value and its field name
        val_data = ''
        target_field = 'value_data'
        if 'value_data' in fields:
            val_data = fields['value_data']
            target_field = 'value_data'
        elif 'sql_expect' in fields:
            val_data = fields['sql_expect']
            target_field = 'sql_expect'
        elif 'expect' in fields:
            val_data = fields['expect']
            target_field = 'expect'
        elif 'regex' in fields:
            val_data = fields['regex']
            target_field = 'regex'
        elif 'mask' in fields:
            val_data = fields['mask']
            target_field = 'mask'
        elif 'rights' in fields:
            val_data = fields['rights']
            target_field = 'rights'

        if val_data.startswith('"') and val_data.endswith('"'):
            val_data = val_data[1:-1]
        elif val_data.startswith("'") and val_data.endswith("'"):
            val_data = val_data[1:-1]

        # Determine setting / query path
        setting_key = fields.get('reg_key', '')
        setting_item = fields.get('reg_item', '')
        if not setting_key and 'sql_request' in fields:
            setting_key = fields['sql_request']
        elif not setting_key and 'cmd' in fields:
            setting_key = fields['cmd']
        elif not setting_key and 'file' in fields:
            setting_key = fields['file']
        elif not setting_key and 'service_name' in fields:
            setting_key = fields['service_name']

        items_list.append({
            'node': node,
            'cis_id': cis_id,
            'description': desc,
            'type': fields.get('type', 'REPORT' if node['type'] == 'report' else ''),
            'reg_key': setting_key,
            'reg_item': setting_item,
            'value_data': val_data,
            'target_field': target_field,
            'info': fields.get('info', ''),
            'solution': fields.get('solution', ''),
            'parent_conditionals': list(current_conditionals)
        })
    elif node['type'] == 'if':
        cond_node = None
        then_node = None
        else_node = None
        for child in node['children']:
            if child['type'] == 'condition':
                cond_node = child
            elif child['type'] == 'then':
                then_node = child
            elif child['type'] == 'else':
                else_node = child
                
        cond_descs = []
        if cond_node:
            cond_items = []
            find_all_custom_items(cond_node, cond_items)
            for item in cond_items:
                inner_text = "".join(render_tree(c) for c in item['children'])
                fields = parse_custom_item_fields(inner_text)
                desc = fields.get('description', '')
                if desc.startswith('"') and desc.endswith('"'):
                    desc = desc[1:-1]
                elif desc.startswith("'") and desc.endswith("'"):
                    desc = desc[1:-1]
                if desc:
                    cond_descs.append(desc)
                    
        cond_label = " AND ".join(cond_descs) if cond_descs else "Conditional Context"
        
        if then_node:
            walk_tree(then_node, current_conditionals + [cond_label], items_list)
        if else_node:
            walk_tree(else_node, current_conditionals + [f"NOT ({cond_label})"], items_list)
    else:
        for child in node.get('children', []):
            walk_tree(child, current_conditionals, items_list)

def node_has_substantive_content(node):
    """
    Recursively determines if a node or its descendants contain any active custom_item or report.
    """
    if node['type'] in ('custom_item', 'report'):
        return not node.get('marked_remove', False)
    for child in node.get('children', []):
        if child.get('marked_remove', False):
            continue
        if child['type'] in ('custom_item', 'report'):
            return True
        if child['type'] in ('if', 'condition', 'then', 'else', 'group_policy', 'check_type'):
            if node_has_substantive_content(child):
                return True
    return False

def prune_tree(node):
    """
    Bottom-up pruning of AST: removes nodes marked with 'marked_remove',
    and removes truly empty containers (if, condition, then, else, group_policy).
    """
    if 'children' not in node:
        return
        
    for child in list(node['children']):
        prune_tree(child)
        
    node['children'] = [c for c in node['children'] if not c.get('marked_remove', False)]
    
    # Prune truly empty control structures
    if node['type'] in ('if', 'condition', 'then', 'else', 'group_policy'):
        if not node_has_substantive_content(node):
            node['marked_remove'] = True

def make_custom_item_node(check_dict):
    """
    Constructs an AST custom_item node from a dictionary.
    Supports Windows, Unix, SQL, and Network check types.
    """
    lines = ["    <custom_item>"]
    
    ctype = check_dict.get('type', 'REGISTRY_SETTING')
    lines.append(f"      type                 : {ctype}")
    
    desc = check_dict.get('description', '')
    if desc:
        desc_clean = desc.replace('"', "'")
        lines.append(f'      description          : "{desc_clean}"')
        
    info = check_dict.get('info', '')
    if info:
        info_clean = info.replace('"', "'")
        lines.append(f'      info                 : "{info_clean}"')
        
    solution = check_dict.get('solution', '')
    if solution:
        solution_clean = solution.replace('"', "'")
        lines.append(f'      solution             : "{solution_clean}"')

    # Type-specific field generation
    if ctype == 'SQL_POLICY':
        sql_req = check_dict.get('sql_request') or check_dict.get('reg_key') or ''
        sql_types = check_dict.get('sql_types', 'INTEGER')
        sql_exp = check_dict.get('sql_expect') or check_dict.get('value_data') or '0'
        lines.append(f'      sql_request          : "{sql_req}"')
        lines.append(f'      sql_types            : {sql_types}')
        lines.append(f'      sql_expect           : {sql_exp}')
    elif ctype == 'CMD_EXEC':
        cmd = check_dict.get('cmd') or check_dict.get('reg_key') or ''
        expect = check_dict.get('expect') or check_dict.get('value_data') or ''
        lines.append(f'      cmd                  : "{cmd}"')
        lines.append(f'      expect               : "{expect}"')
    else:
        # Default Windows / Registry / Policy checks
        reg_key = check_dict.get('reg_key', '')
        if reg_key:
            lines.append(f'      reg_key              : "{reg_key}"')
            
        reg_item = check_dict.get('reg_item', '')
        if reg_item:
            lines.append(f'      reg_item             : "{reg_item}"')
            
        val_data = check_dict.get('value_data', '')
        if val_data:
            lines.append(f'      value_data           : "{val_data}"')
            
        val_type = check_dict.get('value_type', '')
        if val_type:
            lines.append(f'      value_type           : {val_type}')

    lines.append("    </custom_item>")
    
    return {
        'type': 'custom_item',
        'raw_header': '    <custom_item>\n',
        'children': [{
            'type': 'text',
            'content': "\n".join(lines[1:-1]) + "\n"
        }]
    }

def append_to_outer_then(tree, node_to_add):
    """
    Appends a node directly to the first major <then>, <group_policy>, <check_type>, or root container.
    """
    # 1. Try finding <then>
    def find_in_type(curr_node, target_type):
        if curr_node['type'] == target_type:
            curr_node['children'].append(node_to_add)
            return True
        for child in curr_node.get('children', []):
            if find_in_type(child, target_type):
                return True
        return False
        
    for container in ('then', 'group_policy', 'check_type', 'root'):
        if find_in_type(tree, container):
            return True
            
    tree['children'].append(node_to_add)
    return True

def validate_syntax(content):
    """
    Performs tag balance and nesting structure syntax validation.
    Returns list of errors (strings). Empty list indicates success.
    """
    errors = []
    
    tags = re.findall(r'(</?(?:check_type|group_policy|if|condition|then|else|custom_item|report)\b[^>]*>)', content, re.IGNORECASE)
    stack = []
    for t in tags:
        is_closing = t.startswith('</')
        if is_closing:
            tag_name = t[2:-1].strip().lower()
            if not stack:
                errors.append(f"Unexpected closing tag: {t}")
            elif stack[-1] != tag_name:
                errors.append(f"Mismatched closing tag: expected </{stack[-1]}>, found {t}")
                stack.pop()
            else:
                stack.pop()
        else:
            m = re.match(r'<([a-zA-Z0-9_]+)', t)
            if m:
                tag_name = m.group(1).lower()
                stack.append(tag_name)
    if stack:
        errors.append(f"Unclosed tags at the end of file: {', '.join(stack)}")
        
    empty_blocks = re.findall(r'<([a-zA-Z0-9_]+)>\s*</\1>', content, re.IGNORECASE)
    for eb in empty_blocks:
        errors.append(f"Empty block detected: <{eb}>...</{eb}>")
        
    return errors
