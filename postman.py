import re
import json
import requests


def update_tuple_list_to_dict_list(tup_list, conditional):
    try:
        return [{'type': 'string', 'value': tup[0], 'key': tup[1]} for tup in tup_list]
    except Exception:
        tup_list = transform_list(tup_list)
        return [{'type': 'string', 'value': tup[1], 'key': tup[0]} for tup in tup_list]


def parse_result_scripts(input_str):
    globals_list = [(item['value'], item['key']) for item in input_str['globals']]
    collection_variables_list = [(item['value'], item['key']) for item in input_str['collectionVariables']]
    environment_list = [(item['value'], item['key']) for item in input_str['environment']]
    return globals_list, collection_variables_list, environment_list


def separate_lists(input_dict):
    globals_list = input_dict['globals']
    collection_variables_list = input_dict['collectionVariables']
    environment_list = input_dict['environment']
    return globals_list, collection_variables_list, environment_list


def format_code(code):
    code = code.replace('\\n', '\n')
    code = code.replace('\\"', '"')
    code = code.strip('"')
    return code


def merge_lists(lists):
    result = []
    for lst in lists:
        if lst:
            for item in lst:
                result.extend(item)
    return result


def reformat_script(str_list):
    formatted_script = []
    for s in str_list:
        if not s.strip():
            continue
        elif "pm.collectionVariables.set" in s:
            name = s.split("(")[1].split(",")[0].strip("'")
            value = s.split(",")[1].strip().strip(")")
            formatted_str = "pm.collectionVariables.push({value: %s, key: '%s'});" % (value, name)
            formatted_script.append(formatted_str)
        elif "pm.globals.set" in s:
            variable_name = s.split("(")[1].split(",")[0].strip().strip('"')
            formatted_str = "pm.globals.push({value: %s, key: '%s'});" % (variable_name, variable_name)
            formatted_script.append(formatted_str)
        elif "pm.environment.set" in s:
            variable_name = s.split("(")[1].split(",")[0].strip().strip('"')
            formatted_str = "pm.environment.push({value: %s, key: '%s'});" % (variable_name, variable_name)
            formatted_script.append(formatted_str)
        else:
            formatted_script.append(s.strip())

    return '\n'.join(line for line in formatted_script if not line.startswith('//'))


def reformat_script_for_tests(input_str):
    str_list = input_str.split('\n')
    formatted_script = []
    for s in str_list:
        if not s.strip():
            continue
        formatted_str = replace_set_with_push(s.strip())
        formatted_script.append(formatted_str)
    return '\n'.join(formatted_script)


def replace_set_with_push(input_str):
    pattern = r'(pm\.\w+\.)set\((.+?)\);'
    output_str = re.sub(pattern, r'\1push(\2);', input_str)
    return output_str


def get_request_response(url, body, host, content_type, method, auth):
    headers = {}
    if host is not None or host is not '':
        headers['Host'] = host
    if auth is not None or auth is not '':
        headers['Authorization'] = auth
    if content_type is not None or content_type is not '':
        headers['Content-Type'] = content_type
    response = requests.request(method, url, headers=headers, json=body)
    return response


def clean_tests(input_str):
    lines = input_str.split('\n')

    cleaned_lines = []
    skip_line = False
    for line in lines:
        line = line.strip()
        if skip_line:
            if line.endswith('});'):
                skip_line = False
        elif line.startswith('pm.test'):
            skip_line = True
        elif line and not line.startswith('//') and not line.startswith('/*') and not line.startswith('console.log') \
                and 'JSON.parse(responseBody)' not in line:
            cleaned_lines.append(line)

    cleaned_input = '\n'.join(cleaned_lines)

    return cleaned_input


def run_formatted_test(tests, json_response):
    lines = tests.split(u'\n')
    for i in range(len(lines)):
        path = find_json_path(lines[i])
        if path is not None and not isinstance(path, type(None)):
            result_value = get_json_value_by_path(path, json_response)
            lines[i] = replace_value_in_test(result_value, lines[i])

    return "\n".join(lines)


def get_json_value_by_path(path, json_data):
    try:
        json_data = json.loads(json_data)
    except ValueError:
        raise ValueError("Invalid JSON object")

    try:
        if path.startswith(".") and len(path) > 1:
            path = path[1:]
            json_data = json_data.get(path)
        else:
            for key in path.split("."):
                if key.startswith("[") and key.endswith("]"):
                    index = int(key[1:-1])
                    json_data = json_data[index]
                else:
                    json_data = json_data[key]
    except (KeyError, IndexError, TypeError):
        return None

    return json_data


def find_json_path(line):
    json_prefix = "jsonData."
    json_suffix = ");"
    pm_prefix = "pm.response.json()."

    if json_prefix in line:
        start_index = line.index(json_prefix) + len(json_prefix)
        end_index = line.index(json_suffix)
        return "." + line[start_index:end_index]
    elif pm_prefix in line:
        start_index = line.index(pm_prefix) + len(pm_prefix)
        end_index = line.index(json_suffix)
        return "." + line[start_index:end_index]

    return None


def replace_value_in_test(value, push_string):
    if push_string.startswith('pm.'):
        parts = push_string.split(',')
        if len(parts) < 2:
            return push_string
        parts[1] = ' ' + str(value)
        return ','.join(parts) + ')'
    else:
        if 'pm.response.json()' in push_string or 'jsonData' in push_string:
            parts = push_string.split('=')
            if len(parts) == 2:
                return '{}= \'{}\';'.format(parts[0], value)

        return push_string


def get_exec_scripts(item):
    for event in item.get('event', []):
        if event.get('listen') == 'prerequest':
            script = event.get('script', {})
            if 'exec' in script:
                return script['exec']
    return None


def get_exec_tests(item):
    for event in item.get('event', []):
        if event.get('listen') == 'test':
            script = event.get('script', {})
            if 'exec' in script:
                return '\n'.join(script['exec'])
    return None


def eval_js(code):
    url = 'http://localhost:3000'
    code = json.dumps(code)
    code = format_code(code)
    payload = {
        'code': 'pm = {collectionVariables: [], globals: [], environment: []};\nvariable = {};\n' +
                code +
                '\n{ result: pm }'
    }

    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    response_dict = json.loads(response.text)
    body_dict = json.loads(response_dict['body'])
    result = body_dict['result']
    return result


def transform_list(input_list):
    tuple_list = [(input_list[i], input_list[i+1]) for i in range(0, len(input_list), 2)]

    return tuple_list


def get_request_response_status(request_str, body, host, content_type, method, auth):
    response = get_request_response(request_str, body, host, content_type, method, auth)
    response_code = response.status_code
    return response_code


def get_request_response_code(request_str, body, host, content_type, method, auth):
    response = get_request_response(request_str, body, host, content_type, method, auth)
    response_code = response.text
    return response_code


class Postman:
    collection_variables = []
    globals = []
    environment = []

    def run_pre_request_scripts(self, request):
        exec_script = get_exec_scripts(request)
        if exec_script is not None:
            js_code = reformat_script(exec_script)

            pm = eval_js(js_code)

            globals, collection_variables, environment = parse_result_scripts(pm)

            self.collection_variables.append(collection_variables)
            self.globals.append(globals)
            self.environment.append(environment)

    def get_script_variables(self):
        return merge_lists([self.collection_variables, self.globals, self.environment])

    def append_list_to_variables(self, list1, list2, conditional):
        list2 = update_tuple_list_to_dict_list(list2, conditional)
        for item in list1:
            if item['value'] == '' and item['key'] in list2:
                item['value'] = list2[item['key']]
        for item in list2:
            if item['key'] not in list2 and item['key'] not in [d['key'] for d in list1]:
                list1.append({'key': item['key'], 'value': item['value']})
            elif item['key'] not in list2:
                existing_item = next((d for d in list1 if d['key'] == item['key']), None)
                existing_item['value'] = item['value']
            elif item['key'] in list2 and item['key'] not in [d['key'] for d in list1]:
                list1.append({'key': item['key'], 'value': item['value']})
        return list1

    def run_tests(self, request, url, body, host, content_type, method, auth):
        exec_tests = get_exec_tests(request)
        if exec_tests is not None:
            response_status = get_request_response_status(url, body, host, content_type, method, auth)
            if response_status is 200:
                response_text = get_request_response_code(url, body, host, content_type, method, auth)

                exec_tests = get_exec_tests(request)
                cleaned_tests = clean_tests(exec_tests)
                updated_tests = reformat_script_for_tests(cleaned_tests)

                refactored_tests = run_formatted_test(updated_tests, response_text)

                pm = eval_js(refactored_tests)

                globals, collection_variables, environment = separate_lists(pm)

                self.collection_variables.append(collection_variables)
                self.globals.append(globals)
                self.environment.append(environment)

            else:
                print("ERROR: Requests does not return response, response code: " + str(response_status))

        return None


