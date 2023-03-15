import json
import requests


def update_tuple_list_to_dict_list(tup_list):
    return [{'type': 'string', 'value': tup[0], 'key': tup[1]} for tup in tup_list]


def parse_input(input_str):
    globals_list = [(item['value'], item['key']) for item in input_str['globals']]
    collection_variables_list = [(item['value'], item['key']) for item in input_str['collectionVariables']]
    environment_list = [(item['value'], item['key']) for item in input_str['environment']]
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


def get_request_response(request):
    lines = request.split('\n')
    method, url, _ = lines[0].split()
    headers = {}
    host = ''
    for line in lines[1:]:
        if line.strip():
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
            if key.strip().lower() == 'host':
                host = value.strip()

    body = None
    if '' in lines:
        body_str = ''.join(lines[lines.index('') + 1:])
        if body_str.strip():
            body = json.loads(body_str)

    if not url.startswith('http'):
        url = 'http://' + host + url

    response = requests.request(method, url, headers=headers, json=body)
    return response


def get_request_response_code(request_str):
    response = get_request_response(request_str)
    response_code = response.text
    return response_code

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
        elif line and not line.startswith('//') and not line.startswith('console.log'):
            cleaned_lines.append(line)

    cleaned_input = '\n'.join(cleaned_lines)

    return cleaned_input


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


class Postman:
    collection_variables = []
    globals = []
    environment = []

    def run_pre_request_scripts(self, request):
        exec_script = get_exec_scripts(request)
        if exec_script is not None:
            js_code = reformat_script(exec_script)

            pm = eval_js(js_code)

            globals, collection_variables, environment = parse_input(pm)

            self.collection_variables.append(collection_variables)
            self.globals.append(globals)
            self.environment.append(environment)

    def get_script_variables(self):
        return merge_lists([self.collection_variables, self.globals, self.environment])

    def append_list_to_variables(self, list1, list2):
        list2 = update_tuple_list_to_dict_list(list2)
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

    def get_request_response_status(self, request_str):
        response = get_request_response(request_str)
        response_code = response.status_code
        return response_code

    def run_tests(self, finalRequest, request):
        response_text = get_request_response_code(finalRequest)

        exec_tests = get_exec_tests(request)

        if exec_tests is not None:
            updated_tests = clean_tests(exec_tests)
            return updated_tests

        return None


