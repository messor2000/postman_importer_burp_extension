import js2py


class Postman:
    collectionVariables = []
    globals = []
    environment = []

    def runPreRequestScripts(self, request):
        exec_script = self.get_exec(request)
        if exec_script is not None:
            js_code = self.reformat_script(exec_script)
            js_code = "pm = {'collectionVariables': [], 'globals': [], 'environment': []};\nvariable = {}\n" + js_code + "\npm;"

            pm = js2py.eval_js(js_code)

            self.collectionVariables.append(pm.collectionVariables)
            self.globals.append(pm.globals)
            self.environment.append(pm.environment)

    def get_exec(self, item):
        for event in item.get('event', []):
            script = event.get('script', {})
            if 'exec' in script:
                return script['exec']
        return None

    def reformat_script(self, str_list):
        formatted_script = []
        for s in str_list:
            if not s.strip():
                continue
            elif s.startswith(('var', 'const', 'let')):
                formatted_str = s.strip().replace('var', '').replace('const', '').replace('let', '').strip(" ")
                formatted_script.append(formatted_str)
            elif "pm.collectionVariables.set" in s:
                name = s.split("(")[1].split(",")[0].strip("'")
                value = s.split(",")[1].strip().strip(")")
                formatted_str = "pm.collectionVariables.push({'value': %s, 'key': '%s'});" % (value, name)
                formatted_script.append(formatted_str)
            elif "pm.globals.set" in s:
                variable_name = s.split("(")[1].split(",")[0].strip().strip('"')
                formatted_str = "pm.globals.push({'value': %s, 'key': '%s'});" % (variable_name, variable_name)
                formatted_script.append(formatted_str)
            elif "pm.environment.set" in s:
                variable_name = s.split("(")[1].split(",")[0].strip().strip('"')
                formatted_str = "pm.environment.push({'value': %s, 'key': '%s'});" % (variable_name, variable_name)
                formatted_script.append(formatted_str)
            else:
                formatted_script.append(s.strip())

        return '\n'.join(line for line in formatted_script if not line.startswith('//'))

    def get_script_variables(self):
        print(self.merge_lists([self.collectionVariables, self.globals, self.environment]))
        return self.merge_lists([self.collectionVariables, self.globals, self.environment])

    def merge_lists(self, lists):
        result = []
        for lst in lists:
            if lst:
                for item in lst:
                    result.extend(item)
        return result

    def append_list_to_variables(self, list1, list2):
        key_value_map = {item['key']: item['value'] for item in list2}
        for item in list1:
            if item['value'] == '' and item['key'] in key_value_map:
                item['value'] = key_value_map[item['key']]
        for item in list2:
            if item['key'] not in key_value_map:
                list1.append({'key': item['key'], 'value': item['value']})
            elif item['key'] not in [d.get('key') for d in list1]:
                list1.append({'key': item['key'], 'value': item['value']})
        return list1

    def convert_list(self, lst):
        output = []
        keys = set()
        for item in lst:
            if isinstance(item, list):
                if item:
                    output += self.convert_list(item)
            elif isinstance(item, dict):
                key = item.get('key')
                value = item.get('value', '')
                if key not in keys:
                    keys.add(key)
                    output.append({'key': key, 'value': value})
            else:
                continue
        return output
