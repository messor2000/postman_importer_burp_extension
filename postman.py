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

            if hasattr(pm, 'collectionVariables') and pm.collectionVariables is not None:
                self.collectionVariables.append(pm.collectionVariables)

            if hasattr(pm, 'globals') and pm.globals is not None:
                self.globals.append(pm.globals)

            if hasattr(pm, 'environment') and pm.environment is not None:
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
                formatted_str = "pm.collectionVariables.push({'name': '%s', 'value': %s});" % (name, value)
                formatted_script.append(formatted_str)
            elif "pm.globals.set" in s:
                variable_name = s.split("(")[1].split(",")[0].strip().strip('"')
                formatted_str = "pm.globals.push('%s', %s);" % (variable_name, variable_name)
                formatted_script.append(formatted_str)
            elif "pm.environment.set" in s:
                variable_name = s.split("(")[1].split(",")[0].strip().strip('"')
                formatted_str = "pm.environment.push('%s', %s);" % (variable_name, variable_name)
                formatted_script.append(formatted_str)
            else:
                formatted_script.append(s.strip())

        return '\n'.join(line for line in formatted_script if not line.startswith('//'))

    def get_script_variables(self):
        combined_list = self.collectionVariables + self.globals + self.environment
        return combined_list

