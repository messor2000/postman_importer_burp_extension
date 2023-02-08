import json
import re
import os
import urlparse
from javax import swing
from java.awt import Font
import base64
import thread
from burp import IBurpExtender, IExtensionStateListener, ITab
from burp import IHttpService
from burp import IHttpRequestResponse

try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


def getQueryFromUrl(url):
    match = re.search(r'\?(.*)', url)
    if match:
        query_string = match.group(1)
        return query_string
    else:
        return None


def getPathFromUrl(url):
    match = re.search(r'https?://[^/]+([^?]+)', url)
    if match:
        return match.group(1)
    return None


def getRequestContentType(headers):
    for header in headers:
        if header['key'] == "Content-Type":
            return header['value']
    return None


def parsePostmanCollection(collection):
    if 'item' in collection:
        items = collection['item']
        result = []
        for item in items:
            if 'item' in item:
                result += parsePostmanCollection(item)
            else:
                result.append(item)
        return result
    else:
        return [collection]


def createRequestWithoutAuth(method, path_name, query, host, body, contentType):
    if not body or body == "":
        return method + ' ' + path_name + query + ' HTTP/1.1\n\r' \
            + 'Host: ' + host + '\n\r\n\r'

    else:
        return method + ' ' + path_name + query + ' HTTP/1.1\n\r' \
            + 'Host: ' + host + '\n\r' \
            + 'Content-Type: ' + contentType + '\n\r' \
            + '\n\r' + body + '\n\r'


def createRequestWithAuth(method, path_name, query, host, body, contentType, auth):
    if not body or body == "":
        return method + ' ' + path_name + query + ' HTTP/1.1\n\r' \
            + 'Host: ' + host + '\n\r' \
            + 'Authorization: ' + auth + '\n\r'
    else:
        return method + ' ' + path_name + query + ' HTTP/1.1\n\r' \
            + 'Host: ' + host + '\n\r' \
            + 'Content-Type: ' + contentType + '\n\r' \
            + 'Authorization: ' + auth + '\n\r' \
            + '\n\r' + body + '\n\r'


def checkAuthField(collection):
    if isinstance(collection, dict):
        if "auth" in collection:
            return True
        elif "request" in collection and "auth" in collection["request"]:
            return True
        elif "item" in collection:
            return checkAuthField(collection["item"])
    elif isinstance(collection, list):
        for item in collection:
            if checkAuthField(item):
                return True
    return False


class BurpExtender(IBurpExtender, ITab, IExtensionStateListener):
    file = None
    pattern = "{{(.*?)}}"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.callbacks.setExtensionName("Postman Importer")
        self.callbacks.registerExtensionStateListener(self)
        self.helpers = callbacks.getHelpers()

        self.initGui()
        self.callbacks.addSuiteTab(self)
        print("Extension Loaded")

    def initGui(self):
        self.tab = swing.JPanel()
        self.titleLabel = swing.JLabel("Postman Importer")
        self.titleLabel.setFont(Font("Tahoma", 1, 17))
        self.infoLabel1 = swing.JLabel(
            "To get JSON file from postman you need to import, you should follow these steps: ")
        self.infoLabel2 = swing.JLabel(
            "Open collection, push export button, download .json file and upload this file to Burp")
        self.parseFileButton = swing.JButton("Load File to Parse", actionPerformed=self.loadFile)
        self.addButton = swing.JButton("Add requests to site map", actionPerformed=self.addRequestsToSiteMap)
        self.infoLabelEndpoint = swing.JLabel("You can add variables for your requests, auth or body")
        self.infoEndpointKeyField = swing.JLabel("Variable: ")
        self.endpointKeyField = swing.JTextField()
        self.infoEndpointValueField = swing.JLabel("Initial value: ")
        self.endpointValueField = swing.JTextField()
        self.addEndpointButton = swing.JButton("Add variable to list", actionPerformed=self.addEndpointToList)
        self.removeButton = swing.JButton("Remove selected variable", actionPerformed=self.remove)
        self.clearButton = swing.JButton("Clear all variables", actionPerformed=self.clear)
        self.urlListModel = swing.DefaultListModel()
        self.urlList = swing.JList(self.urlListModel)
        self.urlListPane = swing.JScrollPane(self.urlList)
        self.infoLabel3 = swing.JLabel(
            "NOTE: If you add new requests from another collection, but their will be duplicat, they will be "
            "overwritten")
        self.logLabel = swing.JLabel("Log:")
        self.logPane = swing.JScrollPane()
        self.logArea = swing.JTextArea("Postman Importer Log - Parsing and Run details will be appended here.\n")
        self.logArea.setLineWrap(True)
        self.logPane.setViewportView(self.logArea)
        layout = swing.GroupLayout(self.tab)
        self.tab.setLayout(layout)

        layout.setHorizontalGroup(
            layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                      .addGap(15)
                      .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                                .addComponent(self.titleLabel)
                                .addComponent(self.infoLabel1)
                                .addComponent(self.infoLabel2)
                                .addComponent(self.parseFileButton)
                                .addComponent(self.addButton)
                                .addComponent(self.infoLabelEndpoint)
                                .addComponent(self.infoEndpointKeyField)
                                .addComponent(self.endpointKeyField, swing.GroupLayout.PREFERRED_SIZE, 400,
                                              swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(self.infoEndpointValueField)
                                .addComponent(self.endpointValueField, swing.GroupLayout.PREFERRED_SIZE, 400,
                                              swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(self.addEndpointButton)
                                .addComponent(self.urlListPane, swing.GroupLayout.PREFERRED_SIZE, 400,
                                              swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(self.clearButton)
                                .addComponent(self.removeButton)
                                .addComponent(self.infoLabel3)
                                .addComponent(self.logLabel)
                                .addComponent(self.logPane, swing.GroupLayout.PREFERRED_SIZE, 825,
                                              swing.GroupLayout.PREFERRED_SIZE))))

        layout.setVerticalGroup(
            layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                      .addGap(15)
                      .addComponent(self.titleLabel)
                      .addGap(10)
                      .addComponent(self.infoLabel1)
                      .addGap(10)
                      .addComponent(self.infoLabel2)
                      .addGap(10)
                      .addComponent(self.parseFileButton)
                      .addGap(10)
                      .addComponent(self.addButton)
                      .addGap(20)
                      .addComponent(self.infoLabelEndpoint)
                      .addGap(10)
                      .addComponent(self.infoEndpointKeyField)
                      .addComponent(self.endpointKeyField, swing.GroupLayout.PREFERRED_SIZE, 30,
                                    swing.GroupLayout.PREFERRED_SIZE)
                      .addGap(10)
                      .addComponent(self.infoEndpointValueField)
                      .addComponent(self.endpointValueField, swing.GroupLayout.PREFERRED_SIZE, 30,
                                    swing.GroupLayout.PREFERRED_SIZE)
                      .addGap(10)
                      .addComponent(self.addEndpointButton)
                      .addGap(10)
                      .addComponent(self.urlListPane, swing.GroupLayout.PREFERRED_SIZE, 150,
                                    swing.GroupLayout.PREFERRED_SIZE)
                      .addGap(10)
                      .addComponent(self.removeButton)
                      .addGap(10)
                      .addComponent(self.clearButton)
                      .addGap(20)
                      .addComponent(self.infoLabel3)
                      .addGap(15)
                      .addComponent(self.logLabel)
                      .addGap(10)
                      .addComponent(self.logPane, swing.GroupLayout.PREFERRED_SIZE, 225,
                                    swing.GroupLayout.PREFERRED_SIZE)
                      ))
        return

    def getRequestsFromPostman(self):
        environment_variables = self.getUrlList()
        if self.file is None:
            self.callbacks.printError('\nYou did not select file, try agine \n')
            self.logArea.append('\nYou did not select file, try agine \n')
            return

        selectedFile = open(str(self.file))

        data = json.load(selectedFile)

        if data.get('variable'):
            for element in data['variable']:
                environment_variables.append(element)

        requests = parsePostmanCollection(data)

        self.logArea.append(
            '\nRequests from Postman collection: \n')

        for request in requests:
            url = request['request']['url']['raw']
            host = request['request']['url']['host']
            protocol = request['request']['url'].get('protocol', None)
            method = request['request']['method']
            contentType = request['request']['header']
            if request['request'].get('body'):
                body = request['request']['body']['raw']
            else:
                body = ""

            if not protocol:
                protocol = "http"

            host = self.setUpHost(host)
            url = self.setUpUrl(url, protocol, host)
            path = getPathFromUrl(url)
            query = getQueryFromUrl(url)
            contentType = getRequestContentType(contentType)
            body = self.replaceVariables(body)

            if path is None or path == "":
                path = "/"

            if query is None:
                query = ""
            else:
                query = '?' + query

            if contentType is None:
                contentType = ""

            if self.check_url(url):
                authorization, found = None, None
                if checkAuthField(data):
                    authorization, found = self.getAuthorization(request, data)
                    if not found:
                        self.logArea.append(
                            '\nRequest: %s was not added to the site map because of incorrect variables in '
                            'authorization \n' % url)
                        continue
                if found is None or found:
                    if authorization:
                        newRequest = createRequestWithAuth(method, path, query, host, body, contentType, authorization)
                    else:
                        newRequest = createRequestWithoutAuth(method, path, query, host, body, contentType)
                    self.addToSiteMap(url, newRequest, "")
                    self.logArea.append(
                        '\nRequest: %s was successfully added to the site map \n' % url)
                else:
                    self.logArea.append(
                        '\nRequest: %s was not added to the site map \n' % url)
            else:
                pass

        self.logArea.append(
            '\n -------------------------------------- \n')

    def setUpHost(self, host):
        environment_variables = self.getUrlList()
        host = ".".join(host)
        if re.search("{{.*}}", host):
            match = re.search(self.pattern, host)
            key = match.group(1)
            found = False
            for var in environment_variables:
                if isinstance(var, dict) and var['key'] == key:
                    host = var['value']
                    found = True
                    break
            if not found:
                self.callbacks.printError('\nThere is problem with reading this host in your request %s '
                                          % host)
        return host

    def setUpUrl(self, url, protocol, host):
        environment_variables = self.getUrlList()
        if re.search(self.pattern, url):
            match = re.search(self.pattern, url)
            key = match.group(1)
            found = False
            for var in environment_variables:
                if isinstance(var, dict) and var['key'] == key:
                    url = re.sub(self.pattern, var['value'], url)
                    found = True
                    break
            if not found:
                self.callbacks.printError('\nThere is problem with reading url in your request %s ' % url)

        if not re.search("https://", url):
            url = re.sub("^(.*?)/", protocol + "://" + host + "/", url)
        return url

    def addEndpointToList(self, event):
        environment_variables = self.getUrlList()
        endpointKey = self.endpointKeyField.getText()
        endpointValue = self.endpointValueField.getText()

        newEntry = {"type": "string", "value": endpointValue, "key": endpointKey}

        for i, entry in enumerate(environment_variables):
            if entry['key'] == endpointKey:
                environment_variables[i] = newEntry
                break
        else:
            environment_variables.append(newEntry)

        currentList = self.getUrlList()
        currentList.append(newEntry)
        self.urlList.setListData(currentList)

        self.logArea.append(
            '\nEnvironment variable with key: %s and value: %s was successfully added \n' % (
                endpointKey, endpointValue))

    def replaceVariables(self, body):
        environment_variables = self.getUrlList()
        matches = re.findall(self.pattern, body)
        for match in matches:
            variable = next((var for var in environment_variables if var['key'] == match), None)
            if variable is not None:
                body = body.replace("{{" + match + "}}", variable['value'])

        return body

    def check_url(self, url):
        if re.search(self.pattern, url):
            self.logArea.append(
                '\nRequest: %s was not added to the site map because of incorrect url \n' % url)
            self.callbacks.printError(
                '\nRequest: %s was not added to the site map because of incorrect url \n' % url)
            return False
        else:
            return True

    def getAuthorization(self, request, data):
        auth_type = None
        auth_params = {}
        foundVariables = True

        if 'request' in request and 'auth' in request['request']:
            if request["request"]["auth"]["type"] in ["basic", "bearer"]:
                auth_type = request["request"]["auth"]["type"]
                auth_params = request["request"]["auth"][auth_type]
        else:
            auth = data["auth"]
            auth_type = auth.get("type", None)
            auth_params = auth.get("params", {})

        print(auth_type)
        print(auth_params)

        username = ""
        password = ""
        token = ""
        for param in auth_params:
            if param.get("key") == "username":
                username = self.replaceVariablesInAuth(param["value"])
            elif param.get("key") == "password":
                password = self.replaceVariablesInAuth(param["value"])
            if param.get("key") == "token":
                token = self.replaceVariablesInAuth(param["value"])
                break

        if '{{' in username or '{{' in password or '{{' in token:
            foundVariables = False

        if auth_type == "basic":
            return "Basic " + base64.b64encode((username + ":" + password).encode("utf-8")).decode("utf-8") \
                , foundVariables
        elif auth_type == "bearer":
            return "Bearer " + token, foundVariables
        elif auth_type in ["oauth1", "oauth1.0a"]:
            oauth_consumer_key = ""
            oauth_token = ""
            oauth_signature_method = ""
            oauth_timestamp = ""
            oauth_nonce = ""
            oauth_version = ""
            oauth_signature = ""

            for param in auth_params:
                if param.get("key") == "oauth_consumer_key":
                    oauth_consumer_key = self.replaceVariablesInAuth(param["value"])
                elif param.get("key") == "oauth_token":
                    oauth_token = self.replaceVariablesInAuth(param["value"])
                elif param.get("key") == "oauth_signature_method":
                    oauth_signature_method = self.replaceVariablesInAuth(param["value"])
                elif param.get("key") == "oauth_timestamp":
                    oauth_timestamp = self.replaceVariablesInAuth(param["value"])
                elif param.get("key") == "oauth_nonce":
                    oauth_nonce = self.replaceVariablesInAuth(param["value"])
                elif param.get("key") == "oauth_version":
                    oauth_version = self.replaceVariablesInAuth(param["value"])
                elif param.get("key") == "oauth_signature":
                    oauth_signature = self.replaceVariablesInAuth(param["value"])

            oauth_header = "OAuth oauth_consumer_key=\"{}\", oauth_token=\"{}\", oauth_signature_method=\"{}\", " \
                           "oauth_timestamp=\"{}\", oauth_nonce=\"{}\", oauth_version=\"{}\", oauth_signature=\"{" \
                           "}\"".format(oauth_consumer_key, oauth_token, oauth_signature_method, oauth_timestamp,
                                        oauth_nonce, oauth_version, oauth_signature)
            return oauth_header, foundVariables
        elif auth_type == "oauth2":
            return "Bearer " + token, foundVariables
        else:
            if auth_type:
                raise ValueError("Unsupported auth type: " + auth_type)
            else:
                pass

    def replaceVariablesInAuth(self, value):
        environment_variables = self.getUrlList()
        match_pattern = r"{{.*}}"
        pattern = r"{{(.*)}}"

        if re.match(match_pattern, value):
            match = re.search(pattern, value)
            key = match.group(1)
            for var in environment_variables:
                if isinstance(var, dict) and var['key'] == key:
                    value = re.sub(value, var['value'], value)

        else:
            value = value

        return value

    def loadFile(self, event):
        chooseFile = swing.JFileChooser()
        fileDialog = chooseFile.showDialog(self.tab, "Choose file")

        if fileDialog == swing.JFileChooser.APPROVE_OPTION:
            self.file = chooseFile.getSelectedFile()
            filename = self.file.getCanonicalPath()
            fileExtension = os.path.splitext(filename)[1]

            if fileExtension == '.json':
                self.logArea.append(
                    '\nFile %s was successfully loaded \n' % filename)
            else:
                self.callbacks.printError('\nFile %s was read but does not have the correct extension (.json) \n'
                                          % filename)
                self.logArea.append(
                    '\nFile %s was read but does not have the correct extension (.json) \n' % filename)

    def addToSiteMap(self, url, request, response):
        request_response = HttpRequestResponse(request, response, HttpService(url), "", "")
        self.callbacks.addToSiteMap(request_response)

    def addRequestsToSiteMap(self, event):
        thread.start_new_thread(self.getRequestsFromPostman, ())
        return

    def getTabCaption(self):
        return "Postman Importer"

    def getUiComponent(self):
        return self.tab

    def getUrlList(self):
        model = self.urlList.getModel()
        currentList = []

        for i in range(0, model.getSize()):
            currentList.append(model.getElementAt(i))

        return currentList

    def clear(self, e):
        emptyList = []
        self.urlList.setListData(emptyList)

    def remove(self, e):
        indices = self.urlList.getSelectedIndices().tolist()
        currentList = self.getUrlList()

        for index in reversed(indices):
            del currentList[index]

        self.urlList.setListData(currentList)


class HttpService(IHttpService):
    def __init__(self, url):
        x = urlparse.urlparse(url)
        if x.scheme in ("http", "https"):
            self._protocol = x.scheme
        else:
            raise ValueError()
        self._host = x.hostname
        if not x.hostname:
            self._host = ""
        self._port = None
        if x.port:
            self._port = int(x.port)
        if not self._port:
            if self._protocol == "http":
                self._port = 80
            elif self._protocol == "https":
                self._port = 443

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

    def getProtocol(self):
        return self._protocol


class HttpRequestResponse(IHttpRequestResponse):

    def __init__(self, request, response, http_service, cmt, color):
        self.setRequest(request)
        self.setResponse(response)
        self.setHttpService(http_service)
        self.setHighlight(color)
        self.setComment(cmt)

    def getRequest(self):
        return self.req

    def getResponse(self):
        return self.resp

    def getHttpService(self):
        return self.serv

    def getComment(self):
        return self.cmt

    def getHighlight(self):
        return self.color

    def setHighlight(self, color):
        self.color = color

    def setComment(self, cmt):
        self.cmt = cmt

    def setHttpService(self, http_service):
        self.serv = http_service

    def setRequest(self, message):
        self.req = message

    def setResponse(self, message):
        self.resp = message
