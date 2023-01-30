<h1>Postman Importer Burp Suite extension</h1>

This Burp extension allows users to import all requests and add them to the site map from Postman collection, which user specified.

To import requests user needs to export collection using .json file and select it using Burp extension.

Some requests in Postman contain Environment variables in url and body. If you put this variables dependent on some 
pre-requests scripts. You can put such variables directly into the extension using specific input fields.   

Extension provide UI(new Tab) in the Burp. There users can see quick guide how to use it and
input fields where they can put necessary values about Postman collection and it's environment variables.

This Burp extension uses Jython 2.7