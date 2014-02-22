# Dependencies

 * Node http://nodejs.org/download/
 * Grunt ```npm install -g grunt-cli```
 * Node deps ```npm install```

# Notes
* Debugging:
 * Use node-inspector
 * ```node-inspector --web-port=8081```

* Debug grunt: 
 * Run ```node --debug-brk C:\Users\{username}\AppData\Roaming\npm\node_modules\grunt-cli\bin\grunt```

* Working on documentation:
 * Make edits
 * run ```grunt sitePages```
 * If you want to run the full distribution (i.e. you're developing scripts and want to update the site), run ```grunt site``` (takes longer)
 * Processed pages are updated in /site/_site
 * Point a local web server to this directory to test
