const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');

const port = 3000;

const options = {
    ca: fs.readFileSync(path.resolve(__dirname, './certs/ca.crt')),
    cert: fs.readFileSync(path.resolve(__dirname, './certs/server.crt')),
    key: fs.readFileSync(path.resolve(__dirname, './certs/server.key')),
    certs: ['ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384', 'DHE-RSA-AES128-GCM-SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'],
    rejectUnauthorized: false,
    requestCert: true,
};

const app = express();

app.get('/', (req, res) => {
    // console.log(`req`, req)
    console.log(`req.socket`, req.socket)
    // console.log(`req.headers`, req.headers)
    // console.log('getPeerCertificate', req.socket.getPeerCertificate())

    if (!isEmpty(req.socket.getPeerCertificate())) {
        return verify_certificate(req, res);
    }

    if (req.header("ssl_client_verify") !== "SUCCESS")
        return res.status(403).send("Forbidden - please provide valid certificate.")

    res
        .status(200)
        .json(req.headers);
});

https
    .createServer(options, app)
    .listen(port, () => {
        console.log(`.. server up and running and listening on ${port} ..`);
    });

function verify_certificate(request, response) {
    const cert = request.socket.getPeerCertificate();
    console.log(`verify`, request.client);
    console.log(`cert`, cert);

    if (request.client.authorized) {
        return response.send(`Hello ${cert.subject.CN}, your certificate was issued by ${cert.issuer.CN}!`);
    }

    if (cert.subject) {
        return response.status(403).send(`Sorry ${cert.subject.CN}, certificates from ${cert.issuer.CN} are not welcome here.`);

    } else {
        return response.status(401).send(`Sorry, but you need to provide a client certificate to continue.`);
    }
}

function isEmpty(obj) {
    for (var key in obj) {
        if (obj.hasOwnProperty(key))
            return false;
    }
    return true;
}