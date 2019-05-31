const express = require('express');
const log4js = require('log4js');

const logger = log4js.getLogger('istio-sample-app');
logger.level = process.env['LOG_LEVEL'] || 'trace';

const app = express();

app.get('/web/home', (req, res) => {
	return res.status(200).send(req.headers)
});

app.get('/web/home2', (req, res) => {
	return res.status(200).send(req.headers)
});

app.get('/api/headers', (req, res) => {
	return res.status(200).send(req.headers)
});

app.get('/api/headers/2', (req, res) => {
	return res.status(200).send(req.headers)
});

app.listen(8000, () => {
	logger.info('Listening on port 8000');
});
