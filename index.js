require('dotenv').config();
require('./src/database');
require('./src/mongoDb');

const errorHandler = require('./src/error/errorHandler');

const express = require('express');
const routes = require('./src/routes');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api', routes);

app.use(errorHandler);

app.listen(3000,
  () => console.log('server listening to port 3000'));