const express = require('express');
const cors = require('cors');

const config = require('./config/config');
const router = require('./routes');

const app = express();
const port = config.port || 3030;

// Mounts the specified middleware function or functions at the specified path:

// the middleware function is executed when the base of the requested path matches path.
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
    const userId = req.body.userId;
    if (!userId) {
        res.status(400).send({
            error: 'userId must be included in the request body',
        });
    } else {
        next();
    }
});

app.use('/api/v1', router);

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});

module.exports = app;
