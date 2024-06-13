require('dotenv').config();

module.exports = {
    endPointUrl: process.env.ENDPOINT_URL,
    ethereumRpcUrl: process.env.RPC_URL,
};
