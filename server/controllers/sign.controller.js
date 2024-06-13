const { TPCEcdsaSign } = require('@safeheron/two-party-ecdsa-js');
const memoryStore = require('../store');
const BN = require('bn.js');

function protoBuffToHexString(protobuff) {
    return Buffer.from(protobuff).toString('hex');
}

function hexStringToProtoBuff(hexString) {
    return Uint8Array.from(Buffer.from(hexString, 'hex'));
}

const signStep1 = async (req, res) => {
    const userId = req.body.userId;
    const keyShare2JsonStr = memoryStore[userId]['keyShare2JsonStr'];

    if (!keyShare2JsonStr) {
        res.status(400).send({
            error: 'you must generate the keys first',
        });
    } else {
        const message = req.body.message;
        let m = new BN(message, 'hex');

        const keyShare2 = JSON.parse(keyShare2JsonStr);

        console.dir(keyShare2);

        console.time('createContext');
        let p2SignCtx = await TPCEcdsaSign.P2Context.createContext(
            keyShare2JsonStr,
            m
        );
        console.timeEnd('createContext');

        console.log('received message1 : ', req.body.message1);
        const message1 = hexStringToProtoBuff(req.body.message1);

        console.time('step1');
        const message2 = p2SignCtx.step1(message1);
        console.timeEnd('step1');

        memoryStore[userId] = {};
        memoryStore[userId]['p2SignCtx'] = p2SignCtx;

        const result = protoBuffToHexString(message2);
        console.log('message 2 : ', result);

        res.status(200).json({ result: result });
    }
};

const signStep2 = async (req, res) => {
    const userId = req.body.userId;
    const message3 = hexStringToProtoBuff(req.body.message3);

    console.log('received message3 : ', req.body.message3);

    p2SignCtx = memoryStore[userId]['p2SignCtx'];

    console.time('step3');
    const message4 = p2SignCtx.step2(message3);
    console.timeEnd('step3');

    // const result = p2Ctx.message4;
    const result = protoBuffToHexString(message4);
    console.log('message 4 : ', result);

    res.status(200).json({
        result: result,
    });
};

module.exports = {
    signStep1,
    signStep2,
};
