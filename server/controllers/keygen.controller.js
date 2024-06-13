const { TPCEcdsaKeyGen } = require('@safeheron/two-party-ecdsa-js');
const memoryStore = require('../store');

function protoBuffToHexString(protobuff) {
    return Buffer.from(protobuff).toString('hex');
}

function hexStringToProtoBuff(hexString) {
    return Uint8Array.from(Buffer.from(hexString, 'hex'));
}

const keygenStep1 = async (req, res) => {
    const userId = req.body.userId;
    const message1 = hexStringToProtoBuff(req.body.message1);
    memoryStore[userId] = {};
    console.time('init');
    let p2KeyGenCtx = await TPCEcdsaKeyGen.P2Context.createContext();
    console.timeEnd('init');
    memoryStore[userId]['p2KeyGenCtx'] = p2KeyGenCtx;

    console.time('step1');
    // console.dir(JSON.parse(message1));
    let message2 = p2KeyGenCtx.step1(message1);
    console.timeEnd('step1');

    message2 = protoBuffToHexString(message2);
    console.log('message 2 : ', message2);

    res.status(200).json({ result: message2 });
};

const keygenStep2 = async (req, res) => {
    const userId = req.body.userId;
    const message3 = hexStringToProtoBuff(req.body.message3);

    p2KeyGenCtx = memoryStore[userId]['p2KeyGenCtx'];

    console.time('step3');
    p2KeyGenCtx.step2(message3);

    console.timeEnd('step3');

    let keyShare2 = p2KeyGenCtx.exportKeyShare();
    let keyShare2JsonStr = JSON.stringify(keyShare2.toJsonObject(), null, 4);
    console.log('key share 2: \n', keyShare2JsonStr);
    memoryStore[userId]['keyShare2JsonStr'] = keyShare2JsonStr;

    res.sendStatus(200);
};

module.exports = {
    keygenStep1,
    keygenStep2,
};
