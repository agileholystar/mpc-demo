const axios = require('axios');
const { createHash } = require('crypto');
const config = require('./config');
const {
    TPCEcdsaKeyGen,
    TPCEcdsaSign,
} = require('@safeheron/two-party-ecdsa-js');
const { select, input } = require('@inquirer/prompts');
const endPointUrl = config.endPointUrl || 'http://127.0.0.1:3030';
console.log('END_POINT_URL : ', endPointUrl);
const BN = require('bn.js');
const elliptic = require('elliptic');
const Secp256k1 = new elliptic.ec('secp256k1');
const assert = require('assert');
let message;

let keyShare1JsonStr;
let global_r;
let global_s;
let global_v;
let p1KeyGenCtx;
let p1SignCtx;
let keyShare1;
function recoverPubKey(msg, r, s, j) {
    //if ((3 & j) === j) throw 'The recovery param is more than two bits';
    assert((3 & j) === j, 'The recovery param is more than two bits');

    var n = Secp256k1.n;
    var e = msg;

    // A set LSB signifies that the y-coordinate is odd
    var isYOdd = j & 1;
    var isSecondKey = j >> 1;
    if (r.cmp(Secp256k1.curve.p.umod(Secp256k1.n)) >= 0 && isSecondKey)
        throw 'Unable to find sencond key candinate';

    // 1.1. Let x = r + jn.
    let x = undefined;
    if (isSecondKey) x = Secp256k1.curve.pointFromX(r.add(Secp256k1.n), isYOdd);
    else x = Secp256k1.curve.pointFromX(r, isYOdd);

    var rInv = r.invm(n);
    var s1 = n.sub(e).mul(rInv).umod(n);
    var s2 = s.mul(rInv).umod(n);

    // 1.6.1 Compute Q = r^-1 (sR -  eG)
    //               Q = r^-1 (sR + -eG)
    return Secp256k1.g.mulAdd(s1, x, s2);
}

function verifySig(message_to_sign, r, s, v, pub) {
    let pub0 = recoverPubKey(
        message_to_sign,
        r.umod(Secp256k1.n),
        s.umod(Secp256k1.n),
        v
    );
    return pub0.eq(pub);
}

function protoBuffToHexString(protobuff) {
    return Buffer.from(protobuff).toString('hex');
}

function hexStringToProtoBuff(hexString) {
    return Uint8Array.from(Buffer.from(hexString, 'hex'));
}

async function main() {
    const userId = await input({ message: 'Enter your ID to login' });

    while (true) {
        const answer = await select({
            message: 'Select a package manager',
            choices: [
                {
                    name: 'keygen',
                    value: 'keygen',
                    description: 'generate your distributed key via DKG',
                },
                {
                    name: 'sign',
                    value: 'sign',
                    description: 'generate your sign via your keys',
                },
                {
                    name: 'verify',
                    value: 'verify',
                    description: 'verify your input signature',
                },
                {
                    name: 'send_tx',
                    value: 'send_Tx',
                    description:
                        'send your ethereum tx(ERC20-mint) to local ethereum network',
                },
            ],
        });

        switch (answer) {
            case 'keygen':
                console.time('init');
                p1KeyGenCtx = await TPCEcdsaKeyGen.P1Context.createContext();
                console.timeEnd('init');

                console.time('step1');
                const message1 = p1KeyGenCtx.step1();
                console.timeEnd('step1');
                const baseEndPoint = endPointUrl + '/api/v1/keygen';

                let res;
                res = await axios.put(baseEndPoint + '/step1', {
                    userId,
                    message1: protoBuffToHexString(message1),
                });

                const message2 = hexStringToProtoBuff(res.data.result);
                console.log('receive message 2 : ', res.data.result);

                const message3 = p1KeyGenCtx.step2(message2);

                res = await axios.put(baseEndPoint + '/step2', {
                    userId,
                    message3: protoBuffToHexString(message3),
                });

                keyShare1 = p1KeyGenCtx.exportKeyShare();
                keyShare1JsonStr = JSON.stringify(
                    keyShare1.toJsonObject(),
                    null,
                    4
                );
                console.log('key share 1: \n', keyShare1JsonStr);

                break;
            case 'sign':
                if (!keyShare1JsonStr) {
                    console.log('you have not keyShare yet!');
                } else {
                    const jsonData = require('./' + config.inputFileName);

                    message = createHash('sha256')
                        .update(jsonData.message)
                        .digest('hex');

                    p1SignCtx = await TPCEcdsaSign.P1Context.createContext(
                        keyShare1JsonStr,
                        new BN(message, 'hex')
                    );
                    console.time('step1');
                    const message1 = p1SignCtx.step1();
                    console.timeEnd('step1');
                    const baseEndPoint = endPointUrl + '/api/v1/sign';

                    console.log('message1 : ', protoBuffToHexString(message1));

                    let res;
                    res = await axios.put(baseEndPoint + '/step1', {
                        userId,
                        message: message,
                        message1: protoBuffToHexString(message1),
                    });

                    console.log('received message 2 : ', res.data.result);
                    const message2 = hexStringToProtoBuff(res.data.result);

                    console.time('step2');
                    const message3 = p1SignCtx.step2(message2);
                    console.timeEnd('step2');

                    console.log('message3 :', protoBuffToHexString(message3));

                    res = await axios.put(baseEndPoint + '/step2', {
                        userId,
                        message3: protoBuffToHexString(message3),
                    });

                    console.log('receive message 4 : ', res.data.result);
                    const message4 = hexStringToProtoBuff(res.data.result);

                    p1SignCtx.step3(message4);

                    let [r, s, v] = p1SignCtx.exportSig();
                    console.log('r: \n', r.toString(16));
                    console.log('s: \n', s.toString(16));
                    console.log('v: \n', v);
                }
                break;
            case 'verify':
                try {
                    const parsedKey = JSON.parse(keyShare1JsonStr);

                    const jsonData = require('./' + config.inputFileName);

                    const m = new BN(message, 'hex');
                    console.log('my message :', message);
                    console.log('keyshare Q :', parsedKey.Q);
                    let [r, s, v] = p1SignCtx.exportSig();
                    console.log('r: \n', r.toString(16));
                    console.log('s: \n', s.toString(16));
                    console.log('v: \n', v);
                    console.log(verifySig(m, r, s, v, keyShare1.Q));
                } catch (e) {
                    console.log(e);
                    console.log('invalid signature');
                }

                break;
            case 'send_tx':
                console.log('send_tx is not implemented yet!');
                break;
            default:
                return;
        }
    }
}
main();
