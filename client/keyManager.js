const {
    TPCEcdsaKeyGen,
    TPCEcdsaSign,
} = require('@safeheron/two-party-ecdsa-js');
const axios = require('axios');
const config = require('./config');
const elliptic = require('elliptic');
const Secp256k1 = new elliptic.ec('secp256k1');
const assert = require('assert');
const BN = require('bn.js');
const endPointUrl = config.endPointUrl || 'http://127.0.0.1:3030';
const {
    protoBuffToHexString,
    hexStringToProtoBuff,
    recoverPubKey,
    getEoaFromPublicKey,
} = require('./util');

class KeyManager {
    userId; // 백엔드에서 생성된 키를 관리하기위한 목적의 id
    keyShare1;
    keyShare1JsonStr;
    EOA; // DKG를 통해 생성된 key에 대한 공개키로부터 도출해낸 EOA(사용자 이더리움 주소)이다.
    constructor(userId) {
        this.userId = userId;
    }

    // 서버측과 Key Gen Protocol을 수행하여 Key Share #1을 생성하고 저장한다. (서명 생성 및 검증 함수 호출 전에 반드시 호출되어야한다.)
    async init() {
        console.time('init');
        const p1KeyGenCtx = await TPCEcdsaKeyGen.P1Context.createContext();
        console.timeEnd('init');

        console.time('step1');
        const message1 = p1KeyGenCtx.step1();
        console.timeEnd('step1');
        const baseEndPoint = endPointUrl + '/api/v1/keygen';

        let res;
        res = await axios.put(baseEndPoint + '/step1', {
            userId: this.userId,
            message1: protoBuffToHexString(message1),
        });

        const message2 = hexStringToProtoBuff(res.data.result);
        console.log('received message 2');
        // console.log('receive message 2 : ', res.data.result);

        const message3 = p1KeyGenCtx.step2(message2);

        res = await axios.put(baseEndPoint + '/step2', {
            userId: this.userId,
            message3: protoBuffToHexString(message3),
        });

        const keyShare1 = p1KeyGenCtx.exportKeyShare();

        this.keyShare1 = keyShare1;
        this.keyShare1JsonStr = JSON.stringify(
            keyShare1.toJsonObject(),
            null,
            4
        );
        this.EOA = getEoaFromPublicKey(keyShare1.Q);
    }

    async sign(messageHash) {
        assert(this.keyShare1JsonStr, 'you must call init function first.');
        const p1SignCtx = await TPCEcdsaSign.P1Context.createContext(
            this.keyShare1JsonStr,
            new BN(messageHash, 'hex')
        );

        console.time('step1');
        const message1 = p1SignCtx.step1();
        console.timeEnd('step1');
        const baseEndPoint = endPointUrl + '/api/v1/sign';

        //console.log('message1 : ', protoBuffToHexString(message1));

        let res;
        res = await axios.put(baseEndPoint + '/step1', {
            userId: this.userId,
            message: messageHash,
            message1: protoBuffToHexString(message1),
        });
        console.log('received message 2');
        //console.log('received message 2 : ', res.data.result);
        const message2 = hexStringToProtoBuff(res.data.result);

        console.time('step2');
        const message3 = p1SignCtx.step2(message2);
        console.timeEnd('step2');

        //console.log('message3 :', protoBuffToHexString(message3));

        res = await axios.put(baseEndPoint + '/step2', {
            userId: this.userId,
            message3: protoBuffToHexString(message3),
        });
        console.log('received message 4');
        //console.log('receive message 4 : ', res.data.result);
        const message4 = hexStringToProtoBuff(res.data.result);

        p1SignCtx.step3(message4);

        let [r, s, v] = p1SignCtx.exportSig();
        return {
            r,
            s,
            v,
        };
    }

    verify(messageHash, r, s, v) {
        assert(this.keyShare1, 'you must call init function first.');
        let pub0 = recoverPubKey(
            messageHash,
            r.umod(Secp256k1.n),
            s.umod(Secp256k1.n),
            v
        );
        return pub0.eq(this.keyShare1.Q);
    }
}

module.exports = KeyManager;
