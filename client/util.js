const { Buffer } = require('buffer');
const elliptic = require('elliptic');
const Secp256k1 = new elliptic.ec('secp256k1');
const { bigIntToUnpaddedBytes } = require('@ethereumjs/util');
const { Address } = require('ethereumjs-util');
const assert = require('assert');

function protoBuffToHexString(protobuff) {
    return Buffer.from(protobuff).toString('hex');
}

function hexStringToProtoBuff(hexString) {
    return Uint8Array.from(Buffer.from(hexString, 'hex'));
}

function getEoaFromPublicKey(uncompressedPublicKeyData) {
    const processedPubKey = Secp256k1.keyFromPublic(
        { x: uncompressedPublicKeyData.x, y: uncompressedPublicKeyData.y },
        'hex'
    );
    const pubKeyHex = processedPubKey.getPublic(false, 'hex');

    const eoa = Address.fromPublicKey(
        Buffer.from(pubKeyHex.slice(2), 'hex')
    ).toString();

    return eoa;
}

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

function getMessageToSign(txData) {
    const message = [
        bigIntToUnpaddedBytes(txData.nonce),
        bigIntToUnpaddedBytes(txData.gasPrice),
        bigIntToUnpaddedBytes(txData.gasLimit),
        txData.to,
        bigIntToUnpaddedBytes(txData.value),
        txData.data,
    ];
    return message;
}

function getMessageToSend(txData) {
    const message = [
        bigIntToUnpaddedBytes(txData.nonce),
        bigIntToUnpaddedBytes(txData.gasPrice),
        bigIntToUnpaddedBytes(txData.gasLimit),
        txData.to,
        bigIntToUnpaddedBytes(txData.value),
        txData.data,
        txData.v,
        txData.r,
        txData.s,
    ];
    return message;
}

module.exports = {
    protoBuffToHexString,
    hexStringToProtoBuff,
    getEoaFromPublicKey,
    recoverPubKey,
    getMessageToSign,
    getMessageToSend,
};
