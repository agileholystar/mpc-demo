const { select, input } = require('@inquirer/prompts');
const BN = require('bn.js');
const { Buffer } = require('buffer');
const { keccak256 } = require('ethereumjs-util');
const { Web3 } = require('web3');
const config = require('./config');
const web3 = new Web3(config.ethereumRpcUrl || 'http://127.0.0.1:7545');
const { RLP } = require('@ethereumjs/rlp');
const { createHash } = require('crypto');
const KeyManager = require('./keyManager');
const { getMessageToSign, getMessageToSend } = require('./util');

async function main() {
    const userId = await input({ message: 'Enter your ID to login' });

    // MPC 기반 키 생성 및 서명 검증을 위한 객체 생성
    const keyManager = new KeyManager(userId);

    // 필수적인 작업인 초기화 함수 호출
    await keyManager.init();
    // 연결된 이더리움 노드에 등록된 EOA들을 조회한다.
    const accounts = await web3.eth.getAccounts();
    let signature; // 이더리움과 상관없는 테스트에 사용될 서명 저장 변수
    console.log('Your EOA : ', keyManager.EOA);

    while (true) {
        const answer = await select({
            message: 'Select a package manager',
            choices: [
                {
                    name: 'sign',
                    value: 'sign',
                    description: 'generate your signature',
                },
                {
                    name: 'verify',
                    value: 'verify',
                    description: 'verify your input signature',
                },
                {
                    name: 'send_tx',
                    value: 'send_tx',
                    description:
                        'send your ethereum tx(ERC20-mint) to local ethereum network',
                },
                {
                    name: 'get_ether',
                    value: 'get_ether',
                    description:
                        'Receive some ether for free from the Ethereum local testnet',
                },
            ],
        });
        console.log('your answer : ', answer);

        switch (answer) {
            // 임의의 문자열 기반 데이터를 입력받아서 그것에 대해 서명을 생성한다.
            case 'sign':
                const inputMessage = await input({
                    message: 'Entter a message(string) to be signed.',
                });

                hashedMessage = createHash('sha256')
                    .update(inputMessage)
                    .digest('hex');

                signature = await keyManager.sign(hashedMessage);

                console.log('r: \n', signature.r.toString(16));
                console.log('s: \n', signature.s.toString(16));
                console.log('v: \n', signature.v);

                break;

            // 'sign'을 통해 생성된 서명을 검증한다.
            case 'verify':
                const m = new BN(hashedMessage, 'hex');
                try {
                    const verifyResult = await keyManager.verify(
                        m,
                        signature.r,
                        signature.s,
                        signature.v
                    );
                    console.log('verifyResult :', verifyResult);
                } catch (e) {
                    console.log(e);
                    console.log('invalid signature');
                }
                break;

            // 테스트를 위해 연결된 네트워크의 관리자 계정으로부터 MPC 기반으로 생성된 EOA에 1 Ether를 채운다.
            case 'get_ether':
                await web3.eth.sendTransaction({
                    to: keyManager.EOA,
                    from: accounts[0],
                    value: web3.utils.toWei('1', 'ether'),
                    // value: BigInt(100),
                    gasPrice: BigInt(200),
                });
                break;
            // 연결된 네트워크에 MPC 기반으로 생성된 EOA로부터 관리자 계정으로 1 Ether를 송금한다.
            case 'send_tx':
                // Legacy Transaction을 기준으로 한 트랜잭션을 만든다. (연동되는 이더리움 네트워크의 하드포크는 Muir Glacier를 권장)
                // 다른 타입의 트랜잭션의 경우엔 별도로 수정 및 추가구현이 필요함.
                const rawTx = {
                    from: keyManager.EOA,
                    gasPrice: BigInt(0),
                    gasLimit: BigInt(100000),
                    gas: BigInt(21000),
                    to: accounts[0],
                    value: BigInt(web3.utils.toWei('1', 'ether')),
                    //value: BigInt(BigInt(1)),
                    data: new Uint8Array(0),
                    nonce: BigInt(0),
                };

                const serialized = RLP.encode(getMessageToSign(rawTx));

                const transactionDataHash = keccak256(
                    Buffer.from(serialized)
                ).toString('hex');

                let txSignature = await keyManager.sign(transactionDataHash);
                txSignature.v += 27;
                rawTx.r = '0x' + txSignature.r.toString(16);
                rawTx.s = '0x' + txSignature.s.toString(16);
                rawTx.v = '0x' + txSignature.v.toString(16);

                // console.dir(rawTx);

                transactionReceipt = await web3.eth.sendSignedTransaction(
                    // 서명이 완료된 Raw Transaction을 Serialize하여 이더리움 네트워크에 전송한다.
                    RLP.encode(getMessageToSend(rawTx))
                );
                console.dir(transactionReceipt);

                break;
            default:
                return;
        }
    }
}
main();
