'use strict';
const common = require('../common');
const fc = require('fast-check');
const fs = require('fs');

describe('CryptTool', function () {
    describe('cipher & decipher', function () {
        afterEach(async function () {
            // pause to let async functions conclude
            await new Promise(resolve => setTimeout(resolve, 1900));
        });

        this.timeout(30000);
        it('can en- and decrypt any message', async function () {
            await fc.assert(fc.asyncProperty(
                fc.string(),
                fc.string(),
                fc.string(),
                async function (key, password, message) {
                    const clean = globalThis.cleanup();
                    // ensure zlib is getting loaded
                    PrivateBin.Controller.initZlib();
                    Object.defineProperty(window, 'crypto', {
                        value: new WebCrypto(),
                        configurable: true,
                        enumerable: true,
                        writable: false
                    });
                    global.atob = common.atob;
                    global.btoa = common.btoa;
                    message = message.trim();
                    const cipherMessage = await PrivateBin.CryptTool.cipher(
                            key, password, message, []
                        ),
                        plaintext = await PrivateBin.CryptTool.decipher(
                            key, password, cipherMessage
                        );
                    clean();
                    const result = (message === plaintext);
                    if (!result) console.log(plaintext, cipherMessage);
                    return result;
                }
            ),
            {numRuns: 3});
        });

        it('does not truncate messages', async function () {
            const message = fs.readFileSync('test/compression-sample.txt', 'ascii').trim(),
                clean = globalThis.cleanup();
            Object.defineProperty(window, 'crypto', {
                value: new WebCrypto(),
                configurable: true,
                enumerable: true,
                writable: false
            });
            // ensure zlib is getting loaded
            PrivateBin.Controller.initZlib();
            global.atob = common.atob;
            global.btoa = common.btoa;
            const cipherMessage = await PrivateBin.CryptTool.cipher(
                    'foo', 'bar', message, []
                ),
                plaintext = await PrivateBin.CryptTool.decipher(
                    'foo', 'bar', cipherMessage
                );
            clean();
            if (message !== plaintext) {
                console.log(plaintext, cipherMessage);
            }
            assert.strictEqual(message, plaintext);
        });

        it('can en- and decrypt a particular message (#260)', async function () {
            await fc.assert(fc.asyncProperty(
                fc.string(),
                fc.string(),
                async function (key, password) {
                    const message = `
1 subgoal

inv : Assert
expr : Expr
sBody : Instr
deduction : (|- [|inv /\ assertOfExpr expr|] sBody [|inv|])%assert
IHdeduction : (|= [|inv /\ assertOfExpr expr |] sBody [|inv|])%assert
mem : Mem
preInMem : inv mem
m : Mem
n : nat
interpRel : interp (nth_iterate sBody n) (MemElem mem) = CpoElem Mem m
lastIter : interp (nth_iterate sBody n) (MemElem mem) |=e expr_neg expr
notLastIter : forall p : nat,
              p < n -> interp (nth_iterate sBody p) (MemElem mem) |=e expr
isWhile : interp (while expr sBody) (MemElem mem) =
          interp (nth_iterate sBody n) (MemElem mem)

======================== ( 1 / 1 )
conseq_or_bottom inv (interp (nth_iterate sBody n) (MemElem mem))
`;
                    const clean = globalThis.cleanup();
                    // ensure zlib is getting loaded
                    PrivateBin.Controller.initZlib();
                    Object.defineProperty(window, 'crypto', {
                        value: new WebCrypto(),
                        configurable: true,
                        enumerable: true,
                        writable: false
                    });
                    global.atob = common.atob;
                    global.btoa = common.btoa;
                    const cipherMessage = await PrivateBin.CryptTool.cipher(
                            key, password, message, []
                        ),
                        plaintext = await PrivateBin.CryptTool.decipher(
                                key, password, cipherMessage
                        );
                    clean();
                    const result = (message === plaintext);
                    if (!result) console.log(plaintext, cipherMessage);
                    return result;
                }
            ),
            {numRuns: 3});
        });
    });

    describe('getSymmetricKey', function () {
        this.timeout(10000);
        let keys = [];

        // the parameter is used to ensure the test is run more then one time
        it('returns random, non-empty keys', () => {
            fc.assert(fc.property(
                fc.integer(),
                function() {
                    const clean = globalThis.cleanup();
                    Object.defineProperty(window, 'crypto', {
                        value: new WebCrypto(),
                        configurable: true,
                        enumerable: true,
                        writable: false
                    });
                    const key = PrivateBin.CryptTool.getSymmetricKey(),
                        result = (key !== '' && keys.indexOf(key) === -1);
                    keys.push(key);
                    clean();
                    return result;
                }
            ),
            {numRuns: 10});
        });
    });

    describe('getShortCode', function () {
        this.timeout(10000);
        let codes = [];

        it('returns unique 10 character Crockford base32 codes', () => {
            fc.assert(fc.property(
                fc.integer(),
                function() {
                    const clean = globalThis.cleanup();
                    Object.defineProperty(window, 'crypto', {
                        value: new WebCrypto(),
                        configurable: true,
                        enumerable: true,
                        writable: false
                    });
                    const code = PrivateBin.CryptTool.getShortCode(),
                        result = /^[0-9a-hjkmnp-tv-z]{10}$/.test(code) &&
                            codes.indexOf(code) === -1;
                    codes.push(code);
                    clean();
                    return result;
                }
            ),
            {numRuns: 20});
        });
    });

    describe('short code key handling', function () {
        afterEach(async function () {
            await new Promise(resolve => setTimeout(resolve, 1900));
        });
        this.timeout(30000);

        it('roundtrips a message with a short code as key', async function () {
            const clean = globalThis.cleanup();
            PrivateBin.Controller.initZlib();
            Object.defineProperty(window, 'crypto', {
                value: new WebCrypto(),
                configurable: true,
                enumerable: true,
                writable: false
            });
            global.atob = common.atob;
            global.btoa = common.btoa;
            const code = PrivateBin.CryptTool.getShortCode(),
                message = 'short link roundtrip test',
                cipherMessage = await PrivateBin.CryptTool.cipher(code, '', message, []),
                plaintext = await PrivateBin.CryptTool.decipher(code, '', cipherMessage);
            clean();
            assert.strictEqual(message, plaintext);
        });

        it('rejects a different short code', async function () {
            const clean = globalThis.cleanup();
            PrivateBin.Controller.initZlib();
            Object.defineProperty(window, 'crypto', {
                value: new WebCrypto(),
                configurable: true,
                enumerable: true,
                writable: false
            });
            global.atob = common.atob;
            global.btoa = common.btoa;
            let code = PrivateBin.CryptTool.getShortCode(),
                wrongCode = PrivateBin.CryptTool.getShortCode();
            while (wrongCode === code) {
                wrongCode = PrivateBin.CryptTool.getShortCode();
            }
            const cipherMessage = await PrivateBin.CryptTool.cipher(code, '', 'secret', []),
                plaintext = await PrivateBin.CryptTool.decipher(wrongCode, '', cipherMessage);
            clean();
            assert.strictEqual('', plaintext);
        });
    });
});
