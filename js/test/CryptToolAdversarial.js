'use strict';
const common = require('../common');
const fc = require('fast-check');

// reloads the jsdom environment and prepares the WebCrypto polyfill,
// same harness as the CryptTool suite
function setupCrypto() {
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
    return clean;
}

// flips one character of a base64 string at the given position to a
// different base64 alphabet character
function tamperBase64(encoded, position, offset) {
    // stay clear of the tail, where padding bits can leave the decoded
    // bytes unchanged
    const usable = Math.max(encoded.length - 4, 1);
    if (encoded.length === 0) return encoded;
    const i = position % usable,
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
        current = alphabet.indexOf(encoded[i]),
        next = alphabet[(Math.max(current, 0) + 1 + offset) % alphabet.length];
    return encoded.substring(0, i) + next + encoded.substring(i + 1);
}

describe('CryptTool adversarial', function () {
    this.timeout(60000);
    afterEach(async function () {
        // pause to let async functions conclude
        await new Promise(resolve => setTimeout(resolve, 1900));
    });

    it('rejects ciphertext with a single tampered character', async function () {
        await fc.assert(fc.asyncProperty(
            fc.string({minLength: 1}),
            common.fcAlnumString(),
            common.fcAlnumString(),
            fc.nat(),
            fc.integer({min: 0, max: 62}),
            async function (message, key, password, position, offset) {
                const clean = setupCrypto();
                message = message.trim();
                if (message === '') return true;
                const cipherMessage = await PrivateBin.CryptTool.cipher(key, password, message, []),
                    tampered = [tamperBase64(cipherMessage[0], position, offset), cipherMessage[1]],
                    plaintext = await PrivateBin.CryptTool.decipher(key, password, tampered);
                clean();
                // GCM authentication must prevent the original plaintext
                // from being recovered
                return plaintext !== message;
            }
        ), {numRuns: 5});
    });

    it('rejects truncated ciphertext', async function () {
        await fc.assert(fc.asyncProperty(
            fc.string({minLength: 8}),
            common.fcAlnumString(),
            fc.integer({min: 1, max: 8}),
            async function (message, key, cut) {
                const clean = setupCrypto();
                const cipherMessage = await PrivateBin.CryptTool.cipher(key, '', message, []),
                    truncated = [cipherMessage[0].substring(0, cut), cipherMessage[1]],
                    plaintext = await PrivateBin.CryptTool.decipher(key, '', truncated);
                clean();
                return plaintext !== message;
            }
        ), {numRuns: 3});
    });

    it('rejects decryption with a wrong password', async function () {
        await fc.assert(fc.asyncProperty(
            fc.string({minLength: 1}),
            common.fcAlnumString(),
            common.fcAlnumString(),
            common.fcAlnumString(),
            async function (message, key, password, wrongPassword) {
                fc.pre(password !== wrongPassword);
                const clean = setupCrypto();
                message = message.trim();
                if (message === '') return true;
                const cipherMessage = await PrivateBin.CryptTool.cipher(key, password, message, []),
                    plaintext = await PrivateBin.CryptTool.decipher(key, wrongPassword, cipherMessage);
                clean();
                return plaintext !== message;
            }
        ), {numRuns: 3});
    });

    it('rejects decryption with a wrong key', async function () {
        await fc.assert(fc.asyncProperty(
            fc.string({minLength: 1}),
            common.fcAlnumString(),
            common.fcAlnumString(),
            async function (message, key, wrongKey) {
                fc.pre(key !== wrongKey);
                const clean = setupCrypto();
                message = message.trim();
                if (message === '') return true;
                const cipherMessage = await PrivateBin.CryptTool.cipher(key, '', message, []),
                    plaintext = await PrivateBin.CryptTool.decipher(wrongKey, '', cipherMessage);
                clean();
                return plaintext !== message;
            }
        ), {numRuns: 3});
    });

    it('yields different ciphertext for identical input but equal plaintext', async function () {
        await fc.assert(fc.asyncProperty(
            fc.string({minLength: 1}),
            common.fcAlnumString(),
            async function (message, key) {
                const clean = setupCrypto();
                message = message.trim();
                if (message === '') return true;
                const first = await PrivateBin.CryptTool.cipher(key, '', message, []),
                    second = await PrivateBin.CryptTool.cipher(key, '', message, []),
                    firstPlain = await PrivateBin.CryptTool.decipher(key, '', first),
                    secondPlain = await PrivateBin.CryptTool.decipher(key, '', second);
                clean();
                // random IV and salt must make outputs differ while both
                // decrypt to the same message
                return first[0] !== second[0] && firstPlain === message && secondPlain === message;
            }
        ), {numRuns: 3});
    });

    it('decrypts identically across compression modes', async function () {
        await fc.assert(fc.asyncProperty(
            fc.string({minLength: 1}),
            common.fcAlnumString(),
            async function (message, key) {
                const clean = setupCrypto();
                message = message.trim();
                if (message === '') return true;
                document.body.dataset.compression = 'zlib';
                const compressed = await PrivateBin.CryptTool.cipher(key, '', message, []);
                document.body.dataset.compression = 'none';
                const raw = await PrivateBin.CryptTool.cipher(key, '', message, []),
                    compressedPlain = await PrivateBin.CryptTool.decipher(key, '', compressed),
                    rawPlain = await PrivateBin.CryptTool.decipher(key, '', raw);
                clean();
                return compressedPlain === message && rawPlain === message;
            }
        ), {numRuns: 3});
    });

    it('always emits the 8 field cipher specification', async function () {
        await fc.assert(fc.asyncProperty(
            fc.string(),
            common.fcAlnumString(),
            async function (message, key) {
                const clean = setupCrypto();
                const cipherMessage = await PrivateBin.CryptTool.cipher(key, '', message, []),
                    spec = cipherMessage[1][0] instanceof Array ? cipherMessage[1][0] : cipherMessage[1];
                clean();
                return cipherMessage[0].length > 0 &&
                    spec.length === 8 &&
                    spec[2] === 600000 &&
                    spec[3] === 256 &&
                    spec[4] === 128 &&
                    spec[5] === 'aes' &&
                    spec[6] === 'gcm';
            }
        ), {numRuns: 3});
    });
});
