document.addEventListener("DOMContentLoaded", () => {
    const inputText = document.getElementById("inputText");
    const inputKey = document.getElementById("inputKey");
    const resultText = document.getElementById("resultText");

    const encryptBtn = document.getElementById("encryptBtn");
    const decryptBtn = document.getElementById("decryptBtn");

    encryptBtn.addEventListener("click", () => {
        const text = inputText.value;
        const key = inputKey.value;

        if (!key) {
            alert("Введите ключ");
            return;
        }

        if (!text) {
            alert("Введите текст для зашифровки");
            return;
        }

        const cipherHex = encryptText(text, key);
        resultText.value = cipherHex;
    });

    decryptBtn.addEventListener("click", () => {
        const cipherHex = inputText.value.trim();
        const key = inputKey.value;

        if (!key) {
            alert("Введите ключ");
            return;
        }
        if (!cipherHex) {
            alert("Введите текст для расшифровки");
            return;
        }

        const plainText = decryptText(cipherHex, key);
        resultText.value = plainText;
    });
});


const BLOCK_SIZE = 16;

function encryptText(text, key) {
    const encoder = new TextEncoder();
    const textBytes = encoder.encode(text);

    const len = textBytes.length;
    const header = new Uint8Array(4);
    header[0] = (len >>> 24) & 0xff;
    header[1] = (len >>> 16) & 0xff;
    header[2] = (len >>> 8) & 0xff;
    header[3] = len & 0xff;

    const dataWithLen = new Uint8Array(header.length + textBytes.length);
    dataWithLen.set(header, 0);
    dataWithLen.set(textBytes, header.length);


    const paddedLength = Math.ceil(dataWithLen.length / BLOCK_SIZE) * BLOCK_SIZE;
    const padded = new Uint8Array(paddedLength);
    padded.set(dataWithLen, 0);

    const keyBytes = deriveKeyBytes(key, BLOCK_SIZE);

    for (let offset = 0; offset < padded.length; offset += BLOCK_SIZE) {
        encryptBlock(padded, offset, keyBytes);
    }

    return bytesToHex(padded);
}

function decryptText(cipherHex, key) {
    const cipherBytes = hexToBytes(cipherHex);

    if (cipherBytes.length % BLOCK_SIZE !== 0) {
        throw new Error("Длина данных не кратна размеру блока");
    }

    const keyBytes = deriveKeyBytes(key, BLOCK_SIZE);

    for (let offset = 0; offset < cipherBytes.length; offset += BLOCK_SIZE) {
        decryptBlock(cipherBytes, offset, keyBytes);
    }

    const len =
        (cipherBytes[0] << 24) |
        (cipherBytes[1] << 16) |
        (cipherBytes[2] << 8) |
        (cipherBytes[3]);

    if (len < 0 || len > cipherBytes.length - 4) {
        throw new Error("Некорректная длина исходного текста");
    }

    const plainBytes = cipherBytes.slice(4, 4 + len);
    const decoder = new TextDecoder();
    return decoder.decode(plainBytes);
}

function deriveKeyBytes(key, size) {
    const encoder = new TextEncoder();
    const keyBase = encoder.encode(key);

    if (keyBase.length === 0) {
        throw new Error("Пустой ключ");
    }

    const keyBytes = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
        keyBytes[i] = keyBase[i % keyBase.length];
    }
    return keyBytes;
}

function encryptBlock(data, offset, keyBytes) {
    for (let i = 0; i < BLOCK_SIZE; i++) {
        const idx = offset + i;
        const b = data[idx];
        const k = keyBytes[i];
        data[idx] = ((b ^ k) + i) & 0xff;
    }
}

function decryptBlock(data, offset, keyBytes) {
    for (let i = 0; i < BLOCK_SIZE; i++) {
        const idx = offset + i;
        const c = data[idx];
        const k = keyBytes[i];
        const b = (c - i);
        data[idx] = (b < 0 ? b + 256 : b) ^ k;
    }
}

function bytesToHex(bytes) {
    const hex = [];
    for (let i = 0; i < bytes.length; i++) {
        const h = bytes[i].toString(16).padStart(2, "0");
        hex.push(h);
    }
    return hex.join("");
}

function hexToBytes(hex) {
    if (hex.length % 2 !== 0) {
        throw new Error("Нечётная длина hex-строки");
    }
    const len = hex.length / 2;
    const bytes = new Uint8Array(len);

    for (let i = 0; i < len; i++) {
        const byteStr = hex.substr(i * 2, 2);
        const value = parseInt(byteStr, 16);
        if (Number.isNaN(value)) {
            throw new Error("Некорректный символ в hex-строке");
        }
        bytes[i] = value;
    }
    return bytes;
}