import { ConfidentialAccount } from "@coti-io/coti-sdk-typescript"

function encodeString(str: string): Uint8Array {
    let encoder = new TextEncoder()

    return encoder.encode(str)
}

export async function encryptString(str: string, wallet: ConfidentialAccount, contractAddress: string, functionSelector: string) {
    let encodedStr = encodeString(str)

    let encryptedStr = new Array<{ ciphertext: bigint, signature: Buffer }>(str.length)

    for (let i = 0; i < str.length; i++) {
        const { ctInt, signature } = await wallet.encryptValue(encodedStr[i], contractAddress, functionSelector)
        encryptedStr[i] = { ciphertext: ctInt, signature }
    }

    return encryptedStr
}

function decodeString(encodedStr: Uint8Array) {
    let decoder = new TextDecoder()

    return decoder.decode(encodedStr)
}

export function decryptString(encryptedStr: Array<bigint>, wallet: ConfidentialAccount) {
    let decryptedStr = new Array<number>(encryptedStr.length)

    for (let i = 0; i < encryptedStr.length; i++) {
        decryptedStr[i] = wallet.decryptValue(encryptedStr[i])
    }

    return decodeString(new Uint8Array(decryptedStr))
}