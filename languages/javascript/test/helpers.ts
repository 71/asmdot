
export function arrayBufferToArray(buffer: ArrayBuffer): Array<number> {
    return Array.prototype.slice.call(new Uint8Array(buffer));
}
