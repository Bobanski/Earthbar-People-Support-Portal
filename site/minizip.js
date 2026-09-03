// Minimal ZIP writer — STORE method only (no compression), proper CRC-32.
// Hand-rolled so the case export needs no external library/CDN (the portal is
// a static GitHub Pages app). Produces a standard ZIP readable by Windows
// Explorer: local file headers + central directory + end-of-central-directory.
// Case exports are small (HTML/text/JSON), so skipping DEFLATE costs nothing.

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(bytes) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

// files: [{ name: "path/in/zip.txt", data: string | Uint8Array }]
// returns a Uint8Array of the complete .zip
export function makeZip(files) {
  const enc = new TextEncoder();
  const d = new Date();
  const dosTime = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
  const dosDate = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  const chunks = [], central = [];
  let offset = 0;

  const hdr = (size, fill) => {   // little-endian struct writer
    const b = new Uint8Array(size), v = new DataView(b.buffer);
    fill({ u16: (o, x) => v.setUint16(o, x, true), u32: (o, x) => v.setUint32(o, x, true) });
    return b;
  };

  for (const f of files) {
    const name = enc.encode(f.name);
    const data = typeof f.data === "string" ? enc.encode(f.data) : f.data;
    const crc = crc32(data);
    // local file header: sig, ver 2.0, flags bit11 (UTF-8 names), method 0=STORE
    chunks.push(hdr(30, w => { w.u32(0, 0x04034b50); w.u16(4, 20); w.u16(6, 0x0800); w.u16(8, 0);
      w.u16(10, dosTime); w.u16(12, dosDate); w.u32(14, crc); w.u32(18, data.length);
      w.u32(22, data.length); w.u16(26, name.length); w.u16(28, 0); }), name, data);
    central.push(hdr(46, w => { w.u32(0, 0x02014b50); w.u16(4, 20); w.u16(6, 20); w.u16(8, 0x0800);
      w.u16(10, 0); w.u16(12, dosTime); w.u16(14, dosDate); w.u32(16, crc); w.u32(20, data.length);
      w.u32(24, data.length); w.u16(28, name.length); w.u32(42, offset); }), name);
    offset += 30 + name.length + data.length;
  }

  const centralSize = central.reduce((s, b) => s + b.length, 0);
  const eocd = hdr(22, w => { w.u32(0, 0x06054b50); w.u16(8, files.length); w.u16(10, files.length);
    w.u32(12, centralSize); w.u32(16, offset); });

  const all = [...chunks, ...central, eocd];
  const out = new Uint8Array(all.reduce((s, b) => s + b.length, 0));
  let p = 0;
  for (const b of all) { out.set(b, p); p += b.length; }
  return out;
}
