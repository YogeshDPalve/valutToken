const { le64, pae } = require('../../src/utils/pae');

describe('PAE (Pre-Authentication Encoding)', () => {
  describe('le64', () => {
    it('encodes 0 correctly', () => {
      const buf = le64(0);
      expect(buf).toEqual(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0]));
    });

    it('encodes a small positive integer correctly', () => {
      const buf = le64(258); // 256 + 2 = 0x0102
      expect(buf).toEqual(Buffer.from([2, 1, 0, 0, 0, 0, 0, 0]));
    });

    it('throws error for negative numbers', () => {
      expect(() => le64(-1)).toThrow(TypeError);
    });

    it('throws error for non-integers', () => {
      expect(() => le64(1.5)).toThrow(TypeError);
    });
  });

  describe('pae', () => {
    it('implements PAE() correctly', () => {
      // PAE() -> le64(0)
      const encoded = pae();
      expect(encoded).toEqual(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0]));
    });

    it('implements PAE("") correctly', () => {
      // PAE("") -> le64(1) || le64(0) || "" -> [1,0,0,0,0,0,0,0] + [0,0,0,0,0,0,0,0]
      const encoded = pae('');
      expect(encoded).toEqual(Buffer.from([
        1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0
      ]));
    });

    it('implements PAE("test") correctly', () => {
      // PAE("test") -> le64(1) || le64(4) || "test"
      const encoded = pae('test');
      expect(encoded).toEqual(Buffer.concat([
        Buffer.from([1, 0, 0, 0, 0, 0, 0, 0]),
        Buffer.from([4, 0, 0, 0, 0, 0, 0, 0]),
        Buffer.from('test')
      ]));
    });

    it('prevents multi-piece ambiguity prevention', () => {
      // Different splittings must yield different encodings
      const a = pae('ab', 'c');
      const b = pae('a', 'bc');
      const c = pae('abc');

      expect(a).not.toEqual(b);
      expect(b).not.toEqual(c);
      expect(a).not.toEqual(c);
    });

    it('accepts Buffers', () => {
      const result1 = pae(Buffer.from('hello'));
      const result2 = pae('hello');
      expect(result1).toEqual(result2);
    });

    it('accepts Uint8Arrays', () => {
      const result1 = pae(new Uint8Array(Buffer.from('hello')));
      const result2 = pae('hello');
      expect(result1).toEqual(result2);
    });

    it('throws on unsupported types', () => {
      expect(() => pae(123)).toThrow(TypeError);
      expect(() => pae({})).toThrow(TypeError);
      expect(() => pae(null)).toThrow(TypeError);
      expect(() => pae(undefined)).toThrow(TypeError);
    });
  });
});
