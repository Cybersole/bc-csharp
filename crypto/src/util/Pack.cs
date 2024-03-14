using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;

namespace Org.BouncyCastle.Util
{
    /// <summary>
    /// Utility methods for converting byte arrays into ints and longs, and back again.
    /// </summary>
    public abstract class Pack
    {
        public static short BigEndianToShort(byte[] bs, int off)
        {
            int n = (bs[off] & 0xff) << 8;
            n |= (bs[++off] & 0xff);
            return (short)n;
        }

        public static int BigEndianToInt(byte[] bs, int off)
        {
            int n = bs[off] << 24;
            n |= (bs[++off] & 0xff) << 16;
            n |= (bs[++off] & 0xff) << 8;
            n |= (bs[++off] & 0xff);
            return n;
        }

        public static void BigEndianToInt(byte[] bs, int off, int[] ns)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                ns[i] = BigEndianToInt(bs, off);
                off += 4;
            }
        }

        public static void BigEndianToInt(byte[] bs, int off, int[] ns, int nsOff, int nsLen)
        {
            for (int i = 0; i < nsLen; ++i)
            {
                ns[nsOff + i] = BigEndianToInt(bs, off);
                off += 4;
            }
        }

        public static byte[] IntToBigEndian(int n)
        {
            byte[] bs = new byte[4];
            IntToBigEndian(n, bs, 0);
            return bs;
        }

        public static void IntToBigEndian(int n, byte[] bs, int off)
        {
            bs[off] = (byte)(n >>> 24);
            bs[++off] = (byte)(n >>> 16);
            bs[++off] = (byte)(n >>> 8);
            bs[++off] = (byte)(n);
        }

        public static byte[] IntToBigEndian(int[] ns)
        {
            byte[] bs = new byte[4 * ns.Length];
            IntToBigEndian(ns, bs, 0);
            return bs;
        }

        public static void IntToBigEndian(int[] ns, byte[] bs, int off)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                IntToBigEndian(ns[i], bs, off);
                off += 4;
            }
        }

        public static void IntToBigEndian(int[] ns, int nsOff, int nsLen, byte[] bs, int bsOff)
        {
            for (int i = 0; i < nsLen; ++i)
            {
                IntToBigEndian(ns[nsOff + i], bs, bsOff);
                bsOff += 4;
            }
        }

        public static long BigEndianToLong(byte[] bs, int off)
        {
            int hi = BigEndianToInt(bs, off);
            int lo = BigEndianToInt(bs, off + 4);
            return ((long)(hi & 0xffffffff) << 32) | (long)(lo & 0xffffffff);
        }

        public static void BigEndianToLong(byte[] bs, int off, long[] ns)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                ns[i] = BigEndianToLong(bs, off);
                off += 8;
            }
        }

        public static void BigEndianToLong(byte[] bs, int bsOff, long[] ns, int nsOff, int nsLen)
        {
            for (int i = 0; i < nsLen; ++i)
            {
                ns[nsOff + i] = BigEndianToLong(bs, bsOff);
                bsOff += 8;
            }
        }

        public static byte[] LongToBigEndian(long n)
        {
            byte[] bs = new byte[8];
            LongToBigEndian(n, bs, 0);
            return bs;
        }

        public static void LongToBigEndian(long n, byte[] bs, int off)
        {
            IntToBigEndian((int)(n >>> 32), bs, off);
            IntToBigEndian((int)(n & 0xffffffff), bs, off + 4);
        }

        public static byte[] LongToBigEndian(long[] ns)
        {
            byte[] bs = new byte[8 * ns.Length];
            LongToBigEndian(ns, bs, 0);
            return bs;
        }

        public static void LongToBigEndian(long[] ns, byte[] bs, int off)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                LongToBigEndian(ns[i], bs, off);
                off += 8;
            }
        }

        public static void LongToBigEndian(long[] ns, int nsOff, int nsLen, byte[] bs, int bsOff)
        {
            for (int i = 0; i < nsLen; ++i)
            {
                LongToBigEndian(ns[nsOff + i], bs, bsOff);
                bsOff += 8;
            }
        }

        public static void LongToBigEndian(long value, byte[] bs, int off, int bytes)
        {
            for (int i = bytes - 1; i >= 0; i--)
            {
                bs[i + off] = (byte)(value & 0xff);
                value >>>= 8;
            }
        }

        public static short LittleEndianToShort(byte[] bs, int off)
        {
            int n = bs[off] & 0xff;
            n |= (bs[++off] & 0xff) << 8;
            return (short)n;
        }

        public static int LittleEndianToInt(byte[] bs, int off)
        {
            int n = bs[off] & 0xff;
            n |= (bs[++off] & 0xff) << 8;
            n |= (bs[++off] & 0xff) << 16;
            n |= bs[++off] << 24;
            return n;
        }

        public static int LittleEndianToInt_High(byte[] bs, int off, int len)
        {
            return LittleEndianToInt_Low(bs, off, len) << ((4 - len) << 3);
        }

        public static int LittleEndianToInt_Low(byte[] bs, int off, int len)
        {

            //        assert 1 <= len && len <= 4;
            int result = bs[off] & 0xff;
            int pos = 0;
            for (int i = 1; i < len; ++i)
            {
                pos += 8;
                result |= (bs[off + i] & 0xff) << pos;
            }

            return result;
        }

        public static void LittleEndianToInt(byte[] bs, int off, int[] ns)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                ns[i] = LittleEndianToInt(bs, off);
                off += 4;
            }
        }

        public static void LittleEndianToInt(byte[] bs, int bOff, int[] ns, int nOff, int count)
        {
            for (int i = 0; i < count; ++i)
            {
                ns[nOff + i] = LittleEndianToInt(bs, bOff);
                bOff += 4;
            }
        }

        public static int[] LittleEndianToInt(byte[] bs, int off, int count)
        {
            int[] ns = new int[count];
            for (int i = 0; i < ns.Length; ++i)
            {
                ns[i] = LittleEndianToInt(bs, off);
                off += 4;
            }

            return ns;
        }

        public static byte[] ShortToLittleEndian(short n)
        {
            byte[] bs = new byte[2];
            ShortToLittleEndian(n, bs, 0);
            return bs;
        }

        public static void ShortToLittleEndian(short n, byte[] bs, int off)
        {
            bs[off] = (byte)(n);
            bs[++off] = (byte)(n >>> 8);
        }

        public static byte[] ShortToBigEndian(short n)
        {
            byte[] r = new byte[2];
            ShortToBigEndian(n, r, 0);
            return r;
        }

        public static void ShortToBigEndian(short n, byte[] bs, int off)
        {
            bs[off] = (byte)(n >>> 8);
            bs[++off] = (byte)(n);
        }

        public static byte[] IntToLittleEndian(int n)
        {
            byte[] bs = new byte[4];
            IntToLittleEndian(n, bs, 0);
            return bs;
        }

        public static void IntToLittleEndian(int n, byte[] bs, int off)
        {
            bs[off] = (byte)(n);
            bs[++off] = (byte)(n >>> 8);
            bs[++off] = (byte)(n >>> 16);
            bs[++off] = (byte)(n >>> 24);
        }

        public static byte[] IntToLittleEndian(int[] ns)
        {
            byte[] bs = new byte[4 * ns.Length];
            IntToLittleEndian(ns, bs, 0);
            return bs;
        }

        public static void IntToLittleEndian(int[] ns, byte[] bs, int off)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                IntToLittleEndian(ns[i], bs, off);
                off += 4;
            }
        }

        public static void IntToLittleEndian(int[] ns, int nsOff, int nsLen, byte[] bs, int bsOff)
        {
            for (int i = 0; i < nsLen; ++i)
            {
                IntToLittleEndian(ns[nsOff + i], bs, bsOff);
                bsOff += 4;
            }
        }

        public static long LittleEndianToLong(byte[] bs, int off)
        {
            int lo = LittleEndianToInt(bs, off);
            int hi = LittleEndianToInt(bs, off + 4);
            return ((long)(hi & 0xffffffff) << 32) | (long)(lo & 0xffffffff);
        }

        public static void LittleEndianToLong(byte[] bs, int off, long[] ns)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                ns[i] = LittleEndianToLong(bs, off);
                off += 8;
            }
        }

        public static void LittleEndianToLong(byte[] bs, int bsOff, long[] ns, int nsOff, int nsLen)
        {
            for (int i = 0; i < nsLen; ++i)
            {
                ns[nsOff + i] = LittleEndianToLong(bs, bsOff);
                bsOff += 8;
            }
        }

        public static void LongToLittleEndian_High(long n, byte[] bs, int off, int len)
        {

            //Debug.Assert(1 <= len && len <= 8);
            int pos = 56;
            bs[off] = (byte)(n >>> pos);
            for (int i = 1; i < len; ++i)
            {
                pos -= 8;
                bs[off + i] = (byte)(n >>> pos);
            }
        }

        //    public static void longToLittleEndian_Low(long n, byte[] bs, int off, int len)
        //    {
        //        longToLittleEndian_High(n << ((8 - len) << 3), bs, off, len);
        //    }
        public static long LittleEndianToLong_High(byte[] bs, int off, int len)
        {
            return LittleEndianToLong_Low(bs, off, len) << ((8 - len) << 3);
        }

        public static long LittleEndianToLong_Low(byte[] bs, int off, int len)
        {

            //Debug.Assert(1 <= len && len <= 8);
            long result = bs[off] & 0xFF;
            for (int i = 1; i < len; ++i)
            {
                result <<= 8;
                result |= bs[off + i] & 0xFF;
            }

            return result;
        }

        public static byte[] LongToLittleEndian(long n)
        {
            byte[] bs = new byte[8];
            LongToLittleEndian(n, bs, 0);
            return bs;
        }

        public static void LongToLittleEndian(long n, byte[] bs, int off)
        {
            IntToLittleEndian((int)(n & 0xffffffff), bs, off);
            IntToLittleEndian((int)(n >>> 32), bs, off + 4);
        }

        public static byte[] LongToLittleEndian(long[] ns)
        {
            byte[] bs = new byte[8 * ns.Length];
            LongToLittleEndian(ns, bs, 0);
            return bs;
        }

        public static void LongToLittleEndian(long[] ns, byte[] bs, int off)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                LongToLittleEndian(ns[i], bs, off);
                off += 8;
            }
        }

        public static void LongToLittleEndian(long[] ns, int nsOff, int nsLen, byte[] bs, int bsOff)
        {
            for (int i = 0; i < nsLen; ++i)
            {
                LongToLittleEndian(ns[nsOff + i], bs, bsOff);
                bsOff += 8;
            }
        }
    }
}