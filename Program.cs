using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace flvtool
{
    static class StreamUtil
    {
        public static byte[] ReadBlock(this Stream fs, uint byteCount)
        {
            byte[] ret = new byte[byteCount];
            if (fs.Read(ret, 0, (int)byteCount) == byteCount)
                return ret;
            else
                throw new EndOfStreamException();
        }

        public static uint ReadU8(this Stream fs)
        {
            int ret = fs.ReadByte();
            if (ret < 0)
                throw new EndOfStreamException();
            
            return (uint)ret;
        }

        public static uint ReadU16BE(this Stream fs)
        {
            return fs.ReadU8() * 256 + fs.ReadU8();
        }

        public static uint ReadU24BE(this Stream fs)
        {
            return fs.ReadU16BE() * 256 + fs.ReadU8();
        }

        public static uint ReadU32BE(this Stream fs)
        {
            return fs.ReadU24BE() * 256 + fs.ReadU8();
        }

        public static byte[] Append(this byte[] lhs, byte[] rhs)
        {
            byte[] result = new byte[lhs.Length + rhs.Length];
            Array.Copy(lhs, result, lhs.Length);
            Array.Copy(rhs, 0, result, lhs.Length, rhs.Length);
            return result;
        }
    }

    class FLVTag
    {
        public uint tagType;
        public uint tagSize;

        public uint tagDataOffset;

        public byte[] tagData;
    }

    class Nalu
    {
        public enum NaluType { SPS = 0, PPS, OTHER }
        public uint offset;
        public uint len;
        public byte[] data;
        public NaluType type;
    }

    class NaluHash
    {
        public uint offset;
        public uint len;
        public string hash;
        public string message;
    }

    class FLVToolException : Exception
    {
        public FLVToolException(long offset, string msg) : base("POS " + offset.ToString() + " " + msg)
        {
        }
    }

    class FLVTool
    {
        static byte[] startcode = new byte[] { 0, 0, 0, 1 };

        // return body offset
        private void ReadHeader(Stream fs, ref uint offset)
        {
            //FLV 1
            byte[] magic = fs.ReadBlock(4);
            offset += 4;
            if (!magic.SequenceEqual(new byte[] {0x46, 0x4c, 0x56, 0x01}))
                throw new FLVToolException(fs.Position - 4, "Not a FLV stream");

            //flags
            fs.ReadU8();
            offset += 1;

            //offset
            uint dataoffset = fs.ReadU32BE();
            offset += 4;

            if (dataoffset < 9)
                throw new FLVToolException(fs.Position - 4, "Invalid data offset value.");

            uint dummySize = dataoffset - 9;
            if (dummySize > 0)
            {
                byte[] dummy = fs.ReadBlock(dummySize);
                offset += dummySize;
                if (dummy == null || dummy.Length != dummySize)
                    throw new FLVToolException(fs.Position - 4, "Stream ended before FLV body.");
            }
        }

        //tag type, tag size, tag data
        private FLVTag ReadTag(Stream fs, ref uint offset)
        {
            try
            {
                FLVTag result = new FLVTag();

                //prev tag size
                if (fs.ReadBlock(4) == null)
                    return null;
                offset += 4;

                result.tagType = fs.ReadU8();
                offset += 1;
                result.tagSize = fs.ReadU24BE();
                offset += 3;

                //timestamp
                fs.ReadU24BE();
                offset += 3;
                //timestamp ext
                fs.ReadU8();
                offset += 1;

                //stream id
                fs.ReadU24BE();
                offset += 3;

                result.tagDataOffset = offset;

                // tag > 10M, maybe parse in wrong position
                if (result.tagSize > 10485760)
                {
                    throw new FLVToolException(fs.Position, "Tag data > 10M, maybe an error.");
                }
                result.tagData = fs.ReadBlock(result.tagSize);
                offset += result.tagSize;

                return result;
            }
            catch(EndOfStreamException)
            {
                return null;
            }
        }

        private IEnumerator<Nalu> GetNalus(FLVTag tag, long fsPos)
        {
            if (tag.tagType == 9)
            {
                MemoryStream ms = new MemoryStream(tag.tagData);
                uint offset = tag.tagDataOffset;

                //frame type and codec id
                uint tmp = ms.ReadU8();
                offset += 1;

                if ((tmp & 0xf) == 7)
                {
                    uint avcpkttype = ms.ReadU8();
                    offset += 1;

                    if (avcpkttype == 1) //nalu
                    {
                        //composition time
                        ms.ReadU24BE();
                        offset += 3;

                        //avcc to annex-b
                        while(ms.Position < ms.Length)
                        {
                            Nalu nalu = new Nalu();
                            nalu.type = Nalu.NaluType.OTHER;
                            nalu.offset = offset;

                            uint len = ms.ReadU32BE();
                            offset += 4;
                            nalu.len = len;
                            nalu.data = startcode.Append(ms.ReadBlock(len));
                            offset += len;
                            yield return nalu;
                        }
                    }
                    else if (avcpkttype == 0) //sps pps
                    {
                        //???
                        ms.ReadU24BE();
                        offset += 3;

                        //conf ver
                        ms.ReadU8();
                        offset += 1;

                        //avc profile
                        ms.ReadU8();
                        offset += 1;

                        //profile compatibility
                        ms.ReadU8();
                        offset += 1;

                        //avc level
                        ms.ReadU8();
                        offset += 1;
                        
                        //length size - 1
                        uint len_minus_one = ms.ReadU8();
                        if (len_minus_one != 0xff)
                        {
                            throw new FLVToolException(fsPos + ms.Position - 1, "lengthSizeMinusOne != 3 in SPS, not supported");
                        }
                        offset += 1;

                        //sps count | 11100000
                        uint spsCntRaw = ms.ReadU8();
                        int spscount = (int)(spsCntRaw) & 0x1f;
                        offset += 1;

                        //sps
                        for (int i = 0; i < spscount; ++i)
                        {
                            Nalu nalu = new Nalu();
                            nalu.type = Nalu.NaluType.SPS;
                            nalu.offset = offset;

                            uint spslen = ms.ReadU16BE();
                            offset += 2;
                            nalu.len = spslen + 2;
                            nalu.data = startcode.Append(ms.ReadBlock(spslen));
                            offset += spslen;
                            yield return nalu;
                        }

                        //pps count
                        int ppscount = (int)(ms.ReadU8());
                        offset += 1;

                        //pps
                        for (int i = 0; i < ppscount; ++i)
                        {
                            Nalu nalu = new Nalu();
                            nalu.type = Nalu.NaluType.PPS;
                            nalu.offset = offset;

                            uint ppslen = ms.ReadU16BE();
                            offset += 2;
                            nalu.len = ppslen + 2;
                            nalu.data = startcode.Append(ms.ReadBlock(ppslen));
                            offset += ppslen;
                            yield return nalu;
                        }
                    }
                }
            }
        }

        private IEnumerator<Nalu> GetAllNalus(Stream fs)
        {
            fs.Seek(0, SeekOrigin.Begin);

            uint offset = 0;
            
            ReadHeader(fs, ref offset);

            for (; ; )
            {
                long fsPos = fs.Position;
                FLVTag tag = ReadTag(fs, ref offset);
                if (tag != null)
                {
                    var x = GetNalus(tag, fsPos);
                    while (x.MoveNext())
                        yield return x.Current;
                }
                else
                    break;
            }

            yield break;
        }

        public string ComputeMD5(byte[] data)
        {
            MD5 md5 = MD5.Create();
            md5.TransformFinalBlock(data, 0, data.Length);
            return new string(md5.Hash.SelectMany(x => x.ToString("X02")).ToArray());
        }

        List<NaluHash> ComputeMD5s(IEnumerator<Nalu> nalus, string tag)
        {
            var result = new List<NaluHash>();

            int index = 1;
            while(nalus.MoveNext())
            {
                var nalu = nalus.Current;
                string nalutype = "";

                var idctype = nalu.data[4] & 0x1f;
                switch (idctype)
                {
                    case 7: nalutype = "SPS"; break;
                    case 8: nalutype = "PPS"; break;
                    case 5: nalutype = "IDR"; break;
                    case 6: nalutype = "SEI"; break;
                }

                string md5 = ComputeMD5(nalu.data);
                var item = new NaluHash();
                item.hash = md5;
                item.offset = nalu.offset;
                item.len = nalu.len;
                item.message = tag + "[" + index.ToString() + "]" + (string.IsNullOrWhiteSpace(nalutype) ? "" : " _" + nalutype + "_");
                result.Add(item);
                ++index;
            }

            return result;
        }

        void ListToDict(Dictionary<string, NaluHash> output, List<NaluHash> list)
        {
            foreach(var i in list)
            {
                if (!output.ContainsKey(i.hash))
                    output.Add(i.hash, i);
                else
                    Console.WriteLine("{0} is the same as {1}", i.message, output[i.hash].message);
            }
        }

        public void ExtractAVC(string input, string output)
        {
            var fs = new FileStream(input, FileMode.Open);
            var fso = new FileStream(output, FileMode.Create);

            var nalus = GetAllNalus(fs);
            while(nalus.MoveNext())
            {
                fso.Write(nalus.Current.data, 0, nalus.Current.data.Length);
            }

            fs.Close();
            fso.Close();
        }

        public void ExtractAVCs(string input, string output)
        {
            var fs = new FileStream(input, FileMode.Open);
            int index = 0;

            //var fso = new FileStream(output, FileMode.Create);
            FileStream fso = null;

            var nalus = GetAllNalus(fs);
            while(nalus.MoveNext())
            {
                if (fso == null || nalus.Current.type == Nalu.NaluType.SPS)
                {
                    ++index;
                    if (fso != null)
                        fso.Close();
                    fso = new FileStream(output + "_" + index.ToString() + ".h264", FileMode.Create);
                }
                fso.Write(nalus.Current.data, 0, nalus.Current.data.Length);
            }

            fs.Close();

            if (fso != null)
                fso.Close();
        }

        public void AVCTrace(string target, string[] sources)
        {
            var dict = new Dictionary<string, NaluHash>();
            foreach (var s in sources)
            {
                FileStream fs = new FileStream(s, FileMode.Open);

                var nalus = GetAllNalus(fs);
                var t = ComputeMD5s(nalus, Path.GetFileNameWithoutExtension(s));
                
                ListToDict(dict, t);

                fs.Close();
            }

            Console.WriteLine();
            {
                FileStream fs = new FileStream(target, FileMode.Open);
                var nalus = GetAllNalus(fs);
                var t = ComputeMD5s(nalus, "");

                foreach(var x in t)
                {
                    NaluHash r;
                    if (dict.TryGetValue(x.hash, out r))
                        Console.WriteLine("from {0} to {1}  <--  {2} from {3} to {4}", x.offset, x.offset + x.len - 1, r.message, r.offset, r.offset + r.len - 1);
                    else
                        Console.WriteLine("Not Found");
                }
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            var x = new FLVTool();
            if (args.Length > 1)
            {
                try
                {
                    if (args[0] == "extract")
                    {
                        x.ExtractAVC(args[1], args[2]);
                    }
                    else if (args[0] == "extractseg")
                    {
                        x.ExtractAVCs(args[1], args[2]);
                    }
                    else if (args[0] == "trace")
                    {
                        x.AVCTrace(args[1], args.Skip(2).ToArray());
                    }
                    else
                    {
                        goto ShowHelp;
                    }
                    Environment.ExitCode = 0;
                }
                catch(Exception e)
                {
                    Console.WriteLine("Error: {0}", e.Message);
                    Environment.ExitCode = 1;
                }
            }
            else
            {
                goto ShowHelp;
            }
            return;

        ShowHelp:
            Console.WriteLine("args: extract xxxx.flv xxxx.h264");
            Console.WriteLine("    for work around ffmpeg's extraction bug with multiple segments H.264 in different SPS");
            Console.WriteLine();
            Console.WriteLine("args: extractseg xxxx.flv xxxx");
            Console.WriteLine("    save different segments in different files. will add _1.h264 _2.h264 suffix");
            Console.WriteLine();
            Console.WriteLine("args: trace joined.flv src1.flv src2.flv ...");
            Console.WriteLine("    for debug RTMP server's stream repeating");
            Environment.ExitCode = 1;
        }
    }
}
