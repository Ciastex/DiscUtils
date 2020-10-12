using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace DiscUtils.Ntfs.WindowsSecurity
{
    [ComVisible(false)]
    public sealed class SecurityIdentifier : IdentityReference, IComparable<SecurityIdentifier>
    {
        private string _value;
        private byte[] _binaryForm;

        private IdentifierAuthority _identifierAuthority;
        private int[] _subAuthorities;

        public static readonly int MaxBinaryLength;
        public static readonly int MinBinaryLength;

        public int BinaryLength => _binaryForm.Length;
        public override string Value => _value;

        public SecurityIdentifier(string sddlForm)
        {
            _value = sddlForm.ToUpperInvariant();
        }

        public SecurityIdentifier(byte[] binaryForm, int offset)
        {
            CreateFromBinaryForm(binaryForm, offset);
        }

        public SecurityIdentifier(WellKnownSidType sidType, SecurityIdentifier domainSid)
        {
            GetBinaryForm($"S-1-1-{(int)domainSid._identifierAuthority}-{sidType}");
        }

        private void CreateFromBinaryForm(byte[] binaryForm, int offset)
        {
            if (binaryForm == null)
            {
                throw new ArgumentNullException(nameof(binaryForm));
            }

            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(offset),
                    offset,
                    "need non negative num");
            }

            if (binaryForm.Length - offset < MinBinaryLength)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(binaryForm),
                    "array too smol");
            }

            IdentifierAuthority Authority;
            int[] SubAuthorities;

            if (binaryForm[offset] != 1)
            {
                throw new ArgumentException("sid revision invalid", nameof(binaryForm));
            }

            if (binaryForm[offset + 1] > 15)
            {
                throw new ArgumentException("max authorities is 15", nameof(binaryForm));
            }

            int length = 1 + 1 + 6 + 4 * binaryForm[offset + 1];

            if (binaryForm.Length - offset < length)
            {
                throw new ArgumentException("array too small", nameof(binaryForm));
            }

            Authority =
                (IdentifierAuthority)(
                    (((long)binaryForm[offset + 2]) << 40) +
                    (((long)binaryForm[offset + 3]) << 32) +
                    (((long)binaryForm[offset + 4]) << 24) +
                    (((long)binaryForm[offset + 5]) << 16) +
                    (((long)binaryForm[offset + 6]) << 8) +
                    (((long)binaryForm[offset + 7])));

            SubAuthorities = new int[binaryForm[offset + 1]];

            for (byte i = 0; i < binaryForm[offset + 1]; i++)
            {
                unchecked
                {
                    SubAuthorities[i] =
                        (int)(
                            (((uint)binaryForm[offset + 8 + 4 * i + 0]) << 0) +
                            (((uint)binaryForm[offset + 8 + 4 * i + 1]) << 8) +
                            (((uint)binaryForm[offset + 8 + 4 * i + 2]) << 16) +
                            (((uint)binaryForm[offset + 8 + 4 * i + 3]) << 24));
                }
            }

            CreateFromParts(Authority, SubAuthorities);
        }

        public void GetBinaryForm(byte[] bytes, int offset)
            => _binaryForm = bytes;

        public void GetBinaryForm(string sddlForm)
        {
            if (sddlForm == null)
            {
                throw new ArgumentNullException("sddlForm");
            }

            var bytes = new List<byte>();
            var nums = sddlForm.Split('-').Skip(1).ToArray();

            bytes.AddRange(BitConverter.GetBytes(byte.Parse(nums[0]))); // revision
            bytes.AddRange(BitConverter.GetBytes(byte.Parse(nums[1]))); // dash count
            bytes.AddRange(new byte[] {0, 0});
            bytes.AddRange(BitConverter.GetBytes(int.Parse(nums[2])).Reverse());
            bytes.AddRange(BitConverter.GetBytes(int.Parse(nums[3])));

            if (nums.Length > 4)
            {
                for (var i = 4; i < nums.Length; i++)
                {
                    bytes.AddRange(BitConverter.GetBytes(int.Parse(nums[i])));
                }
            }

            _binaryForm = bytes.ToArray();
        }

        public int CompareTo(SecurityIdentifier sid)
            => string.Compare(Value, sid.Value, StringComparison.Ordinal);

        public override bool Equals(object o)
            => Equals(o as SecurityIdentifier);

        public bool Equals(SecurityIdentifier sid)
            => !(sid == null) && sid.Value == Value;

        public override int GetHashCode()
            => Value.GetHashCode();

        public override bool IsValidTargetType(Type targetType)
            => targetType == typeof(SecurityIdentifier) || targetType == typeof(NTAccount);

        public override string ToString()
            => Value;

        private void CreateFromParts(IdentifierAuthority identifierAuthority, int[] subAuthorities)
        {
            if (subAuthorities == null)
            {
                throw new ArgumentNullException(nameof(subAuthorities));
            }

            if (subAuthorities.Length > 15)
            {
                throw new ArgumentOutOfRangeException(
                    "subAuthorities.Length",
                    subAuthorities.Length,
                    "max authorities is 15"
                );
            }

            if (identifierAuthority < 0 ||
                (long)identifierAuthority > 0xFFFFFFFFFFFF)
            {
                throw new ArgumentOutOfRangeException
                (
                    nameof(identifierAuthority),
                    identifierAuthority,
                    "too large"
                );
            }

            _identifierAuthority = identifierAuthority;
            _subAuthorities = new int[subAuthorities.Length];
            subAuthorities.CopyTo(_subAuthorities, 0);

            byte i;
            _binaryForm = new byte[1 + 1 + 6 + 4 * _subAuthorities.Length];

            _binaryForm[0] = 1;
            _binaryForm[1] = (byte)_subAuthorities.Length;

            for (i = 0; i < 6; i++)
            {
                _binaryForm[2 + i] = (byte)((((ulong)_identifierAuthority) >> ((5 - i) * 8)) & 0xFF);
            }

            for (i = 0; i < _subAuthorities.Length; i++)
            {
                byte shift;
                for (shift = 0; shift < 4; shift += 1)
                {
                    _binaryForm[8 + 4 * i + shift] = unchecked((byte)(((ulong)_subAuthorities[i]) >> (shift * 8)));
                }
            }
        }

        public override IdentityReference Translate(Type targetType)
        {
            if (targetType == typeof(SecurityIdentifier))
            {
                return this;
            }
            return null;
        }

        public static bool operator ==(SecurityIdentifier left, SecurityIdentifier right)
        {
            return left?.Value == right?.Value;
        }

        public static bool operator !=(SecurityIdentifier left, SecurityIdentifier right)
        {
            return left?.Value != right?.Value;
        }
    }
}