using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace DiscUtils.Ntfs
{
    [ComVisible(false)]
    public sealed class SecurityIdentifier : IdentityReference, IComparable<SecurityIdentifier>
    {
        private string _value;
        private byte[] _binaryForm;

        public static readonly int MaxBinaryLength;
        public static readonly int MinBinaryLength;

        public SecurityIdentifier(string sddlForm)
        {
            if (sddlForm == null)
            {
                throw new ArgumentNullException("sddlForm");
            }
            this._value = sddlForm.ToUpperInvariant();
        }

        public SecurityIdentifier(byte[] binaryForm, int offset)
        {
            CreateFromBinaryForm(binaryForm, offset);
        }

        public SecurityIdentifier(WellKnownSidType sidType, SecurityIdentifier domainSid)
        {
            CreateFromBinaryForm(new byte[] {1, 1, 0, 0, 0, 0, 0, 0, 0}, 0);
        }

        public SecurityIdentifier AccountDomainSid => throw new ArgumentNullException("AccountDomainSid");

        public int BinaryLength => -1;

        public override string Value => _value;

        public int CompareTo(SecurityIdentifier sid)
            => Value.CompareTo(sid.Value);

        public override bool Equals(object o)
            => Equals(o as SecurityIdentifier);

        public bool Equals(SecurityIdentifier sid)
            => !(sid == null) && sid.Value == this.Value;

        public void GetBinaryForm(byte[] binaryForm, int offset)
        {
            if (binaryForm == null)
            {
                throw new ArgumentNullException("binaryForm");
            }
            if (offset < 0 || offset > binaryForm.Length - 1 - this.BinaryLength)
            {
                throw new ArgumentException("offset");
            }
        }

        public override int GetHashCode()
            => Value.GetHashCode();

        public override bool IsValidTargetType(Type targetType)
            => targetType == typeof(SecurityIdentifier) || targetType == typeof(NTAccount);

        public override string ToString()
            => Value;

        private void CreateFromBinaryForm(byte[] binaryForm, int offset)
        {
            //
            // Give us something to work with
            //

            if (binaryForm == null)
            {
                throw new ArgumentNullException(nameof(binaryForm));
            }

            //
            // Negative offsets are not allowed
            //

            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(offset),
                    offset,
                    "need non negative num");
            }

            //
            // At least a minimum-size SID should fit in the buffer
            //

            if (binaryForm.Length - offset < MinBinaryLength)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(binaryForm),
                    "array too smol");
            }

            IdentifierAuthority Authority;
            int[] SubAuthorities;

            //
            // Extract the elements of a SID
            //

            if (binaryForm[offset] != 1)
            {
                //
                // Revision is incorrect
                //

                throw new ArgumentException(
                    "sid revision invalid",
                    nameof(binaryForm));
            }

            //
            // Insist on the correct number of subauthorities
            //

            if (binaryForm[offset + 1] > 15)
            {
                throw new ArgumentException(
                    "max is 15",
                    nameof(binaryForm));
            }

            //
            // Make sure the buffer is big enough
            //

            int Length = 1 + 1 + 6 + 4 * binaryForm[offset + 1];

            if (binaryForm.Length - offset < Length)
            {
                throw new ArgumentException(
                    "array too smol",
                    nameof(binaryForm));
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

            //
            // Subauthorities are represented in big-endian format
            //

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

            return;
        }

        private IdentifierAuthority _identifierAuthority;
        private int[] _subAuthorities;

        private void CreateFromParts(IdentifierAuthority identifierAuthority, int[] subAuthorities)
        {
            if (subAuthorities == null)
            {
                throw new ArgumentNullException(nameof(subAuthorities));
            }

            //
            // Check the number of subauthorities passed in
            //

            if (subAuthorities.Length > 15)
            {
                throw new ArgumentOutOfRangeException(
                    "subAuthorities.Length",
                    subAuthorities.Length,
                    "max authorities is 15");
            }

            //
            // Identifier authority is at most 6 bytes long
            //

            if (identifierAuthority < 0 ||
                (long)identifierAuthority > 0xFFFFFFFFFFFF)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(identifierAuthority),
                    identifierAuthority,
                    "too large");
            }

            //
            // Create a local copy of the data passed in
            //

            _identifierAuthority = identifierAuthority;
            _subAuthorities = new int[subAuthorities.Length];
            subAuthorities.CopyTo(_subAuthorities, 0);

            //
            // Compute and store the binary form
            //
            // typedef struct _SID {
            //     UCHAR Revision;
            //     UCHAR SubAuthorityCount;
            //     SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
            //     ULONG SubAuthority[ANYSIZE_ARRAY]
            // } SID, *PISID;
            //

            byte i;
            _binaryForm = new byte[1 + 1 + 6 + 4 * _subAuthorities.Length];

            //
            // First two bytes contain revision and subauthority count
            //

            _binaryForm[0] = 1;
            _binaryForm[1] = (byte)_subAuthorities.Length;

            //
            // Identifier authority takes up 6 bytes
            //

            for (i = 0; i < 6; i++)
            {
                _binaryForm[2 + i] = (byte)((((ulong)_identifierAuthority) >> ((5 - i) * 8)) & 0xFF);
            }

            //
            // Subauthorities go last, preserving big-endian representation
            //

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