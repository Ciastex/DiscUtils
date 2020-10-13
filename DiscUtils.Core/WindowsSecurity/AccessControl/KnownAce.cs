using System.Globalization;
using System.Text;

namespace DiscUtils.Ntfs.WindowsSecurity.AccessControl
{
    public abstract class KnownAce : GenericAce
    {
        private int access_mask;
        private SecurityIdentifier identifier;

        internal KnownAce(AceType type, AceFlags flags)
            : base(type, flags) { }

        internal KnownAce(byte[] binaryForm, int offset)
            : base(binaryForm, offset) { }

        public int AccessMask
        {
            get => access_mask;
            set => access_mask = value;
        }

        public SecurityIdentifier SecurityIdentifier
        {
            get => identifier;
            set => identifier = value;
        }

        internal static string GetSddlAccessRights(int accessMask)
        {
            string ret = GetSddlAliasRights(accessMask);
            if (!string.IsNullOrEmpty(ret))
                return ret;

            return string.Format(CultureInfo.InvariantCulture,
                "0x{0:x}", accessMask);
        }

        private static string GetSddlAliasRights(int accessMask)
        {
            SddlAccessRight[] rights = SddlAccessRight.Decompose(accessMask);
            if (rights == null)
                return null;

            StringBuilder ret = new StringBuilder();
            foreach (var right in rights)
            {
                ret.Append(right.Name);
            }

            return ret.ToString();
        }
    }
}