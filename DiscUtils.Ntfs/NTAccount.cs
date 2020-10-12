using System;

namespace DiscUtils.Ntfs
{
    public sealed class NTAccount : IdentityReference
    {
        private string _value;

        public NTAccount(string name)
        {
            if (name == null)
            {
                throw new ArgumentNullException("name");
            }
            if (name.Length == 0)
            {
                throw new ArgumentException("empty", "name");
            }
            this._value = name.ToUpper();
        }

        public NTAccount(string domainName, string accountName)
        {
            if (accountName == null)
            {
                throw new ArgumentNullException("accountName");
            }
            if (accountName.Length == 0)
            {
                throw new ArgumentException("empty", "accountName");
            }
            if (domainName == null)
            {
                this._value = domainName.ToUpper();
            }
            else
            {
                this._value = domainName.ToUpper() + "\\" + domainName.ToUpper();
            }
        }

        public override string Value => this._value;

        public override bool Equals(object o)
        {
            NTAccount ntaccount = o as NTAccount;
            return !(ntaccount == null) && ntaccount.Value == this.Value;
        }

        public override int GetHashCode()
        {
            return this.Value.GetHashCode();
        }

        public override bool IsValidTargetType(Type targetType)
        {
            return targetType == typeof(NTAccount) || targetType == typeof(SecurityIdentifier);
        }

        public override string ToString()
        {
            return this.Value;
        }

        public override IdentityReference Translate(Type targetType)
        {
            if (targetType == typeof(NTAccount))
            {
                return this;
            }
            return null;
        }

        public static bool operator ==(NTAccount left, NTAccount right)
        {
            if (left == null)
            {
                return right == null;
            }
            return right != null && left.Value == right.Value;
        }

        public static bool operator !=(NTAccount left, NTAccount right)
        {
            if (left == null)
            {
                return right != null;
            }
            return right == null || left.Value != right.Value;
        }
    }
}