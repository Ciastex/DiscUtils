using System;
using System.Globalization;

namespace DiscUtils.Ntfs.WindowsSecurity.AccessControl
{
    public sealed class ObjectAce : QualifiedAce
    {
        private Guid object_ace_type;
        private Guid inherited_object_type;
        private ObjectAceFlags object_ace_flags;

        public ObjectAce(AceFlags aceFlags, AceQualifier qualifier,
                         int accessMask, SecurityIdentifier sid,
                         ObjectAceFlags flags, Guid type,
                         Guid inheritedType, bool isCallback,
                         byte[] opaque)
            : base(ConvertType(qualifier, isCallback), aceFlags, opaque)
        {
            AccessMask = accessMask;
            SecurityIdentifier = sid;
            ObjectAceFlags = flags;
            ObjectAceType = type;
            InheritedObjectAceType = inheritedType;
        }

        internal ObjectAce(AceType type, AceFlags flags, int accessMask,
                           SecurityIdentifier sid, ObjectAceFlags objFlags,
                           Guid objType, Guid inheritedType, byte[] opaque)
            : base(type, flags, opaque)
        {
            AccessMask = accessMask;
            SecurityIdentifier = sid;
            ObjectAceFlags = objFlags;
            ObjectAceType = objType;
            InheritedObjectAceType = inheritedType;
        }

        internal ObjectAce(byte[] binaryForm, int offset)
            : base(binaryForm, offset)
        {
            int len = ReadUShort(binaryForm, offset + 2);
            int lenMinimum = 12 + SecurityIdentifier.MinBinaryLength;

            if (offset > binaryForm.Length - len)
                throw new ArgumentException("Invalid ACE - truncated", "binaryForm");
            if (len < lenMinimum)
                throw new ArgumentException("Invalid ACE", "binaryForm");

            AccessMask = ReadInt(binaryForm, offset + 4);
            ObjectAceFlags = (ObjectAceFlags)ReadInt(binaryForm, offset + 8);

            if (ObjectAceTypePresent) lenMinimum += 16;
            if (InheritedObjectAceTypePresent) lenMinimum += 16;
            if (len < lenMinimum)
                throw new ArgumentException("Invalid ACE", "binaryForm");

            int pos = 12;
            if (ObjectAceTypePresent)
            {
                ObjectAceType = ReadGuid(binaryForm, offset + pos);
                pos += 16;
            }
            if (InheritedObjectAceTypePresent)
            {
                InheritedObjectAceType = ReadGuid(binaryForm, offset + pos);
                pos += 16;
            }

            SecurityIdentifier = new SecurityIdentifier(binaryForm, offset + pos);
            pos += SecurityIdentifier.BinaryLength;

            int opaqueLen = len - pos;
            if (opaqueLen > 0)
            {
                byte[] opaque = new byte[opaqueLen];
                Array.Copy(binaryForm, offset + pos, opaque, 0, opaqueLen);
                SetOpaque(opaque);
            }
        }

        public override int BinaryLength
        {
            get
            {
                int length = 12 + SecurityIdentifier.BinaryLength + OpaqueLength;
                if (ObjectAceTypePresent) length += 16;
                if (InheritedObjectAceTypePresent) length += 16;
                return length;
            }
        }

        public Guid InheritedObjectAceType
        {
            get => inherited_object_type;
            set => inherited_object_type = value;
        }

        bool InheritedObjectAceTypePresent => 0 != (ObjectAceFlags & ObjectAceFlags.InheritedObjectAceTypePresent);

        public ObjectAceFlags ObjectAceFlags
        {
            get => object_ace_flags;
            set => object_ace_flags = value;
        }

        public Guid ObjectAceType
        {
            get => object_ace_type;
            set => object_ace_type = value;
        }

        bool ObjectAceTypePresent => 0 != (ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent);

        public override void GetBinaryForm(byte[] binaryForm, int offset)
        {
            int len = BinaryLength;
            binaryForm[offset++] = (byte)this.AceType;
            binaryForm[offset++] = (byte)this.AceFlags;
            WriteUShort((ushort)len, binaryForm, offset);
            offset += 2;
            WriteInt(AccessMask, binaryForm, offset);
            offset += 4;
            WriteInt((int)ObjectAceFlags, binaryForm, offset);
            offset += 4;

            if (0 != (ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent))
            {
                WriteGuid(ObjectAceType, binaryForm, offset);
                offset += 16;
            }
            if (0 != (ObjectAceFlags & ObjectAceFlags.InheritedObjectAceTypePresent))
            {
                WriteGuid(InheritedObjectAceType, binaryForm, offset);
                offset += 16;
            }

            SecurityIdentifier.GetBinaryForm(binaryForm, offset);
            offset += SecurityIdentifier.BinaryLength;

            byte[] opaque = GetOpaque();
            if (opaque != null)
            {
                Array.Copy(opaque, 0, binaryForm, offset, opaque.Length);
                offset += opaque.Length;
            }
        }

        public static int MaxOpaqueLength(bool isCallback)
        {
            // Varies by platform?
            return 65423;
        }

        internal override string GetSddlForm()
        {
            if (OpaqueLength != 0)
                throw new NotImplementedException(
                    "Unable to convert conditional ACEs to SDDL");

            string objType = "";
            if ((ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent) != 0)
                objType = object_ace_type.ToString("D");

            string inhObjType = "";
            if ((ObjectAceFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != 0)
                inhObjType = inherited_object_type.ToString("D");

            return string.Format(CultureInfo.InvariantCulture,
                "({0};{1};{2};{3};{4};{5})",
                GetSddlAceType(AceType),
                GetSddlAceFlags(AceFlags),
                GetSddlAccessRights(AccessMask),
                objType,
                inhObjType,
                SecurityIdentifier.GetSddlForm());
        }

        private static AceType ConvertType(AceQualifier qualifier, bool isCallback)
        {
            switch (qualifier)
            {
                case AceQualifier.AccessAllowed:
                    if (isCallback)
                        return AceType.AccessAllowedCallbackObject;
                    else
                        return AceType.AccessAllowedObject;

                case AceQualifier.AccessDenied:
                    if (isCallback)
                        return AceType.AccessDeniedCallbackObject;
                    else
                        return AceType.AccessDeniedObject;

                case AceQualifier.SystemAlarm:
                    if (isCallback)
                        return AceType.SystemAlarmCallbackObject;
                    else
                        return AceType.SystemAlarmObject;

                case AceQualifier.SystemAudit:
                    if (isCallback)
                        return AceType.SystemAuditCallbackObject;
                    else
                        return AceType.SystemAuditObject;

                default:
                    throw new ArgumentException("Unrecognized ACE qualifier: " + qualifier, "qualifier");
            }
        }

        private void WriteGuid(Guid val, byte[] buffer,
                               int offset)
        {
            byte[] guidData = val.ToByteArray();
            Array.Copy(guidData, 0, buffer, offset, 16);
        }

        private Guid ReadGuid(byte[] buffer, int offset)
        {
            byte[] temp = new byte[16];
            Array.Copy(buffer, offset, temp, 0, 16);
            return new Guid(temp);
        }
    }
}