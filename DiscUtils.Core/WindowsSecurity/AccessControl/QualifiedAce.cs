using System;

namespace DiscUtils.Ntfs.WindowsSecurity.AccessControl
{
    public abstract class QualifiedAce : KnownAce
    {
        private byte[] opaque;

        internal QualifiedAce(AceType type, AceFlags flags, byte[] opaque)
            : base(type, flags)
        {
            SetOpaque(opaque);
        }

        internal QualifiedAce(byte[] binaryForm, int offset)
            : base(binaryForm, offset) { }

        public AceQualifier AceQualifier
        {
            get
            {
                switch (AceType)
                {
                    case AceType.AccessAllowed:
                    case AceType.AccessAllowedCallback:
                    case AceType.AccessAllowedCallbackObject:
                    case AceType.AccessAllowedCompound:
                    case AceType.AccessAllowedObject:
                        return AceQualifier.AccessAllowed;

                    case AceType.AccessDenied:
                    case AceType.AccessDeniedCallback:
                    case AceType.AccessDeniedCallbackObject:
                    case AceType.AccessDeniedObject:
                        return AceQualifier.AccessDenied;

                    case AceType.SystemAlarm:
                    case AceType.SystemAlarmCallback:
                    case AceType.SystemAlarmCallbackObject:
                    case AceType.SystemAlarmObject:
                        return AceQualifier.SystemAlarm;

                    case AceType.SystemAudit:
                    case AceType.SystemAuditCallback:
                    case AceType.SystemAuditCallbackObject:
                    case AceType.SystemAuditObject:
                        return AceQualifier.SystemAudit;

                    default:
                        throw new ArgumentException("Unrecognized ACE type: " + AceType);
                }
            }
        }

        public bool IsCallback =>
            AceType == AceType.AccessAllowedCallback
            || AceType == AceType.AccessAllowedCallbackObject
            || AceType == AceType.AccessDeniedCallback
            || AceType == AceType.AccessDeniedCallbackObject
            || AceType == AceType.SystemAlarmCallback
            || AceType == AceType.SystemAlarmCallbackObject
            || AceType == AceType.SystemAuditCallback
            || AceType == AceType.SystemAuditCallbackObject;

        public int OpaqueLength
        {
            get
            {
                if (opaque == null)
                    return 0;
                return opaque.Length;
            }
        }

        public byte[] GetOpaque()
        {
            if (opaque == null)
                return null;
            return (byte[])opaque.Clone();
        }

        public void SetOpaque(byte[] opaque)
        {
            if (opaque == null)
                this.opaque = null;
            else
                this.opaque = (byte[])opaque.Clone();
        }
    }
}