using System;
using System.Collections.Generic;
using System.IO;
using DiscUtils.Streams;
using DiscUtils.Streams.Util;

namespace DiscUtils.Ntfs
{
    internal sealed class AttributeDefinitions
    {
        private readonly Dictionary<AttributeType, AttributeDefinitionRecord> _attrDefs;

        public AttributeDefinitions()
        {
            _attrDefs = new Dictionary<AttributeType, AttributeDefinitionRecord>();

            Add(AttributeType.StandardInformation, "$STANDARD_INFORMATION", AttributeTypeFlags.MustBeResident, 0x30,
                0x48);
            Add(AttributeType.AttributeList, "$ATTRIBUTE_LIST", AttributeTypeFlags.CanBeNonResident, 0, -1);
            Add(AttributeType.FileName, "$FILE_NAME", AttributeTypeFlags.Indexed | AttributeTypeFlags.MustBeResident,
                0x44, 0x242);
            Add(AttributeType.ObjectId, "$OBJECT_ID", AttributeTypeFlags.MustBeResident, 0, 0x100);
            Add(AttributeType.SecurityDescriptor, "$SECURITY_DESCRIPTOR", AttributeTypeFlags.CanBeNonResident, 0x0, -1);
            Add(AttributeType.VolumeName, "$VOLUME_NAME", AttributeTypeFlags.MustBeResident, 0x2, 0x100);
            Add(AttributeType.VolumeInformation, "$VOLUME_INFORMATION", AttributeTypeFlags.MustBeResident, 0xC, 0xC);
            Add(AttributeType.Data, "$DATA", AttributeTypeFlags.None, 0, -1);
            Add(AttributeType.IndexRoot, "$INDEX_ROOT", AttributeTypeFlags.MustBeResident, 0, -1);
            Add(AttributeType.IndexAllocation, "$INDEX_ALLOCATION", AttributeTypeFlags.CanBeNonResident, 0, -1);
            Add(AttributeType.Bitmap, "$BITMAP", AttributeTypeFlags.CanBeNonResident, 0, -1);
            Add(AttributeType.ReparsePoint, "$REPARSE_POINT", AttributeTypeFlags.CanBeNonResident, 0, 0x4000);
            Add(AttributeType.ExtendedAttributesInformation, "$EA_INFORMATION", AttributeTypeFlags.MustBeResident, 0x8,
                0x8);
            Add(AttributeType.ExtendedAttributes, "$EA", AttributeTypeFlags.None, 0, 0x10000);
            Add(AttributeType.LoggedUtilityStream, "$LOGGED_UTILITY_STREAM", AttributeTypeFlags.CanBeNonResident, 0,
                0x10000);
        }

        public AttributeDefinitions(File file)
        {
            _attrDefs = new Dictionary<AttributeType, AttributeDefinitionRecord>();

            byte[] buffer = new byte[AttributeDefinitionRecord.Size];
            using (Stream s = file.OpenStream(AttributeType.Data, null, FileAccess.Read))
            {
                while (StreamUtilities.ReadMaximum(s, buffer, 0, buffer.Length) == buffer.Length)
                {
                    AttributeDefinitionRecord record = new AttributeDefinitionRecord();
                    record.Read(buffer, 0);

                    // NULL terminator record
                    if (record.Type != AttributeType.None)
                    {
                        _attrDefs.Add(record.Type, record);
                    }
                }
            }
        }

        public void WriteTo(File file)
        {
            List<AttributeType> attribs = new List<AttributeType>(_attrDefs.Keys);
            attribs.Sort();

            using (Stream s = file.OpenStream(AttributeType.Data, null, FileAccess.ReadWrite))
            {
                byte[] buffer;
                for (int i = 0; i < attribs.Count; ++i)
                {
                    buffer = new byte[AttributeDefinitionRecord.Size];
                    AttributeDefinitionRecord attrDef = _attrDefs[attribs[i]];
                    attrDef.Write(buffer, 0);

                    s.Write(buffer, 0, buffer.Length);
                }

                buffer = new byte[AttributeDefinitionRecord.Size];
                s.Write(buffer, 0, buffer.Length);
            }
        }

        internal AttributeDefinitionRecord Lookup(string name)
        {
            foreach (AttributeDefinitionRecord record in _attrDefs.Values)
            {
                if (string.Compare(name, record.Name, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    return record;
                }
            }

            return null;
        }

        internal bool MustBeResident(AttributeType attributeType)
        {
            AttributeDefinitionRecord record;
            if (_attrDefs.TryGetValue(attributeType, out record))
            {
                return (record.Flags & AttributeTypeFlags.MustBeResident) != 0;
            }

            return false;
        }

        internal bool IsIndexed(AttributeType attributeType)
        {
            AttributeDefinitionRecord record;
            if (_attrDefs.TryGetValue(attributeType, out record))
            {
                return (record.Flags & AttributeTypeFlags.Indexed) != 0;
            }

            return false;
        }

        private void Add(AttributeType attributeType, string name, AttributeTypeFlags attributeTypeFlags, int minSize,
                         int maxSize)
        {
            AttributeDefinitionRecord adr = new AttributeDefinitionRecord();
            adr.Type = attributeType;
            adr.Name = name;
            adr.Flags = attributeTypeFlags;
            adr.MinSize = minSize;
            adr.MaxSize = maxSize;
            _attrDefs.Add(attributeType, adr);
        }
    }
}