using System;

namespace DiscUtils.Ntfs
{
    /// <summary>
    /// Fully-qualified reference to an attribute.
    /// </summary>
    internal class AttributeReference : IComparable<AttributeReference>, IEquatable<AttributeReference>
    {
        private FileRecordReference _fileReference;

        /// <summary>
        /// Initializes a new instance of the AttributeReference class.
        /// </summary>
        /// <param name="fileReference">The file containing the attribute.</param>
        /// <param name="attributeId">The identity of the attribute within the file record.</param>
        public AttributeReference(FileRecordReference fileReference, ushort attributeId)
        {
            _fileReference = fileReference;
            AttributeId = attributeId;
        }

        /// <summary>
        /// Gets the identity of the attribute within the file record.
        /// </summary>
        public ushort AttributeId { get; }

        /// <summary>
        /// Gets the file containing the attribute.
        /// </summary>
        public FileRecordReference File => _fileReference;

        #region IComparable<AttributeReference> Members

        /// <summary>
        /// Compares this attribute reference to another.
        /// </summary>
        /// <param name="other">The attribute reference to compare against.</param>
        /// <returns>Zero if references are identical.</returns>
        public int CompareTo(AttributeReference other)
        {
            int refDiff = _fileReference.CompareTo(other._fileReference);
            if (refDiff != 0)
            {
                return refDiff;
            }

            return AttributeId.CompareTo(other.AttributeId);
        }

        #endregion

        #region IEquatable<AttributeReference> Members

        /// <summary>
        /// Indicates if two references are equivalent.
        /// </summary>
        /// <param name="other">The attribute reference to compare.</param>
        /// <returns><c>true</c> if the references are equivalent.</returns>
        public bool Equals(AttributeReference other)
        {
            return CompareTo(other) == 0;
        }

        #endregion

        /// <summary>
        /// The reference as a string.
        /// </summary>
        /// <returns>String representing the attribute.</returns>
        public override string ToString()
        {
            return _fileReference + ".attr[" + AttributeId + "]";
        }

        /// <summary>
        /// Indicates if this reference is equivalent to another object.
        /// </summary>
        /// <param name="obj">The object to compare.</param>
        /// <returns><c>true</c> if obj is an equivalent attribute reference.</returns>
        public override bool Equals(object obj)
        {
            AttributeReference objAsAttrRef = obj as AttributeReference;
            if (objAsAttrRef == null)
            {
                return false;
            }

            return Equals(objAsAttrRef);
        }

        /// <summary>
        /// Gets the hash code for this reference.
        /// </summary>
        /// <returns>The hash code.</returns>
        public override int GetHashCode()
        {
            return _fileReference.GetHashCode() ^ AttributeId.GetHashCode();
        }
    }
}