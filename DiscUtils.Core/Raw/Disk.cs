using System;
using System.Collections.Generic;
using System.IO;
using DiscUtils.Core.Internal;
using DiscUtils.Streams;
using DiscUtils.Streams.Util;

namespace DiscUtils.Core.Raw
{
    /// <summary>
    /// Represents a raw disk image.
    /// </summary>
    /// <remarks>This disk format is simply an uncompressed capture of all blocks on a disk.</remarks>
    public sealed class Disk : VirtualDisk
    {
        private DiskImageFile _file;

        /// <summary>
        /// Initializes a new instance of the Disk class.
        /// </summary>
        /// <param name="stream">The stream to read.</param>
        /// <param name="ownsStream">Indicates if the new instance should control the lifetime of the stream.</param>
        public Disk(Stream stream, Ownership ownsStream)
            : this(stream, ownsStream, null) {}

        /// <summary>
        /// Initializes a new instance of the Disk class.
        /// </summary>
        /// <param name="stream">The stream to read.</param>
        /// <param name="ownsStream">Indicates if the new instance should control the lifetime of the stream.</param>
        /// <param name="geometry">The emulated geometry of the disk.</param>
        public Disk(Stream stream, Ownership ownsStream, Geometry geometry)
        {
            _file = new DiskImageFile(stream, ownsStream, geometry);
        }

        /// <summary>
        /// Initializes a new instance of the Disk class.
        /// </summary>
        /// <param name="path">The path to the disk image.</param>
        public Disk(string path)
            :this(path, FileAccess.ReadWrite) {}

        /// <summary>
        /// Initializes a new instance of the Disk class.
        /// </summary>
        /// <param name="path">The path to the disk image.</param>
        /// <param name="access">The access requested to the disk.</param>
        public Disk(string path, FileAccess access)
        {
            FileShare share = access == FileAccess.Read ? FileShare.Read : FileShare.None;
            var locator = new LocalFileLocator(string.Empty);
            _file = new DiskImageFile(locator.Open(path, FileMode.Open, access, share), Ownership.Dispose, null);
        }

        /// <summary>
        /// Initializes a new instance of the Disk class.
        /// </summary>
        /// <param name="file">The contents of the disk.</param>
        private Disk(DiskImageFile file)
        {
            _file = file;
        }

        /// <summary>
        /// Gets the capacity of the disk (in bytes).
        /// </summary>
        public override long Capacity => _file.Capacity;

        /// <summary>
        /// Gets the content of the disk as a stream.
        /// </summary>
        /// <remarks>Note the returned stream is not guaranteed to be at any particular position.  The actual position
        /// will depend on the last partition table/file system activity, since all access to the disk contents pass
        /// through a single stream instance.  Set the stream position before accessing the stream.</remarks>
        public override SparseStream Content => _file.Content;

        /// <summary>
        /// Gets the type of disk represented by this object.
        /// </summary>
        public override VirtualDiskClass DiskClass => _file.DiskType;

        /// <summary>
        /// Gets information about the type of disk.
        /// </summary>
        /// <remarks>This property provides access to meta-data about the disk format, for example whether the
        /// BIOS geometry is preserved in the disk file.</remarks>
        public override VirtualDiskTypeInfo DiskTypeInfo => DiskFactory.MakeDiskTypeInfo();

        /// <summary>
        /// Gets the geometry of the disk.
        /// </summary>
        public override Geometry Geometry => _file.Geometry;

        /// <summary>
        /// Gets the layers that make up the disk.
        /// </summary>
        public override IEnumerable<VirtualDiskLayer> Layers
        {
            get { yield return _file; }
        }

        /// <summary>
        /// Initializes a stream as an unformatted disk.
        /// </summary>
        /// <param name="stream">The stream to initialize.</param>
        /// <param name="ownsStream">Indicates if the new instance controls the lifetime of the stream.</param>
        /// <param name="capacity">The desired capacity of the new disk.</param>
        /// <returns>An object that accesses the stream as a disk.</returns>
        public static Disk Initialize(Stream stream, Ownership ownsStream, long capacity)
        {
            return Initialize(stream, ownsStream, capacity, null);
        }

        /// <summary>
        /// Initializes a stream as an unformatted disk.
        /// </summary>
        /// <param name="stream">The stream to initialize.</param>
        /// <param name="ownsStream">Indicates if the new instance controls the lifetime of the stream.</param>
        /// <param name="capacity">The desired capacity of the new disk.</param>
        /// <param name="geometry">The desired geometry of the new disk, or <c>null</c> for default.</param>
        /// <returns>An object that accesses the stream as a disk.</returns>
        public static Disk Initialize(Stream stream, Ownership ownsStream, long capacity, Geometry geometry)
        {
            return new Disk(DiskImageFile.Initialize(stream, ownsStream, capacity, geometry));
        }

        /// <summary>
        /// Initializes a stream as an unformatted floppy disk.
        /// </summary>
        /// <param name="stream">The stream to initialize.</param>
        /// <param name="ownsStream">Indicates if the new instance controls the lifetime of the stream.</param>
        /// <param name="type">The type of floppy disk image to create.</param>
        /// <returns>An object that accesses the stream as a disk.</returns>
        public static Disk Initialize(Stream stream, Ownership ownsStream, FloppyDiskType type)
        {
            return new Disk(DiskImageFile.Initialize(stream, ownsStream, type));
        }

        /// <summary>
        /// Create a new differencing disk, possibly within an existing disk.
        /// </summary>
        /// <param name="fileSystem">The file system to create the disk on.</param>
        /// <param name="path">The path (or URI) for the disk to create.</param>
        /// <returns>The newly created disk.</returns>
        public override VirtualDisk CreateDifferencingDisk(DiscFileSystem fileSystem, string path)
        {
            throw new NotSupportedException("Differencing disks not supported for raw disks");
        }

        /// <summary>
        /// Create a new differencing disk.
        /// </summary>
        /// <param name="path">The path (or URI) for the disk to create.</param>
        /// <returns>The newly created disk.</returns>
        public override VirtualDisk CreateDifferencingDisk(string path)
        {
            throw new NotSupportedException("Differencing disks not supported for raw disks");
        }

        /// <summary>
        /// Disposes of underlying resources.
        /// </summary>
        /// <param name="disposing">Set to <c>true</c> if called within Dispose(),
        /// else <c>false</c>.</param>
        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing)
                {
                    if (_file != null)
                    {
                        _file.Dispose();
                    }

                    _file = null;
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }
    }
}