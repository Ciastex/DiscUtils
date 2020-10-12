using System;
using System.IO;
using DiscUtils.Ntfs;
using DiscUtils.Partitions;
using DiscUtils.Streams;
using DiscUtils.Vhd;
using File = System.IO.File;

namespace DiscUtils.Test
{
    class Program
    {
        private static Disk Vhd { get; set; }
        private static NtfsFileSystem Ntfs { get; set; }

        static void Main(string[] args)
        {
            if (!File.Exists("disk.vhd"))
            {
                var diskStream = File.Create("disk.vhd");
                Vhd = Disk.InitializeDynamic(diskStream, Ownership.None, 1024 * 1024 * 1024);
                BiosPartitionTable.Initialize(Vhd, WellKnownPartitionType.WindowsNtfs);
                var volmgr = new VolumeManager(Vhd);
                Ntfs = NtfsFileSystem.Format(volmgr.GetPhysicalVolumes()[0], "test");
            }
            else
            {
                var diskStream = File.Open("disk.vhd", FileMode.Open);
                Vhd = new Disk(diskStream, Ownership.None);
                Ntfs = new NtfsFileSystem(Vhd.Partitions[0].Open());
            }
        }
    }
}