using DiscUtils.CoreCompat;
using DiscUtils.Ntfs;

namespace DiscUtils.FileSystems
{
    public static class SetupHelper
    {
        public static void SetupFileSystems()
        {
            Setup.SetupHelper.RegisterAssembly(ReflectionHelper.GetAssembly(typeof(NtfsFileSystem)));
        }
    }
}