using DiscUtils.CoreCompat;

namespace DiscUtils.Containers
{
    public static class SetupHelper
    {
        public static void SetupContainers()
        {
            Setup.SetupHelper.RegisterAssembly(ReflectionHelper.GetAssembly(typeof(Vhd.Disk)));
        }
    }
}