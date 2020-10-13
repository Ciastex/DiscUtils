using System.Collections;

namespace DiscUtils.Ntfs.WindowsSecurity.AccessControl
{
    public sealed class AceEnumerator : IEnumerator
    {
        GenericAcl owner;
        int current = -1;

        internal AceEnumerator(GenericAcl owner)
        {
            this.owner = owner;
        }

        public GenericAce Current => current < 0 ? null : owner[current];
        object IEnumerator.Current => Current;

        public bool MoveNext()
        {
            if (current + 1 == owner.Count)
                return false;
            current++;
            return true;
        }

        public void Reset()
        {
            current = -1;
        }
    }
}