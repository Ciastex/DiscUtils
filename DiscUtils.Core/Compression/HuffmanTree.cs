namespace DiscUtils.Core.Compression
{
    /// <summary>
    /// A canonical Huffman tree implementation.
    /// </summary>
    /// <remarks>
    /// A lookup table is created that will take any bit sequence (max tree depth in length),
    /// indicating the output symbol.  In WIM files, in practice, no chunk exceeds 32768 bytes
    /// in length, so we often end up generating a bigger lookup table than the data it's
    /// encoding. This makes for exceptionally fast symbol lookups O(1), but is inefficient
    /// overall.
    /// </remarks>
    internal sealed class HuffmanTree
    {
        private readonly uint[] _buffer;
        private readonly int _numBits; // Max bits per symbol
        private readonly int _numSymbols; // Max symbols

        public HuffmanTree(uint[] lengths)
        {
            Lengths = lengths;
            _numSymbols = lengths.Length;

            uint maxLength = 0;
            for (int i = 0; i < Lengths.Length; ++i)
            {
                if (Lengths[i] > maxLength)
                {
                    maxLength = Lengths[i];
                }
            }

            _numBits = (int)maxLength;
            _buffer = new uint[1 << _numBits];

            Build();
        }

        public uint[] Lengths { get; }

        public uint NextSymbol(BitStream bitStream)
        {
            uint symbol = _buffer[bitStream.Peek(_numBits)];

            // We may have over-read, reset bitstream position
            bitStream.Consume((int)Lengths[symbol]);

            return symbol;
        }

        private void Build()
        {
            int position = 0;

            // For each bit-length...
            for (int i = 1; i <= _numBits; ++i)
            {
                // Check each symbol
                for (uint symbol = 0; symbol < _numSymbols; ++symbol)
                {
                    if (Lengths[symbol] == i)
                    {
                        int numToFill = 1 << (_numBits - i);
                        for (int n = 0; n < numToFill; ++n)
                        {
                            _buffer[position + n] = symbol;
                        }

                        position += numToFill;
                    }
                }
            }

            for (int i = position; i < _buffer.Length; ++i)
            {
                _buffer[i] = uint.MaxValue;
            }
        }
    }
}