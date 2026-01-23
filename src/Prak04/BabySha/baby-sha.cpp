/*
baby_sha -- A weak cryptographic hash function for educational purpose.
Copyright (C) 2010 Christian Maaser

This library is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as
published by the Free Software Foundation; either version 2.1 of the
License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <iostream>
#include <string>


// rotate bits left
unsigned char rol(unsigned char value, unsigned char bits)
{
    return value << bits | value >> (8 - bits);
}

union Block
{
    unsigned int data;
    char buffer[16];
};

union State
{
    unsigned int dword;
    char byte[4];
};

const State DEFAULT_IV = {0x8F1BBCDC};

State baby_sha(Block block, State iv)
{
    // expand data block from 4 bytes to 16 bytes.
    for (unsigned int i = 4; i != 16; ++i)
        block.buffer[i] = rol(block.buffer[i - 4] + block.buffer[i - 3] + block.buffer[i - 2] + block.buffer[i - 1], 5);

    // save state
    unsigned char a = iv.byte[0];
    unsigned char b = iv.byte[1];
    unsigned char c = iv.byte[2];
    unsigned char d = iv.byte[3];

    // for each data byte
    for (unsigned int i = 0; i != 16; ++i)
    {
        unsigned char e = b & c | d & (b | c);
        unsigned char t = rol(a, 3) + e + 0xCA + block.buffer[i];
        d = c;
        c = b;
        b = a;
        a = t;
    }

    // add new state to initial state
    iv.byte[0] += a;
    iv.byte[1] += b;
    iv.byte[2] += c;
    iv.byte[3] += d;

    return iv;
}

State baby_sha(const char* data, unsigned int dataLength, State iv = DEFAULT_IV)
{
    unsigned int offset = 0;
    while (dataLength != 0) {
        Block block;
        block.data = 0;
        for (unsigned int i = 0; i != 4 && dataLength > 0; ++i, --dataLength, ++offset)
            block.buffer[i] = data[offset];
        iv = baby_sha(block, iv);
    }
    return iv;
}

State test_baby_sha(std::string text, State iv = DEFAULT_IV)
{
    State result = baby_sha(text.c_str(), text.length(), iv);
    std::cout << std::hex << "baby_sha(\"" << text << "\", " << iv.dword << ") -> " <<
                 result.dword << std::dec << std::endl;
    return result;
}

int main(int argc, char* argv[])
{
    test_baby_sha("");
    test_baby_sha("Hello world");
    test_baby_sha("Hellp world");
    test_baby_sha("Hellq world");
    test_baby_sha("Iello world");
    test_baby_sha("Jello world");
    test_baby_sha("Hello worle");
    test_baby_sha("Hello worlf");
    test_baby_sha("a");
    test_baby_sha("b");
    test_baby_sha("c");
    test_baby_sha("d");

    // Your code goes here ;o

    return 0;
}

