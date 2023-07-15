#include "patcher_encryption.h"
#include "patcher_utils.h"


/* Encryption code signatures*/

//--Inside a UOGameCipher_C2S_Encrypt putative method
size_t offset_encr_1 = 0;
static constexpr byte signature_encr_1[] = { 0x30, 0x45, 0x00, 0x83, 0x83, 0x4C, 0x12, 0x00, 0x00, 0x01, 0x5D, 0x5B };

//--Inside a UOGameCipher_S2C_Decrypt putative method
size_t offset_encr_2 = 0;
static constexpr byte signature_encr_2[] = { 0x30, 0x10, 0x83, 0x46, 0x18, 0x01, 0x8B, 0x45, 0x0C, 0x83, 0xC7, 0x01, 0x3B, 0xFB, 0x72, 0xD5 };

//--Inside a UOLoginCipher_C2S_Encrypt putative method
size_t offset_encr_3 = 0;
static constexpr byte signature_encr_3[] = { 0x30, 0x08, 0x8B, 0x4E, 0x04, 0x8B, 0x46, 0x08, 0x8B, 0xD0, 0xD1, 0xE8, 0x8B, 0xF9 };


/*
bool patch_encryption(std::fstream& fs, const size_t file_size, const int client_version)
{

    if (g_logger.is_verbose())
            g_logger << "-- Starting patch: encryption." << std::endl;

    if (checkBox_encryption.Checked)
    {
                //Console.WriteLine(String.Format("Encryption signature offsets: {0:X} {1:X} {2:X}", offset_encr_1, offset_encr_2, offset_encr_3));

                writer.BaseStream.Seek(offset_encr_1, SeekOrigin.Begin);
                writer.Write((byte)0x90);
                writer.Write((byte)0x90);
                writer.Write((byte)0x90);

                writer.BaseStream.Seek(offset_encr_2, SeekOrigin.Begin);
                writer.Write((byte)0x90);
                writer.Write((byte)0x90);

                writer.BaseStream.Seek(offset_encr_3, SeekOrigin.Begin);
                writer.Write((byte)0x90);
                writer.Write((byte)0x90);
            }

}


fs.seekg(0, std::fstream::beg);

*/


/*
For the ENCRYPTION, there's some more work to do.
Bear in mind, in assembly NOP stands for the no-op instruction (it does nothing: useful to nullify some code). In hex, it's 0x90.


    FIRST BLOCK
    ------------------------------------------------------------------------
    Assembly                            |   Hex code (signature)
    ------------------------------------------------------------------------
    mov     edx, [ebx+124Ch]            |   8B 93 4C 12 00 00
    mov     al, [edx+ebx+114Ch]         |   8A 84 1A 4C 11 00 00
    xor     [ebp+0], al                 |   30 45 00 (we need to NOP it, overwriting it with 90 90 90)
    add     dword ptr [ebx+124Ch], 1    |   83 83 4C 12 00 00 01
    pop     ebp                         |   5D
    pop     ebx                         |   5B
    add     esp, 100h                   |   81 C4 00 01 00 00
    ------------------------------------------------------------------------
    Disassembled pseudocode of the whole function:
        (called by a function which is in turn referenced by [DATA XREF: .rdata:]const UOGameCipher_C2S_Encrypt::`vftable'↓o)   // client to server?
        char __stdcall sub_635430(int a1, _BYTE *a2)
        {
          char result; // al
          char v3; // [esp+8h] [ebp-100h]

          if ( *(a1 + 4684) == 256 )
          {
            sub_A63B5E(a1 + 4388, a1, a1 + 4428, 2048, &v3);
            qmemcpy((a1 + 4428), &v3, 0x100u);
            *(a1 + 4684) = 0;
          }
          result = *(*(a1 + 4684) + a1 + 4428);
          *a2 ^= result;        // we want to nullify this assignment
          ++*(a1 + 4684);
          return result;
        }


    SECOND BLOCK
    ------------------------------------------------------------------------
    Assembly                            |   Hex code (signature)
    ------------------------------------------------------------------------
    mov     dl, [ecx+esi+8]             |   8A 54 31 08
    xor     [eax], dl                   |   30 10 (we need to NOP it, overwriting it with 90 90)
    add     dword ptr [esi+18h], 1      |   83 46 18 01
    mov     eax, [ebp+0Ch]              |   8B 45 0C
    add     edi, 1                      |   83 C7 01
    cmp     edi, ebx                    |   3B FB
    jb      short loc_23A750            |   72 D5
    ------------------------------------------------------------------------
    Disassembled pseudocode of the whole function:
        (referenced by [DATA XREF: .rdata:]const UOGameCipher_S2C_Decrypt::`vftable'↓o)     server to client?
        _DWORD *__thiscall sub_637330(_BYTE *this, _DWORD *a2, _DWORD *a3, volatile signed __int32 *a4)
        {
          _DWORD *v4; // eax
          unsigned int v5; // edi
          unsigned int v6; // ebx
          _BYTE *v7; // esi
          _BYTE *v8; // eax

          v4 = a3;
          v5 = 0;
          v6 = a3[12] - a3[13];
          v7 = this;
          if ( a3[12] != a3[13] )
          {
            do
            {
              v8 = sub_63E5F0(v4, v5);
              *v8 ^= v7[(*(v7 + 6))++ % 16 + 8];    // we want to nullify this assignment
              v4 = a3;
              ++v5;
            }
            while ( v5 < v6 );
          }
          *(v7 + 1) += v6;
          *a2 = v4;
          a2[1] = a4;
          if ( a4 )
          {
            _InterlockedExchangeAdd(a4 + 1, 1u);
            if ( !_InterlockedExchangeAdd(a4 + 1, 0xFFFFFFFF) )
            {
              (*(*a4 + 4))(a4);
              if ( !_InterlockedExchangeAdd(a4 + 2, 0xFFFFFFFF) )
         (*(*a4 + 8))(a4);
            }
          }
          return a2;
        }


    THIRD BLOCK
    ------------------------------------------------------------------------
    Assembly                    |   Hex code (signature)
    ------------------------------------------------------------------------
    xor     [eax], cl           |   30 08   (we need to NOP it, overwriting it with 90 90)
    mov     ecx, [esi+4]        |   8B 4E 04
    mov     eax, [esi+8]        |   8B 46 08
    mov     edx, eax            |   8B D0
    shr     eax, 1              |   D1 E8
    mov     edi, ecx            |   8B F9
    shl     edi, 1Fh            |   C1 E7 1F
    ------------------------------------------------------------------------
    Disassebled pseudocode of the whole function:
        (referenced by [DATA XREF: .rdata:]const UOLoginCipher_C2S_Encrypt::`vftable'↓o)    client to server?
        _DWORD *__thiscall sub_637C50(_BYTE *this, _DWORD *a2, _DWORD *a3, volatile signed __int32 *a4)
        {
          _DWORD *v4; // eax
          _BYTE *v5; // esi
          unsigned int v6; // ebx
          int v7; // ecx
          _DWORD *v8; // eax
          unsigned int v9; // ecx
          unsigned int v11; // [esp+Ch] [ebp-4h]

          v4 = a3;
          v5 = this;
          v6 = 0;
          v7 = a3[12] - a3[13];
          v11 = a3[12] - a3[13];
          if ( a3[12] != a3[13] )
          {
            do
            {
              v8 = sub_63E5F0(v4, v6);
              *v8 ^= v5[4];     // we want to nullify this assignment
              ++v6;
              v9 = ((*(v5 + 2) << 31) | (*(v5 + 1) >> 1)) ^ 0xB5E2127F;
              *(v5 + 2) = (&loc_AF8639 + 4) ^ ((*(v5 + 1) << 31) | (((&loc_AF8639 + 3) ^ ((*(v5 + 1) << 31) | (*(v5 + 2) >> 1))) >> 1));
              v4 = a3;
              *(v5 + 1) = v9;
            }
            while ( v6 < v11 );
            v7 = v11;
          }
          *(v5 + 5) += v7;
          *a2 = v4;
          a2[1] = a4;
          if ( a4 )
          {
            _InterlockedExchangeAdd(a4 + 1, 1u);
            if ( !_InterlockedExchangeAdd(a4 + 1, 0xFFFFFFFF) )
            {
              (*(*a4 + 4))(a4);
              if ( !_InterlockedExchangeAdd(a4 + 2, 0xFFFFFFFF) )
         (*(*a4 + 8))(a4);
            }
          }
          return a2;
        }


    Disassembled pseudocode of sub_63E5F0:
        _DWORD *__stdcall sub_63E5F0(_DWORD *a1, int a2)
        {
          int v2; // esi
          unsigned int v3; // edi
          unsigned int v4; // ebx
          unsigned int v5; // eax
          int v7; // [esp+18h] [ebp-8h]
          int v8; // [esp+1Ch] [ebp-4h]

          v2 = a1[3];
          v3 = a2 + a1[13];
          v4 = 0;
          v7 = a1[5];
          v8 = a1[6];
          if ( v2 == a1[7] )
            return a1 + 14;
          while ( 1 )
          {
            v5 = v4 + (*(**v2 + 4))();
            if ( v3 < v5 && v3 >= v4 )
              break;
            v2 += 8;
            v4 = v5;
            if ( v2 == v7 )
            {
              v2 = *(v8 + 4);
              v8 += 4;
              v7 = v2 + 256;
            }
            if ( v2 == a1[7] )
              return a1 + 14;
          }
          return (*(**v2 + 8))(v3 - v4);
        }
*/
