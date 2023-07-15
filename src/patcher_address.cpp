#include "patcher_address.h"
#include "logger.h"
#include "clientversion.h"
#include "patcher_utils.h"
#include <cstring> // for memcmp
#include <sstream>


bool patch_address(std::fstream& fs, const size_t file_size, const int client_version, const std::string& ip, const int port)
{
    // Precomputations
    const bool isClientTOL = ClientVersion::isTOL(client_version);

    if (g_logger.is_verbose())
        g_logger << "-- Starting patch: address." << std::endl;


    //------------------------//
    //Search signature offsets//
    //------------------------//

    // ** Info about how i found those signatures, and what are them, are at the end of this file **

    size_t offset_port1 = 0;
    //first and second part, between which there is the PP QQ RR SS variable part.
    constexpr byte signature_port1_1[] = { 0xC7, 0x44, 0x24, 0x14 };
    constexpr byte signature_port1_2[] = { 0x66, 0xC7, 0x44, 0x24, 0x18 };

    size_t offset_port2 = 0;
    //first part is 0x89, i don't need an array to manage a single value
    constexpr byte signature_port2[] = { 0x24, 0x14, 0x66, 0xC7, 0x44, 0x24, 0x18 };

    size_t offset_ip = 0;
    constexpr byte signature_ip[] =    { 0x0A, 0, 0x55, 0x4F, 0x53, 0x41, 0x20, 0x2D, 0x20, 0x25, 0x73, 0x20, 0, 0 };

    if (g_logger.is_verbose())
        g_logger << "--- Searching for the signatures... ";

    bool found = false;

    //Searching for first PORT signature
    byte buf_search[50] = {};
    while (fs.good() && size_t(fs.tellg()) < file_size)
    {
        if (find_bytes(&offset_port1, fs, file_size, signature_port1_1, sizeof(signature_port1_1)))
        {
            // if i have found the first part of the signature, move the pointer 4 bytes on and look if there's the second part
            fs.seekg(4, std::fstream::cur);
            fs.read(reinterpret_cast<char*>(buf_search), sizeof(signature_port1_2));

            if (0 == memcmp(buf_search, signature_port1_2, sizeof(signature_port1_2)))
            {
                found = true;
                break;
            }
        }
    }
    if (!found)
    {
        g_logger << "Error. Can't find signature 1 for the port." << std::endl;
        return false;
    }
    

    //Searching for second PORT signature
    //fs.seekg(std::fstream::beg);  //i don't need this, because until now block 2 is always after block 1
    found = false;
    while (fs.good() && size_t(fs.tellg()) < file_size)
    {
        // Search offset
        offset_port2 = size_t(fs.tellg());
        fs.read(reinterpret_cast<char*>(&buf_search), 1);
        if (buf_search[0] == 0x89)
        {
            fs.seekg(1, std::fstream::cur);
            fs.read(reinterpret_cast<char*>(buf_search), sizeof(signature_port2));

            if (0 == memcmp(buf_search, signature_port2, sizeof(signature_port2)))
            {
                found = true;
                break;
            }
        }
    }
    if (!found)
    {
        g_logger << "Error. Can't find signature 2 for the port." << std::endl;
        return false;
    }

    //Searching for IP signature
    //fs.seekg(std::fstream::beg);  //i don't need this, because for now IP block is after port 1 and 2 blocks
    if (!find_bytes(&offset_ip, fs, file_size, signature_ip, sizeof(signature_ip)))
    {
        g_logger << "Error. Can't find signature for the IP." << std::endl;
        return false;
    }

    offset_port1 += 13;     //after the end of the first PORT signature (which length is 13 bytes), there's the PORT value
    offset_port2 += 9;      //second PORT signature is 9 bytes long
    offset_ip += 14;        //IP signature is 14 bytes long

    if (g_logger.is_verbose())
        g_logger << "Success." << std::endl;


    //--------------------//
    //    Write patches   //
    //--------------------//

    if (g_logger.is_verbose())
        g_logger << "--- Applying... ";

    // Divide the port into its two bytes (bytes reversed)
    byte bytes_port[2];
    bytes_port[0] = (byte)(port & 0xFF);
    bytes_port[1] = (byte)((port >> 8) & 0xFF);

    // Separate each field of the ip
    std::string ip_split[4];
    std::istringstream ip_ss(ip);
    for (unsigned i = 0; (i < 4); ++i)
    {
        if (!getline(ip_ss, ip_split[i], '.'))
            break;
    }

    //Write first PORT value (reversed bytes)
    fs.seekp(unsigned_to_signed_ceil(offset_port1), std::fstream::beg);
    fs.write(reinterpret_cast<char*>(&bytes_port[0]), 1);
    fs.write(reinterpret_cast<char*>(&bytes_port[1]), 1);
    if (fs.bad())
    {
        g_logger << "Error. Unexpected upon replacing port 1 code." << std::endl;
        return false;
    }

    //Write second PORT value (reversed bytes)
    fs.seekp(unsigned_to_signed_ceil(offset_port2), std::fstream::beg);
    fs.write(reinterpret_cast<char*>(&bytes_port[0]), 1);
    fs.write(reinterpret_cast<char*>(&bytes_port[1]), 1);
    if (fs.bad())
    {
        g_logger << "Error. Unexpected upon replacing port 2 code." << std::endl;
        return false;
    }

    if (isClientTOL)
    {
        //If it's a Time of Legends or newer client, write third PORT value
        fs.seekp(7, std::fstream::cur);
        fs.write(reinterpret_cast<char*>(&bytes_port[0]), 1);
        fs.write(reinterpret_cast<char*>(&bytes_port[1]), 1);
        if (fs.bad())
        {
            g_logger << "Error. Unexpected upon replacing port 3 code." << std::endl;
            return false;
        }
    }

    //Write IP (as plain text)
    fs.seekp(unsigned_to_signed_ceil(offset_ip), std::ofstream::beg);
    size_t count_ip = 0;
    auto writeIP = [&]() -> bool
    {
        ++count_ip;
        for (unsigned x = 0; x < 4; ++x)       // < 4 because IPv4 addresses have 4 fields, i.e.: 127.0.0.1
        {
            for (size_t y = 0; y < ip_split[x].length(); ++y)
            {
                if (!std::isdigit(ip_split[x][y]))
                    break;
                fs.write(reinterpret_cast<char*>(&ip_split[x][y]), 1);
            }
            if (x < 3)
            {
                constexpr char buf_dot = 0x2E;   //it is the dot (.)
                fs.write(&buf_dot, 1);
            }
        }

        //Since the space for the IP is 16 bytes, i fill with zeroes the remaining space
        constexpr char buf_strterm = 0;
        for (size_t i = size_t(fs.tellp()); i < (offset_ip + (16 * count_ip)); ++i)
            fs.write(&buf_strterm, 1);

        if (fs.bad())
        {
            g_logger << "Error. Unexpected upon replacing IP with: " << count_ip << std::endl;
            return false;
        }
        return true;
    };
    
    if (!writeIP())
        return false;
    if (isClientTOL)
    {
        //If it's a Time of Legends or newer client, i need to write the second IP immediately after

        if (!writeIP())
            return false;
    }

    if (g_logger.is_verbose())
        g_logger << "Success." << std::endl;

    return true;
}


/*
    - WARNING: i know nearly -nothing- of assembly, disassembling and IDA, but i managed to find these infos anyways. I report what i have found on IDA,
    -  i don't know if i'm writing them incorrectly or whatever, the important thing is the message (and the fact that this reasoning works).
*/


    //-- PORT --//

    /*
    The PORT is managed in two code blocks, + 1 if client is Time of Legends.

    FIRST BLOCK
    ------------------------------------------------------------------------
    Assembly                                    |   Hex code (signature)
    ------------------------------------------------------------------------
    mov     [esp+144h+var_130], SSRRQQPPh       |   C7 44 24 14 PP QQ RR SS  (the PPQQRRSS part varies with client versions)
    mov     word ptr [esp+144h+var_12C], XXYYh  |   66 C7 44 24 18 YY XX     (YY XX is the port, with bytes REVERSED)
    ------------------------------------------------------------------------

    SECOND BLOCK
    ------------------------------------------------------------------------
    Assembly                                    |   Hex code (signature)
    ------------------------------------------------------------------------
    mov     [esp+14h], eax                      |   89 TT 24 14              (the TT part varies with client versions)
    mov     dword ptr [esp+18h], XXYYh          |   66 C7 44 24 18 YY XX     (YY XX is the port, with bytes REVERSED)
    ------------------------------------------------------------------------

    PORT in First and Second block is the same (as of 28/11/2015 and 21/04/2019, it is 7775).


    THIRD BLOCK (if Time of Legends or above)
    This is right after the second block, so after that i can simply seek to 7 bytes forward and then overwrite the port.
    ------------------------------------------------------------------------
    Assembly                                    |   Hex code (signature)
    ------------------------------------------------------------------------
    jnz     short loc_*offset*                  |   75 07                    (offset of the last byte of the following mov instruction, which is always 7 bytes length, so jump to current offset + 7)
    mov     word ptr [esp+18h], XXYYh           |   66 C7 44 24 18 YY XX     (YY XX is the port, with bytes REVERSED)
    ------------------------------------------------------------------------

    As of 15/01/2016 and 21/04/2019, the default port in the third block is 7776.
    If the client is TOL+, it looks like the port is selected randomly (there's a call to rand() between 7775 and 7776).
    */


    //-- IP --//

    /*
    The IP is managed in a single code block (it's a string stored in the rdata section, so the address is in the last part of the file,
        but it's referenced in the same method in which the port data is used).

    -----------------------------
    First line:  signature (chars)
    Second line: signature (hex)
        * stands for EMPTY; / stands for SPACE; \n is the newline character
    ----------------------------

    SIGNATURE
    \n   *   U   O   S   A   /   -   /   %   s   /   *   *
    0A  00  55  4F  53  41  20  2D  20  25  73  20  00  00

    Immediately after the signature, i have 16 bytes for the IP.
    If client is Time of Legends, immediately after these 16 bytes i have other 16 bytes for another IP
    (starting from TOL, the client randomly chooses one of the two IPs (there's another call to rand())

    As of 28/11/2015 and 21/04/2019, first IP is 107.23.85.115, second (TOL+) is 107.23.176.74
    */


    //-- Considerations about ip and port code --//

    /*
    So, when the client is TOL+, it may connect to one of the following IP/port combinations (which are also the ones reported in the CC login.cfg):
    LoginServer=107.23.176.74,7775
    LoginServer=107.23.176.74,7776
    LoginServer=107.23.85.115,7775
    LoginServer=107.23.85.115,7776
    */


/*  Disassembled pseudocode of the ip/port function:

void __userpurge sub_60FFA0(int a1@<eax>, int a2, int a3)
{
  int v3; // edi
  _DWORD *v4; // ebp
  _DWORD *v5; // eax
  int v6; // eax
  bool v7; // zf
  signed int v8; // eax
  u_long v9; // edi
  char *v10; // eax
  bool v11; // zf
  signed int v12; // eax
  u_long v13; // [esp+14h] [ebp-130h]
  int v14; // [esp+18h] [ebp-12Ch]
  char v15; // [esp+1Ch] [ebp-128h]
  char ArgList[4]; // [esp+20h] [ebp-124h]
  int v17; // [esp+30h] [ebp-114h]
  unsigned int v18; // [esp+34h] [ebp-110h]
  CHAR String; // [esp+38h] [ebp-10Ch]

  v3 = a1;
  if ( *(a2 + 56) )
  {
    if ( *(a1 + 24) < 0x10u )
      sub_481DA0("LoginAccount: Error: account \"%s\" login already in progress\n", a1 + 4);
    else
      sub_481DA0("LoginAccount: Error: account \"%s\" login already in progress\n", *(a1 + 4));
    return;
  }
  *(a2 + 84) = 1;
  sub_60CDE0(a3);
  v4 = (v3 + 4);
  if ( *(v3 + 24) < 0x10u )
    LOBYTE(v5) = v3 + 4;
  else
    v5 = *v4;
  sub_481DA0("LoginManager::LoginAccount: UI Login started, account \"%s\"\n", v5);
  if ( *(v3 + 24) >= 0x10u )
    v4 = *v4;
  sub_997FBB(&String, 0x104u, "UOSA - %s ", v4);
  sub_483AE0(&String);
  v6 = dword_E2F468;
  v13 = 0;
  LOWORD(v14) = 0;
  if ( dword_E2F468 )
  {
    v13 = *(dword_E2F468 + 156);
    v14 = *(dword_E2F468 + 160);
  }
  else
  {
    if ( *(dword_E2F35C + 457) )
    {
      v13 = -1408232979;
      LOWORD(v14) = 7775;           // PORT BLOCK 1
LABEL_30:
      sub_60CE90(&v13);
      return;
    }
    v18 = 15;
    v17 = 0;
    ArgList[0] = 0;
    v8 = rand() & 0x80000001;
    v7 = v8 == 0;
    if ( v8 < 0 )
      v7 = ((v8 - 1) | 0xFFFFFFFE) == -1;
    if ( v7 )
      TiXmlString::operator=("107.23.176.74");      // IP 2
    else
      TiXmlString::operator=("107.23.85.115");      // IP 1
    sub_485F10();
    v9 = sub_641DC0(&v15);
    if ( !v9 )
    {
      LOBYTE(v10) = ArgList[0];
      if ( v18 < 0x10 )
        v10 = ArgList;
      sub_481DA0("LoginConfig::SetInfoForLogin: Error! DNS lookup failed for loginserver \"%s\"\n", v10);
      *(dword_E2F35C + 8) = 0;
      sub_403770(&v15);
      return;
    }
    v12 = rand() & 0x80000001;
    v11 = v12 == 0;
    if ( v12 < 0 )
      v11 = ((v12 - 1) | 0xFFFFFFFE) == -1;
    v13 = v9;
    LOWORD(v14) = 7775;             // PORT BLOCK 2
    if ( v11 )
      LOWORD(v14) = 7776;           // PORT BLOCK 3
    sub_403770(&v15);
    v6 = dword_E2F468;
  }
  if ( !v6 || !*(v6 + 152) )
    goto LABEL_30;
}

*/
