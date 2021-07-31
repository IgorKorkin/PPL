// ppl_dominate_mask.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "Windows.h"

#include <iostream>
#include <conio.h>
#include <ctype.h>

typedef enum _PS_PROTECTED_TYPE {
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;


typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode,
    PsProtectedSignerCodeGen,
    PsProtectedSignerAntimalware,
    PsProtectedSignerLsa,
    PsProtectedSignerWindows,
    PsProtectedSignerWinTcb,
    PsProtectedSignerWinSystem,
    PsProtectedSignerApp,
    PsProtectedSignerMax
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;

typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;                  // Reserved
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _RTL_PROTECTED_ACCESS {
    DWORD DominateMask;
    DWORD DeniedProcessAccess;
    DWORD DeniedThreadAccess;
}RTL_PROTECTED_ACCESS, * PRTL_PROTECTED_ACCESS;

RTL_PROTECTED_ACCESS RtlProtectedAccess[] =
{
    //   Domination,       Process,         Thread,
   //Index,    Mask,  Restrictions,   Restrictions,
   /*0*/{         0,             0,             0}, //PsProtectedSignerNone               Subject To Restriction Type
   /*1*/{         2,    0x000fc7fe,    0x000fe3fd}, //PsProtectedSignerAuthenticode       0y00000010
   /*2*/{         4,    0x000fc7fe,    0x000fe3fd}, //PsProtectedSignerCodeGen            0y00000100
   /*3*/{     0x108,    0x000fc7ff,    0x000fe3ff}, //PsProtectedSignerAntimalware        0y00001000
   /*4*/{     0x110,    0x000fc7ff,    0x000fe3ff}, //PsProtectedSignerLsa                0y00010000
   /*5*/{     0x13e,    0x000fc7fe,    0x000fe3fd}, //PsProtectedSignerWindows            0y00111110
   /*6*/{     0x17e,    0x000fc7ff,    0x000fe3ff}, //PsProtectedSignerWinTcb             0y01111110
   /*7*/{     0x1fe,    0x000fc7ff,    0x000ff7ff}, //PsProtectedSignerWinSystem          0y01111110
   /*8*/{         0,    0x000fc6fe,    0x000fe3fd}, //PsProtectedSignerApp                0y00000000
};


bool RtlTestProtectedAccessFull(PS_PROTECTION CallerProt, PS_PROTECTION TargetProt)
{
    // Allow access to the non-protected processes - the mimikatz case
    if (TargetProt.Type == 0)
        return true;

    // Restrict access to the Caller with lower protection Type than the Target
    if (CallerProt.Type < TargetProt.Type)
        return false;

    // Check whether the Target Signer value can be accessed from the Caller Signer value
    auto CallerDominateMask = RtlProtectedAccess[CallerProt.Signer].DominateMask;
    auto TargetMask = (1 << TargetProt.Signer);
    if (CallerDominateMask & TargetMask)
    {
        return true;
    }
    return false;
	//return bittest(&RtlProtectedAccess[CallerProt.Signer].DominateMask, TargetProt.Signer);
}

bool RtlTestProtectedAccessSimple(PS_PROTECTION CallerProt, PS_PROTECTION TargetProt)
{
    // Allow access to the non-protected processes - mimikatz case
    if (TargetProt.Type == 0)
        return true;

    // Restrict access to the Caller with lower protection Type than the Target
    if (CallerProt.Type < TargetProt.Type)
        return false;

    // Check whether the Target Signer value can be accessed from the Caller Signer value  
    if (CallerProt.Signer >= TargetProt.Signer) 
    {
        return true;
    }
    return false;
}

void check(PS_PROTECTION CallerProt, PS_PROTECTION TargetProt)
{
    bool simple = RtlTestProtectedAccessSimple(CallerProt, TargetProt);
    bool full = RtlTestProtectedAccessFull(CallerProt, TargetProt);

    auto simple_res = (simple == true) ? "true" : "false";
    auto full_res = (full == true) ? "true" : "false";
    auto sum_res = (simple == full) ? "SAME" : "NOT-SAME";

    std::cout << std::hex
        << " Caller " << (int)CallerProt.Level
        << " --> Target " << (int)TargetProt.Level
        << "  simple = " << simple_res
        << "  full = " << full_res
        << "  res = " << sum_res
        << std::endl;
}


int main()
{
    std::cout << "Who dominates whom? " << std::endl;

    check({ 0x42 }, { 0x10 });
    check({ 0x42 }, { 0x11 });
    check({ 0x42 }, { 0x12 });
    
    check({ 0x42 }, { 0x20 });
    check({ 0x42 }, { 0x21 });
    check({ 0x42 }, { 0x22 });

    check({ 0x42 }, { 0x30 });
    check({ 0x42 }, { 0x31 });
    check({ 0x42 }, { 0x32 });

    check({ 0x42 }, { 0x40 });
    check({ 0x42 }, { 0x41 });
    check({ 0x42 }, { 0x42 });

    check({ 0x42 }, { 0x50 });
    check({ 0x42 }, { 0x51 });
    check({ 0x42 }, { 0x52 });

    check({ 0x42 }, { 0x60 });
    check({ 0x42 }, { 0x61 });
    check({ 0x42 }, { 0x62 });

    check({ 0x42 }, { 0x70 });
    check({ 0x42 }, { 0x71 });
    check({ 0x42 }, { 0x72 });

    check({ 0x42 }, { 0x80 });
    check({ 0x42 }, { 0x81 });
    check({ 0x42 }, { 0x82 });




    check({ 0x62 }, { 0x10 });
    check({ 0x62 }, { 0x11 });
    check({ 0x62 }, { 0x12 });

    check({ 0x62 }, { 0x20 });
    check({ 0x62 }, { 0x21 });
    check({ 0x62 }, { 0x22 });
    
	check({ 0x62 }, { 0x30 });
    check({ 0x62 }, { 0x31 });
    check({ 0x62 }, { 0x32 });
    
	check({ 0x62 }, { 0x40 });
    check({ 0x62 }, { 0x41 });
    check({ 0x62 }, { 0x42 });
    
	check({ 0x62 }, { 0x50 });
    check({ 0x62 }, { 0x51 });
    check({ 0x62 }, { 0x52 });
    
	check({ 0x62 }, { 0x60 });
    check({ 0x62 }, { 0x61 });
    check({ 0x62 }, { 0x62 });
    
	check({ 0x62 }, { 0x70 });
    check({ 0x62 }, { 0x71 });
    check({ 0x62 }, { 0x72 });
    
	check({ 0x62 }, { 0x80 });
    check({ 0x62 }, { 0x81 });
    check({ 0x62 }, { 0x82 });

	_getch();
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
