// Function: FUN_140001000

void FUN_140001000(void)

{
  return;
}



// Function: mainCRTStartup

int mainCRTStartup(void)

{
  int iVar1;
  
  *(undefined4 *)_refptr___mingw_app_type = 0;
  iVar1 = __tmainCRTStartup();
  return iVar1;
}



// Function: __tmainCRTStartup

int __tmainCRTStartup(void)

{
  longlong lVar1;
  bool bVar2;
  longlong lVar3;
  LPTOP_LEVEL_EXCEPTION_FILTER pPVar4;
  longlong unaff_GS_OFFSET;
  
  lVar1 = *(longlong *)(*(longlong *)(unaff_GS_OFFSET + 0x30) + 8);
  bVar2 = false;
  while( true ) {
    LOCK();
    lVar3 = *(longlong *)_refptr___native_startup_lock;
    if (lVar3 == 0) {
      *(longlong *)_refptr___native_startup_lock = lVar1;
      lVar3 = 0;
    }
    UNLOCK();
    if (lVar3 == 0) goto LAB_1400011e3;
    if (lVar3 == lVar1) break;
    Sleep(1000);
  }
  bVar2 = true;
LAB_1400011e3:
  if (*(int *)_refptr___native_startup_state == 1) {
    _amsg_exit(0x1f);
  }
  else if (*(int *)_refptr___native_startup_state == 0) {
    *(undefined4 *)_refptr___native_startup_state = 1;
    _initterm(_refptr___xi_a,_refptr___xi_z);
  }
  else {
    has_cctor = 1;
  }
  if (*(int *)_refptr___native_startup_state == 1) {
    _initterm(_refptr___xc_a,_refptr___xc_z);
    *(undefined4 *)_refptr___native_startup_state = 2;
  }
  if (!bVar2) {
    LOCK();
    *(undefined8 *)_refptr___native_startup_lock = 0;
    UNLOCK();
  }
  if (*(longlong *)_refptr___dyn_tls_init_callback != 0) {
    (**(code **)_refptr___dyn_tls_init_callback)(0,2,0);
  }
  _pei386_runtime_relocator();
  pPVar4 = SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)_refptr__gnu_exception_handler)
  ;
  *(LPTOP_LEVEL_EXCEPTION_FILTER *)_refptr___mingw_oldexcpt_handler = pPVar4;
  _set_invalid_parameter_handler(FUN_140001000);
  fpreset();
  duplicate_ppstrings(argc,(longlong *)&argv);
  __main();
  **(undefined8 **)_refptr___imp___initenv = envp;
  mainret = main(argc,argv,envp);
  if (managedapp != 0) {
    if (has_cctor == 0) {
      _cexit();
    }
    return mainret;
  }
                    /* WARNING: Subroutine does not return */
  exit(mainret);
}



// Function: check_managed_app

bool check_managed_app(void)

{
  int *piVar1;
  bool bVar2;
  
  *(undefined4 *)_refptr___mingw_initltsdrot_force = 1;
  *(undefined4 *)_refptr___mingw_initltsdyn_force = 1;
  *(undefined4 *)_refptr___mingw_initltssuo_force = 1;
  if (*(short *)_refptr___ImageBase == 0x5a4d) {
    piVar1 = (int *)(_refptr___ImageBase + *(int *)(_refptr___ImageBase + 0x3c));
    if (*piVar1 == 0x4550) {
      if ((short)piVar1[6] == 0x10b) {
        if ((uint)piVar1[0x1d] < 0xf) {
          bVar2 = false;
        }
        else {
          bVar2 = piVar1[0x3a] != 0;
        }
      }
      else if ((short)piVar1[6] == 0x20b) {
        if ((uint)piVar1[0x21] < 0xf) {
          bVar2 = false;
        }
        else {
          bVar2 = piVar1[0x3e] != 0;
        }
      }
      else {
        bVar2 = false;
      }
    }
    else {
      bVar2 = false;
    }
  }
  else {
    bVar2 = false;
  }
  return bVar2;
}



// Function: duplicate_ppstrings

void duplicate_ppstrings(int param_1,longlong *param_2)

{
  longlong lVar1;
  void *pvVar2;
  size_t sVar3;
  void *pvVar4;
  undefined4 local_1c;
  
  pvVar2 = malloc((longlong)(param_1 + 1) << 3);
  lVar1 = *param_2;
  for (local_1c = 0; local_1c < param_1; local_1c = local_1c + 1) {
    sVar3 = strlen(*(char **)(lVar1 + (longlong)local_1c * 8));
    pvVar4 = malloc(sVar3 + 1);
    *(void **)((longlong)local_1c * 8 + (longlong)pvVar2) = pvVar4;
    memcpy(*(void **)((longlong)pvVar2 + (longlong)local_1c * 8),
           *(void **)(lVar1 + (longlong)local_1c * 8),sVar3 + 1);
  }
  *(undefined8 *)((longlong)pvVar2 + (longlong)local_1c * 8) = 0;
  *param_2 = (longlong)pvVar2;
  return;
}



// Function: atexit

int __cdecl atexit(_func_5014 *param_1)

{
  int iVar1;
  _onexit_t p_Var2;
  
  p_Var2 = _onexit((_onexit_t)param_1);
  if (p_Var2 == (_onexit_t)0x0) {
    iVar1 = -1;
  }
  else {
    iVar1 = 0;
  }
  return iVar1;
}



// Function: .weak.__register_frame_info.hmod_libgcc

void _weak___register_frame_info_hmod_libgcc(void)

{
  return;
}



// Function: __gcc_register_frame

void __gcc_register_frame(void)

{
  HMODULE hModule;
  code *pcVar1;
  
  hModule = GetModuleHandleA("libgcc_s_dw2-1.dll");
  if (hModule == (HMODULE)0x0) {
    pcVar1 = _weak___register_frame_info_hmod_libgcc;
    DAT_140004000 = (FARPROC)&_weak___deregister_frame_info_hmod_libgcc;
  }
  else {
    hmod_libgcc = LoadLibraryA("libgcc_s_dw2-1.dll");
    pcVar1 = GetProcAddress(hModule,"__register_frame_info");
    DAT_140004000 = GetProcAddress(hModule,"__deregister_frame_info");
    if (pcVar1 == (FARPROC)0x0) goto LAB_140001653;
  }
  (*pcVar1)(&DAT_140006000,&obj);
LAB_140001653:
  atexit(__gcc_deregister_frame);
  return;
}



// Function: __gcc_deregister_frame

void __gcc_deregister_frame(void)

{
  if (DAT_140004000 != (code *)0x0) {
    (*DAT_140004000)(&DAT_140006000);
  }
  if (hmod_libgcc != (HMODULE)0x0) {
                    /* WARNING: Could not recover jumptable at 0x0001400016be. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    FreeLibrary(hmod_libgcc);
    return;
  }
  return;
}



// Function: main

int __cdecl main(int _Argc,char **_Argv,char **_Env)

{
  int iVar1;
  
  iVar1 = printf(message);
  return iVar1;
}



// Function: __do_global_dtors

void __do_global_dtors(void)

{
  for (; *(longlong *)p_0 != 0; p_0 = p_0 + 8) {
    (**(code **)p_0)();
  }
  return;
}



// Function: __do_global_ctors

void __do_global_ctors(void)

{
  uint local_10;
  uint local_c;
  
  local_c = (uint)*(undefined8 *)_refptr___CTOR_LIST__;
  if (local_c == 0xffffffff) {
    local_c = 0;
    while (*(longlong *)(_refptr___CTOR_LIST__ + (ulonglong)(local_c + 1) * 8) != 0) {
      local_c = local_c + 1;
    }
  }
  for (local_10 = local_c; local_10 != 0; local_10 = local_10 - 1) {
    (**(code **)(_refptr___CTOR_LIST__ + (ulonglong)local_10 * 8))();
  }
  atexit(__do_global_dtors);
  return;
}



// Function: __main

void __main(void)

{
  if (initialized == 0) {
    initialized = 1;
    __do_global_ctors();
  }
  return;
}



// Function: _setargv

int __cdecl _setargv(void)

{
  return 0;
}



// Function: __dyn_tls_init

undefined8 __dyn_tls_init(undefined8 param_1,int param_2)

{
  longlong *local_10;
  
  if (*(int *)_refptr__CRT_MT != 2) {
    *(undefined4 *)_refptr__CRT_MT = 2;
  }
  if (param_2 == 2) {
    for (local_10 = &_CRT_XDZ; local_10 != &_CRT_XDZ; local_10 = local_10 + 1) {
      if (*local_10 != 0) {
        (*(code *)*local_10)();
      }
    }
  }
  else if (param_2 == 1) {
    __mingw_TLScallback(param_1,1);
  }
  return 1;
}



// Function: __dyn_tls_dtor

undefined8 __dyn_tls_dtor(undefined8 param_1,uint param_2)

{
  if ((param_2 == 3) || (param_2 == 0)) {
    __mingw_TLScallback(param_1,param_2);
  }
  return 1;
}



// Function: _matherr

int __cdecl _matherr(_exception *_Except)

{
  double param6;
  double param5;
  double param4;
  char *param3;
  FILE *param0;
  char *local_50;
  
  switch(_Except->type) {
  default:
    local_50 = "Unknown error";
    break;
  case 1:
    local_50 = "Argument domain error (DOMAIN)";
    break;
  case 2:
    local_50 = "Argument singularity (SIGN)";
    break;
  case 3:
    local_50 = "Overflow range error (OVERFLOW)";
    break;
  case 4:
    local_50 = "The result is too small to be represented (UNDERFLOW)";
    break;
  case 5:
    local_50 = "Total loss of significance (TLOSS)";
    break;
  case 6:
    local_50 = "Partial loss of significance (PLOSS)";
  }
  param6 = _Except->retval;
  param5 = _Except->arg2;
  param4 = _Except->arg1;
  param3 = _Except->name;
  param0 = (FILE *)__acrt_iob_func(2);
  fprintf(param0,"_matherr(): %s in %s(%g, %g)  (retval=%g)\n",local_50,param3,param4,param5,param6)
  ;
  return 0;
}



// Function: fpreset

void __cdecl fpreset(void)

{
  return;
}



// Function: __report_error

void __report_error(char *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  FILE *pFVar1;
  undefined8 local_res10;
  undefined8 local_res18;
  undefined8 local_res20;
  
  local_res10 = param_2;
  local_res18 = param_3;
  local_res20 = param_4;
  pFVar1 = (FILE *)__acrt_iob_func(2);
  fwrite("Mingw-w64 runtime failure:\n",1,0x1b,pFVar1);
  pFVar1 = (FILE *)__acrt_iob_func(2);
  vfprintf(pFVar1,param_1,(va_list)&local_res10);
                    /* WARNING: Subroutine does not return */
  abort();
}



// Function: mark_section_writable

void mark_section_writable(ulonglong param_1,undefined8 param_2,longlong param_3,undefined8 param_4)

{
  BOOL BVar1;
  DWORD DVar2;
  IMAGE_DOS_HEADER *pIVar3;
  SIZE_T SVar4;
  PDWORD lpflOldProtect;
  ulonglong uVar5;
  _MEMORY_BASIC_INFORMATION local_48;
  PIMAGE_SECTION_HEADER local_18;
  uint local_10;
  int local_c;
  
  local_c = 0;
  while( true ) {
    if (maxSections <= local_c) {
      local_18 = __mingw_GetSectionForAddress(param_1);
      if (local_18 == (PIMAGE_SECTION_HEADER)0x0) {
        __report_error("Address %p has no image-section",param_1,param_3,param_4);
      }
      *(PIMAGE_SECTION_HEADER *)(the_secs + (longlong)local_c * 0x28 + 0x20) = local_18;
      *(undefined4 *)((longlong)local_c * 0x28 + the_secs) = 0;
      pIVar3 = _GetPEImageBase();
      uVar5 = (ulonglong)local_18->VirtualAddress;
      *(char **)((longlong)local_c * 0x28 + the_secs + 0x18) = pIVar3->e_magic + uVar5;
      SVar4 = VirtualQuery(*(LPCVOID *)((longlong)local_c * 0x28 + the_secs + 0x18),&local_48,0x30);
      if (SVar4 == 0) {
        __report_error("  VirtualQuery failed for %d bytes at address %p",
                       (ulonglong)(local_18->Misc).PhysicalAddress,
                       *(undefined8 *)((longlong)local_c * 0x28 + the_secs + 0x18),uVar5);
      }
      if ((((local_48.Protect != 0x40) && (local_48.Protect != 4)) && (local_48.Protect != 0x80)) &&
         (local_48.Protect != 8)) {
        if (local_48.Protect == 2) {
          local_10 = 4;
        }
        else {
          local_10 = 0x40;
        }
        *(PVOID *)(the_secs + (longlong)local_c * 0x28 + 8) = local_48.BaseAddress;
        *(SIZE_T *)(the_secs + (longlong)local_c * 0x28 + 0x10) = local_48.RegionSize;
        lpflOldProtect = (PDWORD)((longlong)local_c * 0x28 + the_secs);
        uVar5 = (ulonglong)local_10;
        BVar1 = VirtualProtect(local_48.BaseAddress,local_48.RegionSize,local_10,lpflOldProtect);
        if (BVar1 == 0) {
          DVar2 = GetLastError();
          __report_error("  VirtualProtect failed with code 0x%x",(ulonglong)DVar2,uVar5,
                         lpflOldProtect);
        }
      }
      maxSections = maxSections + 1;
      return;
    }
    if ((*(ulonglong *)((longlong)local_c * 0x28 + the_secs + 0x18) <= param_1) &&
       (param_3 = the_secs,
       param_1 < (ulonglong)*(uint *)(*(longlong *)((longlong)local_c * 0x28 + the_secs + 0x20) + 8)
                 + *(longlong *)((longlong)local_c * 0x28 + the_secs + 0x18))) break;
    local_c = local_c + 1;
  }
  return;
}



// Function: restore_modified_sections

void restore_modified_sections(void)

{
  DWORD local_10;
  int local_c;
  
  for (local_c = 0; local_c < maxSections; local_c = local_c + 1) {
    if (*(int *)((longlong)local_c * 0x28 + the_secs) != 0) {
      VirtualProtect(*(LPVOID *)((longlong)local_c * 0x28 + the_secs + 8),
                     *(SIZE_T *)((longlong)local_c * 0x28 + the_secs + 0x10),
                     *(DWORD *)((longlong)local_c * 0x28 + the_secs),&local_10);
    }
  }
  return;
}



// Function: __write_memory

void __write_memory(void *param_1,void *param_2,size_t param_3,undefined8 param_4)

{
  if (param_3 != 0) {
    mark_section_writable((ulonglong)param_1,param_2,param_3,param_4);
    memcpy(param_1,param_2,param_3);
  }
  return;
}



// Function: do_pseudo_reloc

void do_pseudo_reloc(uint *param_1,uint *param_2,ulonglong *param_3,longlong param_4)

{
  uint *puVar1;
  uint uVar2;
  byte bVar3;
  ulonglong *puVar4;
  int local_54;
  ulonglong local_50;
  longlong local_48;
  longlong local_40;
  uint local_34;
  longlong local_30;
  ulonglong *local_28;
  uint *local_20;
  uint *local_18;
  uint *local_10;
  
  local_28 = (ulonglong *)((longlong)param_2 - (longlong)param_1);
  if (7 < (longlong)local_28) {
    local_10 = param_1;
    if ((((0xb < (longlong)local_28) && (*param_1 == 0)) && (param_1[1] == 0)) && (param_1[2] == 0))
    {
      local_10 = param_1 + 3;
    }
    if ((*local_10 == 0) && (local_10[1] == 0)) {
      puVar4 = param_3;
      puVar1 = local_10;
      if (local_10[2] != 1) {
        __report_error("  Unknown pseudo relocation protocol version %d.\n",(ulonglong)local_10[2],
                       param_3,param_4);
        puVar1 = local_10;
      }
      while (local_18 = puVar1 + 3, local_18 < param_2) {
        local_28 = (ulonglong *)((longlong)param_3 + (ulonglong)puVar1[4]);
        local_30 = *(longlong *)((longlong)param_3 + (ulonglong)*local_18);
        uVar2 = puVar1[5] & 0xff;
        if (uVar2 == 0x40) {
          local_50 = *local_28;
        }
        else if (uVar2 < 0x41) {
          if (uVar2 == 0x20) {
            local_50 = (ulonglong)(uint)*local_28;
            if (((uint)*local_28 & 0x80000000) != 0) {
              local_50 = local_50 | 0xffffffff00000000;
            }
          }
          else {
            if (0x20 < uVar2) goto LAB_140002098;
            if (uVar2 == 8) {
              local_50 = (ulonglong)(byte)*local_28;
              if (((byte)*local_28 & 0x80) != 0) {
                local_50 = local_50 | 0xffffffffffffff00;
              }
            }
            else {
              if (uVar2 != 0x10) goto LAB_140002098;
              local_50 = (ulonglong)(ushort)*local_28;
              if (((ushort)*local_28 & 0x8000) != 0) {
                local_50 = local_50 | 0xffffffffffff0000;
              }
            }
          }
        }
        else {
LAB_140002098:
          local_50 = 0;
          __report_error("  Unknown pseudo relocation bit size %d.\n",(ulonglong)(puVar1[5] & 0xff),
                         puVar4,param_4);
        }
        local_50 = local_30 + (local_50 - ((ulonglong)*local_18 + (longlong)param_3));
        local_34 = local_18[2] & 0xff;
        if (local_34 < 0x40) {
          bVar3 = (byte)local_18[2];
          local_40 = (1L << (bVar3 & 0x3f)) + -1;
          local_48 = -1L << (bVar3 - 1 & 0x3f);
          if ((local_40 < (longlong)local_50) || ((longlong)local_50 < local_48)) {
            puVar4 = local_28;
            param_4 = local_30;
            __report_error("%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p.\n"
                           ,(ulonglong)local_34,local_28,local_30);
          }
        }
        uVar2 = local_18[2] & 0xff;
        if (uVar2 == 0x40) {
          puVar4 = (ulonglong *)0x8;
          __write_memory(local_28,&local_50,8,param_4);
          puVar1 = local_18;
        }
        else {
          puVar1 = local_18;
          if (uVar2 < 0x41) {
            if (uVar2 == 0x20) {
              puVar4 = (ulonglong *)0x4;
              __write_memory(local_28,&local_50,4,param_4);
              puVar1 = local_18;
            }
            else if (uVar2 < 0x21) {
              if (uVar2 == 8) {
                puVar4 = (ulonglong *)0x1;
                __write_memory(local_28,&local_50,1,param_4);
                puVar1 = local_18;
              }
              else if (uVar2 == 0x10) {
                puVar4 = (ulonglong *)0x2;
                __write_memory(local_28,&local_50,2,param_4);
                puVar1 = local_18;
              }
            }
          }
        }
      }
    }
    else {
      for (local_20 = local_10; local_20 < param_2; local_20 = local_20 + 2) {
        local_28 = (ulonglong *)((longlong)param_3 + (ulonglong)local_20[1]);
        local_54 = *local_20 + *(int *)local_28;
        __write_memory(local_28,&local_54,4,param_4);
      }
    }
  }
  return;
}



// Function: _pei386_runtime_relocator

/* WARNING: Function: ___chkstk_ms replaced with injection: alloca_probe */

void _pei386_runtime_relocator(void)

{
  longlong lVar1;
  word wVar2;
  undefined6 extraout_var;
  longlong in_R9;
  undefined8 auStack_40 [6];
  undefined1 auStack_10 [4];
  int local_c;
  
  if (was_init_0 == 0) {
    was_init_0 = 1;
    auStack_40[0] = 0x140002242;
    wVar2 = __mingw_GetSectionCount();
    local_c = (int)CONCAT62(extraout_var,wVar2);
    auStack_40[0] = 0x14000226a;
    lVar1 = -((longlong)local_c * 0x28 + 0xfU & 0xfffffffffffffff0);
    the_secs = auStack_10 + lVar1;
    maxSections = 0;
    *(undefined8 *)((longlong)auStack_40 + lVar1) = 0x1400022af;
    do_pseudo_reloc((uint *)_refptr___RUNTIME_PSEUDO_RELOC_LIST__,
                    (uint *)_refptr___RUNTIME_PSEUDO_RELOC_LIST_END__,
                    (ulonglong *)_refptr___ImageBase,in_R9);
    *(undefined8 *)((longlong)auStack_40 + lVar1) = 0x1400022b4;
    restore_modified_sections();
  }
  return;
}



// Function: __mingw_setusermatherr

void __mingw_setusermatherr(undefined8 param_1)

{
  stUserMathErr = param_1;
  __setusermatherr(param_1);
  return;
}



// Function: __mingwthr_run_key_dtors

void __mingwthr_run_key_dtors(void)

{
  DWORD DVar1;
  LPVOID pvVar2;
  DWORD *local_10;
  
  if (__mingwthr_cs_init != 0) {
    EnterCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
    for (local_10 = key_dtor_list; local_10 != (DWORD *)0x0; local_10 = *(DWORD **)(local_10 + 4)) {
      pvVar2 = TlsGetValue(*local_10);
      DVar1 = GetLastError();
      if ((DVar1 == 0) && (pvVar2 != (LPVOID)0x0)) {
        (**(code **)(local_10 + 2))(pvVar2);
      }
    }
    LeaveCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
  }
  return;
}



// Function: __mingw_TLScallback

undefined8 __mingw_TLScallback(undefined8 param_1,uint param_2)

{
  void *pvVar1;
  void *local_10;
  
  if (param_2 == 3) {
    __mingwthr_run_key_dtors();
  }
  else if (param_2 < 4) {
    if (param_2 == 2) {
      fpreset();
    }
    else if (param_2 < 3) {
      if (param_2 == 0) {
        __mingwthr_run_key_dtors();
        if (__mingwthr_cs_init == 1) {
          local_10 = key_dtor_list;
          while (local_10 != (void *)0x0) {
            pvVar1 = *(void **)((longlong)local_10 + 0x10);
            free(local_10);
            local_10 = pvVar1;
          }
          key_dtor_list = (void *)0x0;
          __mingwthr_cs_init = 0;
          DeleteCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
        }
      }
      else if (param_2 == 1) {
        if (__mingwthr_cs_init == 0) {
          InitializeCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
        }
        __mingwthr_cs_init = 1;
      }
    }
  }
  return 1;
}



// Function: _ValidateImageBase

BOOL __cdecl _ValidateImageBase(PBYTE pImageBase)

{
  BOOL BVar1;
  
  if (*(short *)pImageBase == 0x5a4d) {
    if (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550) {
      if ((short)*(int *)((longlong)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) == 0x20b) {
        BVar1 = 1;
      }
      else {
        BVar1 = 0;
      }
    }
    else {
      BVar1 = 0;
    }
  }
  else {
    BVar1 = 0;
  }
  return BVar1;
}



// Function: _FindPESection

PIMAGE_SECTION_HEADER __cdecl _FindPESection(PBYTE pImageBase,DWORD_PTR rva)

{
  int iVar1;
  uint local_14;
  PIMAGE_SECTION_HEADER local_10;
  
  iVar1 = *(int *)(pImageBase + 0x3c);
  local_14 = 0;
  local_10 = (PIMAGE_SECTION_HEADER)
             (pImageBase +
             (ulonglong)*(ushort *)(pImageBase + (longlong)iVar1 + 0x14) + (longlong)iVar1 + 0x18);
  while( true ) {
    if (*(ushort *)(pImageBase + (longlong)iVar1 + 6) <= local_14) {
      return (PIMAGE_SECTION_HEADER)0x0;
    }
    if ((local_10->VirtualAddress <= rva) &&
       (rva < (local_10->Misc).PhysicalAddress + local_10->VirtualAddress)) break;
    local_14 = local_14 + 1;
    local_10 = local_10 + 1;
  }
  return local_10;
}



// Function: __mingw_GetSectionForAddress

PIMAGE_SECTION_HEADER __mingw_GetSectionForAddress(longlong param_1)

{
  undefined *pImageBase;
  BOOL BVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  
  pImageBase = _refptr___ImageBase;
  BVar1 = _ValidateImageBase(_refptr___ImageBase);
  if (BVar1 == 0) {
    p_Var2 = (PIMAGE_SECTION_HEADER)0x0;
  }
  else {
    p_Var2 = _FindPESection(pImageBase,param_1 - (longlong)pImageBase);
  }
  return p_Var2;
}



// Function: __mingw_GetSectionCount

word __mingw_GetSectionCount(void)

{
  undefined *puVar1;
  word wVar2;
  BOOL BVar3;
  
  puVar1 = _refptr___ImageBase;
  BVar3 = _ValidateImageBase(_refptr___ImageBase);
  if (BVar3 == 0) {
    wVar2 = 0;
  }
  else {
    wVar2 = *(word *)(puVar1 + (longlong)*(int *)(puVar1 + 0x3c) + 6);
  }
  return wVar2;
}



// Function: _GetPEImageBase

IMAGE_DOS_HEADER * _GetPEImageBase(void)

{
  BOOL BVar1;
  IMAGE_DOS_HEADER *pIVar2;
  
  pIVar2 = (IMAGE_DOS_HEADER *)_refptr___ImageBase;
  BVar1 = _ValidateImageBase(_refptr___ImageBase);
  if (BVar1 == 0) {
    pIVar2 = (IMAGE_DOS_HEADER *)0x0;
  }
  return pIVar2;
}



// Function: _IsNonwritableInCurrentImage

BOOL __cdecl _IsNonwritableInCurrentImage(PBYTE pTarget)

{
  undefined *pImageBase;
  BOOL BVar1;
  uint uVar2;
  PIMAGE_SECTION_HEADER p_Var3;
  
  pImageBase = _refptr___ImageBase;
  BVar1 = _ValidateImageBase(_refptr___ImageBase);
  if (BVar1 == 0) {
    uVar2 = 0;
  }
  else {
    p_Var3 = _FindPESection(pImageBase,(longlong)pTarget - (longlong)pImageBase);
    if (p_Var3 == (PIMAGE_SECTION_HEADER)0x0) {
      uVar2 = 0;
    }
    else {
      uVar2 = ~p_Var3->Characteristics >> 0x1f;
    }
  }
  return uVar2;
}



// Function: ___chkstk_ms

/* WARNING: This is an inlined function */

ulonglong ___chkstk_ms(void)

{
  ulonglong in_RAX;
  ulonglong uVar1;
  undefined8 *puVar2;
  undefined8 local_res8 [4];
  
  puVar2 = local_res8;
  uVar1 = in_RAX;
  if (0xfff < in_RAX) {
    do {
      puVar2 = puVar2 + -0x200;
      *puVar2 = *puVar2;
      uVar1 = uVar1 - 0x1000;
    } while (0x1000 < uVar1);
  }
  *(undefined8 *)((longlong)puVar2 - uVar1) = *(undefined8 *)((longlong)puVar2 - uVar1);
  return in_RAX;
}



// Function: vfprintf

int __cdecl vfprintf(FILE *_File,char *_Format,va_list _ArgList)

{
  int iVar1;
  
  iVar1 = __stdio_common_vfprintf(0,_File,_Format,0,_ArgList);
  return iVar1;
}



// Function: printf

int __cdecl printf(char *_Format,...)

{
  int iVar1;
  undefined8 uVar2;
  undefined8 in_RDX;
  undefined8 in_R8;
  undefined8 in_R9;
  undefined8 local_res10;
  undefined8 local_res18;
  undefined8 local_res20;
  
  local_res10 = in_RDX;
  local_res18 = in_R8;
  local_res20 = in_R9;
  uVar2 = __acrt_iob_func(1);
  iVar1 = __stdio_common_vfprintf(0,uVar2,_Format,0,&local_res10);
  return iVar1;
}



// Function: fprintf

int __cdecl fprintf(FILE *_File,char *_Format,...)

{
  int iVar1;
  undefined8 in_R8;
  undefined8 in_R9;
  undefined8 local_res18;
  undefined8 local_res20;
  
  local_res18 = in_R8;
  local_res20 = in_R9;
  iVar1 = __stdio_common_vfprintf(0,_File,_Format,0,&local_res18);
  return iVar1;
}



// Function: __getmainargs

undefined8
__getmainargs(undefined4 *param_1,undefined8 *param_2,undefined8 *param_3,int param_4,
             undefined4 *param_5)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  undefined8 *puVar3;
  
  _initialize_narrow_environment();
  if (param_4 == 0) {
    uVar1 = 1;
  }
  else {
    uVar1 = 2;
  }
  _configure_narrow_argv(uVar1);
  puVar2 = (undefined4 *)__p___argc();
  *param_1 = *puVar2;
  puVar3 = (undefined8 *)__p___argv();
  *param_2 = *puVar3;
  puVar3 = (undefined8 *)__p__environ();
  *param_3 = *puVar3;
  if (param_5 != (undefined4 *)0x0) {
    _set_new_mode(*param_5);
  }
  return 0;
}



// Function: _onexit

_onexit_t __cdecl _onexit(_onexit_t _Func)

{
  int iVar1;
  
  iVar1 = _crt_atexit(_Func);
  if (iVar1 != 0) {
    _Func = (_onexit_t)0x0;
  }
  return _Func;
}



// Function: _amsg_exit

void __cdecl _amsg_exit(int param_1)

{
  FILE *param0;
  
  param0 = (FILE *)__acrt_iob_func(2);
  fprintf(param0,"runtime error %d\n",param_1);
                    /* WARNING: Subroutine does not return */
  _exit(0xff);
}



// Function: _get_output_format

uint __cdecl _get_output_format(void)

{
  return 0;
}



// Function: _tzset

void __cdecl _tzset(void)

{
  (**(code **)_refptr___imp__tzset)();
  __imp_tzname = (undefined *)__tzname();
  __imp_timezone = (undefined *)__timezone();
  __imp_daylight = (undefined *)__daylight();
  return;
}



// Function: tzset

void __cdecl tzset(void)

{
  _tzset();
  return;
}



// Function: __daylight

int * __cdecl __daylight(void)

{
  int *piVar1;
  
                    /* WARNING: Could not recover jumptable at 0x0001400030e0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  piVar1 = __daylight();
  return piVar1;
}



// Function: __timezone

long * __cdecl __timezone(void)

{
  long *plVar1;
  
                    /* WARNING: Could not recover jumptable at 0x0001400030e8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  plVar1 = __timezone();
  return plVar1;
}



// Function: __tzname

char ** __cdecl __tzname(void)

{
  char **ppcVar1;
  
                    /* WARNING: Could not recover jumptable at 0x0001400030f0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  ppcVar1 = __tzname();
  return ppcVar1;
}



// Function: strlen

size_t __cdecl strlen(char *_Str)

{
  size_t sVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140003100. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  sVar1 = strlen(_Str);
  return sVar1;
}



// Function: strncmp

int __cdecl strncmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  int iVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140003108. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  iVar1 = strncmp(_Str1,_Str2,_MaxCount);
  return iVar1;
}



// Function: __acrt_iob_func

void __acrt_iob_func(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003110. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __acrt_iob_func();
  return;
}



// Function: __p__commode

void __p__commode(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003118. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __p__commode();
  return;
}



// Function: __p__fmode

void __p__fmode(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003120. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __p__fmode();
  return;
}



// Function: __stdio_common_vfprintf

void __stdio_common_vfprintf(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003128. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __stdio_common_vfprintf();
  return;
}



// Function: __stdio_common_vfwprintf

void __stdio_common_vfwprintf(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003130. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __stdio_common_vfwprintf();
  return;
}



// Function: fwrite

size_t __cdecl fwrite(void *_Str,size_t _Size,size_t _Count,FILE *_File)

{
  size_t sVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140003138. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  sVar1 = fwrite(_Str,_Size,_Count,_File);
  return sVar1;
}



// Function: __p___argc

void __p___argc(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003140. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __p___argc();
  return;
}



// Function: __p___argv

void __p___argv(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003148. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __p___argv();
  return;
}



// Function: __p___wargv

void __p___wargv(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003150. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __p___wargv();
  return;
}



// Function: _cexit

void __cdecl _cexit(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003158. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _cexit();
  return;
}



// Function: _configure_narrow_argv

void _configure_narrow_argv(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003160. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _configure_narrow_argv();
  return;
}



// Function: _configure_wide_argv

void _configure_wide_argv(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003168. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _configure_wide_argv();
  return;
}



// Function: _crt_at_quick_exit

void _crt_at_quick_exit(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003170. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _crt_at_quick_exit();
  return;
}



// Function: _crt_atexit

void _crt_atexit(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003178. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _crt_atexit();
  return;
}



// Function: _exit

void __cdecl _exit(int _Code)

{
                    /* WARNING: Could not recover jumptable at 0x000140003180. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
  _exit(_Code);
  return;
}



// Function: _initialize_narrow_environment

void _initialize_narrow_environment(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003188. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _initialize_narrow_environment();
  return;
}



// Function: _initialize_wide_environment

void _initialize_wide_environment(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003190. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _initialize_wide_environment();
  return;
}



// Function: _initterm

void _initterm(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003198. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _initterm();
  return;
}



// Function: __set_app_type

void __set_app_type(void)

{
                    /* WARNING: Could not recover jumptable at 0x0001400031a0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _set_app_type();
  return;
}



// Function: _set_invalid_parameter_handler

_invalid_parameter_handler __cdecl
_set_invalid_parameter_handler(_invalid_parameter_handler _Handler)

{
  _invalid_parameter_handler p_Var1;
  
                    /* WARNING: Could not recover jumptable at 0x0001400031a8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  p_Var1 = _set_invalid_parameter_handler(_Handler);
  return p_Var1;
}



// Function: abort

void __cdecl abort(void)

{
                    /* WARNING: Could not recover jumptable at 0x0001400031b0. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
  abort();
  return;
}



// Function: exit

void __cdecl exit(int _Code)

{
                    /* WARNING: Could not recover jumptable at 0x0001400031b8. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
  exit(_Code);
  return;
}



// Function: signal

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void signal(int param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0001400031c0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  signal(param_1);
  return;
}



// Function: __C_specific_handler

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

EXCEPTION_DISPOSITION
__C_specific_handler
          (_EXCEPTION_RECORD *ExceptionRecord,void *EstablisherFrame,_CONTEXT *ContextRecord,
          _DISPATCHER_CONTEXT *DispatcherContext)

{
  EXCEPTION_DISPOSITION EVar1;
  
                    /* WARNING: Could not recover jumptable at 0x0001400031d0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  EVar1 = __C_specific_handler(ExceptionRecord,EstablisherFrame,ContextRecord,DispatcherContext);
  return EVar1;
}



// Function: memcpy

void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    /* WARNING: Could not recover jumptable at 0x0001400031d8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



// Function: __setusermatherr

void __setusermatherr(void)

{
                    /* WARNING: Could not recover jumptable at 0x0001400031e0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __setusermatherr();
  return;
}



// Function: _set_new_mode

void _set_new_mode(void)

{
                    /* WARNING: Could not recover jumptable at 0x0001400031f0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _set_new_mode();
  return;
}



// Function: calloc

void * __cdecl calloc(size_t _Count,size_t _Size)

{
  void *pvVar1;
  
                    /* WARNING: Could not recover jumptable at 0x0001400031f8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pvVar1 = calloc(_Count,_Size);
  return pvVar1;
}



// Function: free

void __cdecl free(void *_Memory)

{
                    /* WARNING: Could not recover jumptable at 0x000140003200. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  free(_Memory);
  return;
}



// Function: malloc

void * __cdecl malloc(size_t _Size)

{
  void *pvVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140003208. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pvVar1 = malloc(_Size);
  return pvVar1;
}



// Function: __p__environ

void __p__environ(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003210. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __p__environ();
  return;
}



// Function: __p__wenviron

void __p__wenviron(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140003218. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __p__wenviron();
  return;
}



// Function: VirtualQuery

SIZE_T __stdcall VirtualQuery(LPCVOID lpAddress,PMEMORY_BASIC_INFORMATION lpBuffer,SIZE_T dwLength)

{
  SIZE_T SVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140003220. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  SVar1 = VirtualQuery(lpAddress,lpBuffer,dwLength);
  return SVar1;
}



// Function: VirtualProtect

BOOL __stdcall
VirtualProtect(LPVOID lpAddress,SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect)

{
  BOOL BVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140003228. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  BVar1 = VirtualProtect(lpAddress,dwSize,flNewProtect,lpflOldProtect);
  return BVar1;
}



// Function: TlsGetValue

LPVOID __stdcall TlsGetValue(DWORD dwTlsIndex)

{
  LPVOID pvVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140003230. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pvVar1 = TlsGetValue(dwTlsIndex);
  return pvVar1;
}



// Function: Sleep

void __stdcall Sleep(DWORD dwMilliseconds)

{
                    /* WARNING: Could not recover jumptable at 0x000140003238. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  Sleep(dwMilliseconds);
  return;
}



// Function: SetUnhandledExceptionFilter

LPTOP_LEVEL_EXCEPTION_FILTER __stdcall
SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)

{
  LPTOP_LEVEL_EXCEPTION_FILTER pPVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140003240. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pPVar1 = SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
  return pPVar1;
}



// Function: LoadLibraryA

HMODULE __stdcall LoadLibraryA(LPCSTR lpLibFileName)

{
  HMODULE pHVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140003248. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pHVar1 = LoadLibraryA(lpLibFileName);
  return pHVar1;
}



// Function: LeaveCriticalSection

void __stdcall LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    /* WARNING: Could not recover jumptable at 0x000140003250. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  LeaveCriticalSection(lpCriticalSection);
  return;
}



// Function: InitializeCriticalSection

void __stdcall InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    /* WARNING: Could not recover jumptable at 0x000140003258. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  InitializeCriticalSection(lpCriticalSection);
  return;
}



// Function: GetProcAddress

FARPROC __stdcall GetProcAddress(HMODULE hModule,LPCSTR lpProcName)

{
  FARPROC pFVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140003260. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pFVar1 = GetProcAddress(hModule,lpProcName);
  return pFVar1;
}



// Function: GetModuleHandleA

HMODULE __stdcall GetModuleHandleA(LPCSTR lpModuleName)

{
  HMODULE pHVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140003268. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pHVar1 = GetModuleHandleA(lpModuleName);
  return pHVar1;
}



// Function: GetLastError

DWORD __stdcall GetLastError(void)

{
  DWORD DVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140003270. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  DVar1 = GetLastError();
  return DVar1;
}



// Function: FreeLibrary

BOOL __stdcall FreeLibrary(HMODULE hLibModule)

{
  BOOL BVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140003278. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  BVar1 = FreeLibrary(hLibModule);
  return BVar1;
}



// Function: EnterCriticalSection

void __stdcall EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    /* WARNING: Could not recover jumptable at 0x000140003280. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  EnterCriticalSection(lpCriticalSection);
  return;
}



// Function: DeleteCriticalSection

void __stdcall DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    /* WARNING: Could not recover jumptable at 0x000140003288. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  DeleteCriticalSection(lpCriticalSection);
  return;
}



