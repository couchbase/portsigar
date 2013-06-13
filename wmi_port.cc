/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *   Copyright 2013 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

// TODO - we are using non-rate based raw counters to mimick sigar.
// We should move the rate counting logic from ns_server to portsigar,
// so we can delegate the rate counting to OS where the OS supports it.

#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib, "wbemuuid")

#include "./wmi_port.h"

#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <comdef.h>
#include <wbemidl.h>
#include <stdint.h>
#include <comutil.h>
#include <stdio.h>

#include <vector>
#include <hash_map>
#include <algorithm>
#include <string>

#define SKIP_PROCESS "moxi"
#define NUM_INTERESTING_PROCS 10
#define PROC_NAME_LEN 12

// As COM does not use exceptions, we use below to avoid cluttering flow
#define REQUIRE_HR(x) REQUIRE(SUCCEEDED(x));
#define REQUIRE(x) if (!(x)) {                              \
        Errors::Instance().Push(__FILE__, __LINE__, #x);    \
        return false;                                       \
    }

using std::string;
using std::wstring;
using std::vector;
using std::hash_map;

namespace wmiport {

    WMIHelper::WMIHelper()
        : bCom(false), pLoc(NULL), pSvc(NULL), pEnum(NULL),
          pObj(NULL), bFinished(true) {
    }

    bool WMIHelper::Init() {
        REQUIRE_HR(CoInitializeEx(0, 0));
        bCom = true;
        REQUIRE_HR(CoInitializeSecurity(0, -1, 0, 0, RPC_C_AUTHN_LEVEL_DEFAULT,
                                        RPC_C_IMP_LEVEL_IMPERSONATE, 0, EOAC_NONE, 0));
        REQUIRE_HR(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                                    IID_IWbemLocator, reinterpret_cast<LPVOID*>(&pLoc)));
        REQUIRE_HR(pLoc->ConnectServer(BSTR(L"ROOT\\CIMV2"), 0, 0, 0, 0, 0, 0,
                                       &pSvc));
        return true;
    }

    template <typename T>
    static void Release(T*& p) {
        if (p) {
            p->Release();
            p = NULL;
        }
    }

    template <typename T>
    bool WMIHelper::ReadVector(const WCHAR* name, vector<T>* val) {
        // unlike scalar reads, this allows empty results
        while (!bFinished) {
            T ele;
            REQUIRE(Read<T>(name, &ele));
            val->insert(val->end(), ele);
            REQUIRE(Next());
        }
        return true;
    }

    template<typename T, typename D>
    void WMIHelper::ReadOrDefault(const WCHAR* name, const D& fallback, T* val) {
        bool rc = Read<T>(name, val);
        if (!rc) {
            *val = fallback;
        }
    }

    template<>
    bool WMIHelper::Read(const WCHAR* name, wstring* val) {
        REQUIRE(!bFinished);
        _variant_t variant;
        REQUIRE_HR(pObj->Get(name, 0, &variant.GetVARIANT(), 0, 0));
        REQUIRE(variant.vt == VT_BSTR);
        *val = variant.bstrVal;
        return true;
    }

    template <>
    bool WMIHelper::Read(const WCHAR* name, uint64_t* val) {
        REQUIRE(!bFinished);
        _variant_t variant;
        REQUIRE_HR(pObj->Get(name, 0, &variant.GetVARIANT(), 0, 0));
        switch (variant.vt) {
        case VT_BSTR:
            *val = _wtoi64(variant.bstrVal);
            return true;
        case VT_I1:
        case VT_I2:
        case VT_UI1:
        case VT_UI2:
            *val = variant.uiVal;
            return true;
        case VT_I4:
        case VT_UI4:
        case VT_CY:
        case VT_INT:
        case VT_UINT:
            *val = variant.uintVal;
            return true;
        case VT_I8:
        case VT_UI8:
            *val = variant.ullVal;
            return true;
        }
        val = 0;
        return false;
    }

    template <>
    bool WMIHelper::Read(const WCHAR* name, uint32_t* val) {
        REQUIRE(!bFinished);
        _variant_t variant;
        REQUIRE_HR(pObj->Get(name, 0, &variant.GetVARIANT(), 0, 0));
        switch (variant.vt) {
        case VT_BSTR:
            *val = _wtoi(variant.bstrVal);
            return true;
        case VT_I1:
        case VT_I2:
        case VT_UI1:
        case VT_UI2:
            *val = variant.uiVal;
            return true;
        case VT_I4:
        case VT_UI4:
        case VT_CY:
        case VT_INT:
        case VT_UINT:
            *val = variant.uintVal;
            return true;
        }
        val = 0;
        return false;
    }

    bool WMIHelper::Next() {
        bFinished = true;
        Release(pObj);
        ULONG uReturn = 0;
        REQUIRE_HR(pEnum->Next(WBEM_INFINITE, 1, &pObj, &uReturn));
        bFinished = !uReturn;
        return true;
    }

    bool WMIHelper::Finished() {
        return bFinished;
    }

    WMIHelper::~WMIHelper() {
        Release(pObj);
        Release(pEnum);
        Release(pSvc);
        Release(pLoc);
        if (bCom) {
            CoUninitialize();
        }
    }

    bool WMIHelper::Query(const wstring& query) {
        Release(pObj);
        Release(pEnum);
        REQUIRE_HR(pSvc->ExecQuery(BSTR(L"WQL"),
                                   BSTR(query.c_str()),
                                   WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                   NULL,
                                   &pEnum));
        REQUIRE(Next());
        return true;
    }

    WMIPort::WMIPort()
        :  pHelper(NULL) {
    }

    bool WMIPort::Begin() {
        if (pHelper) {
            return true;
        }
        pHelper = new WMIHelper();
        REQUIRE(pHelper->Init());
        return true;
    }

    bool WMIPort::GetParentPid(uint32_t pid, uint32_t* ppid) {
        REQUIRE(Begin());
        wstring query = L"SELECT ParentProcessId"
            L" FROM Win32_Process WHERE ProcessId = ";
        query.append(std::to_wstring(static_cast<uint64_t>(pid)));
        REQUIRE(pHelper->Query(query));
        REQUIRE(pHelper->Read(L"ParentProcessId", ppid));
        return true;
    }

    bool WMIPort::GetChildren(uint32_t pid, vector<uint32_t>* children) {
        REQUIRE(Begin());
        children->empty();
        wstring query = L"SELECT ProcessId"
            L" FROM Win32_Process WHERE ParentProcessId = ";
        query.append(std::to_wstring(static_cast<uint64_t>(pid)));
        REQUIRE(pHelper->Query(query));
        REQUIRE(pHelper->ReadVector(L"ProcessId", children));
        return true;
    }

    bool WMIPort::FillSystemStats(system_stats* stats) {
        REQUIRE(Begin());

        memset(stats, 0, sizeof(*stats));
        stats->version = 2;
        stats->struct_size = sizeof(*stats);

        static uint64_t totalmem = 0;
        if (!totalmem) {
            REQUIRE(pHelper->Query(L"SELECT TotalPhysicalMemory"
                                   L" FROM Win32_ComputerSystem"));
            REQUIRE(pHelper->Read(L"TotalPhysicalMemory", &totalmem));
        }

        uint64_t ctrTotal, ctrIdle;
        REQUIRE(pHelper->Query(L"SELECT PercentIdleTime, TimeStamp_Sys100NS"
                               L" FROM Win32_PerfRawData_PerfOS_Processor"
                               L" WHERE Name = '_Total'"));
        pHelper->ReadOrDefault(L"TimeStamp_Sys100NS", 0, &ctrTotal);
        pHelper->ReadOrDefault(L"PercentIdleTime", 0, &ctrIdle);

        uint32_t pagepct = 0, pagebase = 0;
        bool paging = pHelper->Query(L"SELECT PercentUsage, PercentUsage_Base"
                                     L" FROM Win32_PerfRawData_PerfOS_PagingFile"
                                     L" WHERE Name = '_Total'");
        if (paging) {
            pHelper->ReadOrDefault(L"PercentUsage", 0, &pagepct);
            pHelper->ReadOrDefault(L"PercentUsage_Base", 0, &pagebase);
        }

        uint64_t availmem, freemem, modmem, cache1, cache2, cache3, climit;
        uint32_t incount, outcount;
        REQUIRE(pHelper->Query(
                               L"SELECT AvailableBytes, FreeAndZeroPageListBytes, ModifiedPageListBytes,"
                               L"  StandbyCacheCoreBytes, StandbyCacheNormalPriorityBytes, CommitLimit,"
                               L"  StandbyCacheReserveBytes, PagesInputPersec, PagesOutputPersec"
                               L" FROM Win32_PerfRawData_PerfOS_Memory"));

        pHelper->ReadOrDefault(L"AvailableBytes", 0, &availmem);
        pHelper->ReadOrDefault(L"FreeAndZeroPageListBytes", 0, &freemem);
        pHelper->ReadOrDefault(L"ModifiedPageListBytes", 0, &modmem);
        pHelper->ReadOrDefault(L"StandbyCacheCoreBytes", 0, &cache1);
        pHelper->ReadOrDefault(L"StandbyCacheReserveBytes", 0, &cache2);
        pHelper->ReadOrDefault(L"StandbyCacheNormalPriorityBytes", 0, &cache3);
        pHelper->ReadOrDefault(L"CommitLimit", 0, &climit);

        // as we are using raw counters, below are not rates
        pHelper->ReadOrDefault(L"PagesInputPersec", 0, &incount);
        pHelper->ReadOrDefault(L"PagesOutputPersec", 0, &outcount);

        stats->cpu_total_ms = ctrTotal/10;  // 100ns
        stats->cpu_idle_ms = ctrIdle/10;  // 100ns
        stats->mem_total = totalmem;
        stats->mem_used = (totalmem - freemem);
        stats->mem_actual_free = availmem;
        stats->mem_actual_used =
            totalmem - (freemem + cache1 + cache2 + cache3 + modmem);
        stats->swap_page_in = incount;
        stats->swap_page_out = outcount;

        uint64_t swapsz = (climit > totalmem) ? climit - totalmem : 0;
        uint64_t swapuse = (pagebase > 0) ? (pagepct * swapsz) / pagebase : 0;
        stats->swap_total = swapsz;
        stats->swap_used = swapuse;

        // to take care of a glitch in data
        if (stats->mem_actual_used > totalmem) {
            stats->mem_actual_used = totalmem;
        }

        return true;
    }

    bool WMIPort::FillProcessStats(uint32_t sitterpid, system_stats* stats) {
        REQUIRE(Begin());

        int count = 0;
        hash_map<uint32_t, uint32_t> pidloc;
        memset(stats->interesting_procs, 0, sizeof(stats->interesting_procs));
        wstring pquery =
            L"SELECT Name, ProcessId, UserModeTime, KernelModeTime,"
            L"  PageFaults, PrivatePageCount, WorkingSetSize"
            L" FROM Win32_Process"
            L" WHERE ParentProcessId = ";
        pquery.append(std::to_wstring(static_cast<uint64_t>(sitterpid)));

        REQUIRE(pHelper->Query(pquery));
        while (!pHelper->Finished()) {
            wstring wname;
            pHelper->ReadOrDefault(L"Name", L"unknown", &wname);
            string name(wname.begin(), wname.end());
            transform(name.begin(), name.end(), name.begin(), tolower);
            if (name.find(SKIP_PROCESS) == 0) {
                REQUIRE(pHelper->Next());
                continue;
            }

            uint32_t pid, faults, cpu;
            uint64_t cpu_u, cpu_k, mem_ws, mem_pvt;
            REQUIRE(pHelper->Read(L"ProcessId", &pid));
            pHelper->ReadOrDefault(L"UserModeTime", 0, &cpu_u);
            pHelper->ReadOrDefault(L"KernelModeTime", 0, &cpu_k);
            pHelper->ReadOrDefault(L"PageFaults", 0, &faults);
            pHelper->ReadOrDefault(L"WorkingSetSize", 0, &mem_ws);
            //
            // note that this is actually private bytes, not pages!
            pHelper->ReadOrDefault(L"PrivatePageCount", 0, &mem_pvt);

            proc_stats& pstat = stats->interesting_procs[count];
            strncpy(pstat.name, name.c_str(), PROC_NAME_LEN-1);
            char* dotpos = strrchr(pstat.name, '.');
            while (dotpos && *dotpos) {
                *(dotpos++) = 0;
            }
            cpu = static_cast<uint32_t>((cpu_u + cpu_k)/10000);  // 100ns

            pstat.cpu_utilization = cpu;
            pstat.pid = pid;
            pstat.page_faults = faults;
            pstat.mem_size = mem_pvt;
            pstat.mem_resident = mem_ws;

            pstat.minor_faults = 0;
            pstat.major_faults = 0;
            pstat.mem_share = 0;

            pidloc[pid] = count;
            count++;
            if (count == NUM_INTERESTING_PROCS) {
                break;
            }
            REQUIRE(pHelper->Next());
        }

        wstring cquery =
            L"SELECT IDProcess, WorkingSetPrivate"
            L" FROM Win32_PerfRawData_PerfProc_Process"
            L" WHERE CreatingProcessID = ";
        cquery.append(std::to_wstring(static_cast<uint64_t>(sitterpid)));

        uint32_t pid;
        REQUIRE(pHelper->Query(cquery));
        while (!pHelper->Finished()) {
            REQUIRE(pHelper->Read(L"IDProcess", &pid));
            if (pidloc.find(pid) == pidloc.end()) {
                REQUIRE(pHelper->Next());
                continue;
            }

            uint64_t mem_wspvt;
            proc_stats& pstat = stats->interesting_procs[pidloc[pid]];
            pHelper->ReadOrDefault(L"WorkingSetPrivate", 0, &mem_wspvt);

            pstat.mem_share = pstat.mem_resident - mem_wspvt;
            REQUIRE(pHelper->Next());
        }
        return true;
    }

    bool WMIPort::Dump(const system_stats& stats) {
        REQUIRE(Begin());

        printf("Swap total size: %llu MB\n", stats.swap_total/(1024*1024));
        printf("Swap used size: %llu MB\n", stats.swap_used/(1024*1024));
        printf("Swap in: %llu\n", stats.swap_page_in);
        printf("Swap out: %llu\n", stats.swap_page_out);

        static uint64_t prior_total = stats.cpu_total_ms;
        static uint64_t prior_idle = stats.cpu_idle_ms;
        int64_t total = stats.cpu_total_ms - prior_total;
        int64_t idle = stats.cpu_idle_ms - prior_idle;
        prior_total = stats.cpu_total_ms;
        prior_idle = stats.cpu_idle_ms;
        printf("CPU idle: %llu %%\n", (total > 0 ? (idle * 100) / total : 0));

        printf("Mem Total: %llu MB\n", stats.mem_total/(1024*1024));
        printf("Mem Used: %llu MB\n", stats.mem_used/(1024*1024));
        printf("Actual Free: %llu MB\n", stats.mem_actual_free/(1024*1024));
        printf("Actual Used: %llu MB\n", stats.mem_actual_used/(1024*1024));
        printf("\n");

        for (int i = 0; i < NUM_INTERESTING_PROCS; i++) {
            struct proc_stats proc = stats.interesting_procs[i];
            if (proc.name[0] == 0) {
                continue;
            }
            printf("Interesting Process: #%d\n", i);
            printf("Name: %s\n", proc.name);
            printf("PID: %llu\n", proc.pid);
            printf("CPU Utilization: %lu sec\n", proc.cpu_utilization/1000);
            printf("Major Faults: %llu\n", proc.major_faults);
            printf("Minor Faults: %llu\n", proc.minor_faults);
            printf("Page Faults: %llu\n", proc.page_faults);
            printf("Mem Size: %llu kB\n", proc.mem_size/1024);
            printf("Mem Shared: %llu kB\n", proc.mem_share/1024);
            printf("Mem Resident: %llu kB\n", proc.mem_resident/1024);
            printf("\n");
        }
        return true;
    }

    WMIPort::~WMIPort() {
    }

    bool debugloop() {
        WMIPort port;
        uint32_t pid, ppid, sitterpid;

        pid = GetCurrentProcessId();
        REQUIRE(port.GetParentPid(pid, &ppid));
        REQUIRE(port.GetParentPid(ppid, &sitterpid));

        struct system_stats reply;
        while (true) {
            REQUIRE(port.FillSystemStats(&reply));
            REQUIRE(port.FillProcessStats(sitterpid, &reply));
            REQUIRE(port.Dump(reply));
        }
        return true;
    }

    bool loop() {
        _setmode(1, _O_BINARY);
        _setmode(0, _O_BINARY);

        WMIPort port;

        uint32_t pid, ppid, sitterpid;
        pid = GetCurrentProcessId();

        REQUIRE(port.GetParentPid(pid, &ppid));
        REQUIRE(port.GetParentPid(ppid, &sitterpid));

        struct system_stats reply;
        while (!feof(stdin)) {
            int req;
            int rv = fread(&req, sizeof(req), 1, stdin);
            if (rv < 1) {
                continue;
            }
            if (req != 0) {
                break;
            }

            REQUIRE(port.FillSystemStats(&reply));
            REQUIRE(port.FillProcessStats(sitterpid, &reply));
            fwrite(&reply, sizeof(reply), 1, stdout);
            fflush(stdout);
        }

        return true;
    }

    Errors Errors::gErrors;

    Errors::Errors() {
    }

    Errors& Errors::Instance() {
        return gErrors;
    }

    void Errors::Push(const string& file, const int line,
                      const string& operation) {
        string fname = file.substr(file.find_last_of('\\') + 1);
        sErrors.append("Failed: ").append(fname).append(":");
        sErrors.append(std::to_string(static_cast<uint64_t>(line)));
        sErrors.append(": ").append(operation);
        IErrorInfo* info = 0;
        if (SUCCEEDED(GetErrorInfo(0, &info)) && info) {
            _bstr_t src, desc;
            if (SUCCEEDED(info->GetSource(&src.GetBSTR()))) {
                sErrors.append(" - ").append(src);
            }
            if (SUCCEEDED(info->GetDescription(&desc.GetBSTR()))) {
                sErrors.append(": ").append(desc);
            }
            info->Release();
        }
        sErrors.append("\n");
    }

    void Errors::GetStackTrace(string* description) {
        *description = sErrors;
    }

}  // namespace wmiport

int main(int argc, const char* argv[]) {
    bool debug = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-debug") == 0) {
            debug = true;
        }
    }

    bool rc = debug ? wmiport::debugloop() : wmiport::loop();

    if (!rc) {
        string err;
        wmiport::Errors::Instance().GetStackTrace(&err);
        fprintf(stderr, "WMIPort Failed %s\n", err.c_str());
    }

    return (rc ? 0 : 255);
}
