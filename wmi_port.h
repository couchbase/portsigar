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
#ifndef WMI_PORT_H_
#define WMI_PORT_H_

#include <wbemidl.h>
#include <stdint.h>
#include <vector>
#include <string>

namespace wmiport {

    const char* SKIP_PROCESS = "moxi";
    const int   NUM_INTERESTING_PROCS = 10;
    const int   PROC_NAME_LEN = 12;

    struct proc_stats {
        char name[PROC_NAME_LEN];
        uint32_t cpu_utilization;
        uint64_t pid;
        uint64_t mem_size;
        uint64_t mem_resident;
        uint64_t mem_share;
        uint64_t minor_faults;
        uint64_t major_faults;
        uint64_t page_faults;
    };

    struct system_stats {
        uint32_t version;
        uint32_t struct_size;
        uint64_t cpu_total_ms;
        uint64_t cpu_idle_ms;
        uint64_t swap_total;
        uint64_t swap_used;
        uint64_t swap_page_in;
        uint64_t swap_page_out;
        uint64_t mem_total;
        uint64_t mem_used;
        uint64_t mem_actual_used;
        uint64_t mem_actual_free;
        struct proc_stats interesting_procs[NUM_INTERESTING_PROCS];
    };

    class WMIHelper;

    class WMIPort {
    public:
        WMIPort();
        virtual ~WMIPort();
        bool GetParentPid(const uint32_t pid, uint32_t* ppid);
        bool GetChildren(const uint32_t ppid, std::vector<uint32_t>* children);
        bool FillProcessStats(const uint32_t sitterpid, system_stats* stats);
        bool FillSystemStats(system_stats* stats);
        bool Dump();
    private:
        bool Begin();
        WMIHelper* pHelper;
    };

    class WMIHelper {
    public:
        WMIHelper();
        virtual ~WMIHelper();
        bool Init();
        bool Query(const std::wstring& query);
        bool Next();
        bool Finished();
        template <typename T>
        bool Read(const WCHAR* name, T* value);
        template <typename T, typename D>
        void ReadOrDefault(const WCHAR* name, const D& fallback, T* value);
        template <typename T>
        bool ReadVector(const WCHAR* name, std::vector<T>* value);
    private:
        bool                    bCom;
        IWbemLocator*           pLoc;
        IWbemServices*          pSvc;
        IEnumWbemClassObject*   pEnum;
        IWbemClassObject*       pObj;
        bool                    bFinished;
    };

    class Errors {
    public:
        static Errors& Instance();
        void Push(const std::string& file, const int line, const std::string& op);
        void GetStackTrace(std::string* description);
    private:
        static Errors gErrors;
        std::string sErrors;
        Errors();
    };

}  // namespace wmiport
#endif  // WMI_PORT_H_
