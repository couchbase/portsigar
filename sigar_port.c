/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011 Couchbase, Inc.
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
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sigar.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

#define DEFAULT(value, def) ((value) == SIGAR_FIELD_NOTIMPL ? (def) : (value))

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

    uint64_t parent_mem_minor_faults;
    uint64_t parent_mem_major_faults;
    uint64_t parent_mem_page_faults;
};

int main(void)
{
    sigar_t *sigar;
    sigar_mem_t mem;
    sigar_swap_t swap;
    sigar_cpu_t cpu;
    sigar_proc_mem_t parent_mem;
    struct system_stats reply;

    sigar_pid_t pid;
    sigar_proc_state_t state;
    sigar_pid_t ppid;

    sigar_open(&sigar);

    pid = sigar_pid_get(sigar);
    sigar_proc_state_get(sigar, pid, &state);
    ppid = state.ppid;

#ifdef _WIN32
    _setmode(1, _O_BINARY);
    _setmode(0, _O_BINARY);
#endif

    while (!feof(stdin)) {
        int req;
        int rv = fread(&req, sizeof(req), 1, stdin);
        if (rv < 1) {
            continue;
        }
        if (req != 0) {
            break;
        }
        memset(&reply, 0, sizeof(reply));
        reply.version = 1;
        reply.struct_size = sizeof(reply);

        sigar_mem_get(sigar, &mem);
        sigar_swap_get(sigar, &swap);
        sigar_cpu_get(sigar, &cpu);
        sigar_proc_mem_get(sigar, ppid, &parent_mem);

        reply.cpu_total_ms = cpu.total;
        reply.cpu_idle_ms = cpu.idle + cpu.wait;

        reply.swap_total = swap.total;
        reply.swap_used = swap.used;
        reply.swap_page_in = swap.page_in;
        reply.swap_page_out = swap.page_out;

        reply.mem_total = mem.total;
        reply.mem_used = mem.used;
        reply.mem_actual_used = mem.actual_used;
        reply.mem_actual_free = mem.actual_free;

        reply.parent_mem_minor_faults = DEFAULT(parent_mem.minor_faults, 0);
        reply.parent_mem_major_faults = DEFAULT(parent_mem.major_faults, 0);
        reply.parent_mem_page_faults = DEFAULT(parent_mem.page_faults, 0);

        fwrite(&reply, sizeof(reply), 1, stdout);
        fflush(stdout);
    }

    return 0;
}
