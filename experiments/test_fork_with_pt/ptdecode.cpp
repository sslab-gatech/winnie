/*
  WinAFL - Intel PT decoding
  ------------------------------------------------

  Written and maintained by Ivan Fratric <ifratric@google.com>

  Copyright 2016 Google Inc. All Rights Reserved.
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <map>
#include <mutex>
#include <vector>
#include <unordered_set>
#include <Windows.h>

#include <intel-pt.h>
extern "C" {
#include <internal/pt_cpu.h>
};
#include <internal/pt_cpuid.h>
#include <internal/pt_opcodes.h>
#include <internal/pt_retstack.h>
#include <internal/pt_block_decoder.h>

#include "ptdecode.h"
#include "debug.h"

#define PPT_EXT 0xFF

int fetch_insn(struct pt_image *image, uint64_t addr, uint8_t* insn) {
	for (struct pt_section_list *section = image->sections; section; section = section->next) {
		if (addr >= section->section.vaddr && addr < section->section.vaddr + section->section.size) {
			return pt_iscache_read(section->section.section->iscache, insn, 16, section->isid, addr);
		}
	}
	return -pte_nomap;
}

// uses Intel's reference basic block decoder to decode the full trace
// needs to have access to executable memory of the process that generated
// the trace (passed through pt_image)
extern "C" void analyze_trace_full_reference(unsigned char *trace_data, size_t trace_size, struct pt_image *image, bool skip_first_bb, trace_callback func) {

	struct pt_block_decoder *decoder;
	struct pt_config config;
	struct pt_event event;
	struct pt_block block;

	bool first = true;
	bool skip_next = skip_first_bb; // doesn't really do shit. we always skip the first bb

	pt_config_init(&config);
	pt_cpu_read(&config.cpu);
	pt_cpu_errata(&config.errata, &config.cpu);
	config.begin = trace_data;
	config.end = trace_data + trace_size;

	// This is important not only for accurate coverage, but also because
	// if we don't set it, the decoder is sometimes going to break
	// blocks on these instructions anyway, resulting in new coverage being
	// detected where there in fact was none.
	// See also skip_next comment below
	config.flags.variant.block.end_on_call = 1;
	config.flags.variant.block.end_on_jump = 1;

	decoder = pt_blk_alloc_decoder(&config);
	if (!decoder) {
		FATAL("Error allocating decoder\n");
	}

	int ret = pt_blk_set_image(decoder, image);

	int status;

	for (;;) {
		status = pt_blk_sync_forward(decoder);
		if (status < 0) {
			// printf("cant't sync\n");
			break;
		}

		for (;;) {

			// we aren't really interested in events
			// but have to empty the event queue
			while (status & pts_event_pending) {
				status = pt_blk_event(decoder, &event, sizeof(event));
				if (status < 0)
					break;

				 printf("event %d\n", event.type);
			}

			if (status < 0)
				break;

			uint64_t src_addr;
			if (!first) {
				if (!block.end_ip) {
					skip_next = true; // corrupted trace info
				}
				else {
					src_addr = block.end_ip;
				}
			}
			else {
				first = false;
				skip_next = true;
			}

			status = pt_blk_next(decoder, &block, sizeof(block));

			if (status < 0) {
				break;
			}

			bool skip = skip_next;

			// Sometimes, due to asynchronous events and other reasons (?)
			// the tracing of a basic block will break in the middle of it
			// and the subsequent basic block will continue where the previous
			// one was broken, resulting in new coverage detected where there
			// was none.
			// Currently, this is resolved by examining the instruction class of
			// the last instruction in the basic block. If it is not one of the
			// instructions that normally terminate a basic block, we will simply
			// ignore the subsequent block.
			// Another way to do this could be to compute the address of the next
			// instruction after the basic block, and only ignore a subsequent block
			// if it starts on that address
			if (block.iclass == ptic_other) skip_next = true;
			else skip_next = false;

			if (skip) continue;

			 func(status, &block);
		}
	}

	pt_blk_free_decoder(decoder);
}
