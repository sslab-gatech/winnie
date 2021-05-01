#pragma once

int fullspeed_init(int argc, char **argv);
int run_target_fullspeed(char **argv, uint32_t timeout, uint32_t init_timeout, int drun);
void destroy_target_process();
void setup_watchdog_timer();

// from forkserver.c
void get_coverage_info(u32 *visited_bbs_out, u32 *total_bbs_out);
