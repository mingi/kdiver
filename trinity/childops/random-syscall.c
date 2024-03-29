/*
 * Call a single random syscall with random args.
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "arch.h"	// biarch
#include "arg-decoder.h"
#include "child.h"
#include "debug.h"
#include "locks.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "signals.h"
#include "sanitise.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "field.h"

/*
 * This function decides if we're going to be doing a 32bit or 64bit syscall.
 * There are various factors involved here, from whether we're on a 32-bit only arch
 * to 'we asked to do a 32bit only syscall' and more.. Hairy.
 */

static int *active_syscalls;

static bool choose_syscall_table(void)
{
	bool do32 = FALSE;

	if (biarch == FALSE) {
		active_syscalls = shm->active_syscalls;
	} else {

		/* First, check that we have syscalls enabled in either table. */
		if (validate_syscall_table_64() == FALSE) {
			use_64bit = FALSE;
			/* If no 64bit syscalls enabled, force 32bit. */
			do32 = TRUE;
		}

		if (validate_syscall_table_32() == FALSE)
			use_32bit = FALSE;

		/* If both tables enabled, pick randomly. */
		if ((use_64bit == TRUE) && (use_32bit == TRUE)) {
			/* 10% possibility of a 32bit syscall */
			if (ONE_IN(10))
				do32 = TRUE;
		}

		if (do32 == FALSE) {
			syscalls = syscalls_64bit;
			active_syscalls = shm->active_syscalls64;
			max_nr_syscalls = max_nr_64bit_syscalls;
		} else {
			syscalls = syscalls_32bit;
			active_syscalls = shm->active_syscalls32;
			max_nr_syscalls = max_nr_32bit_syscalls;
		}
	}
	return do32;
}

static bool set_syscall_nr(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	unsigned int syscallnr;
	bool do32;

retry:
	if (no_syscalls_enabled() == TRUE) {
		output(0, "[%d] No more syscalls enabled. Exiting\n", getpid());
		shm->exit_reason = EXIT_NO_SYSCALLS_ENABLED;
		return FAIL;
	}

	/* Ok, we're doing another syscall, let's pick one. */
	do32 = choose_syscall_table();
	syscallnr = rnd() % max_nr_syscalls;

	/* If we got a syscallnr which is not active repeat the attempt,
	 * since another child has switched that syscall off already.*/
	if (active_syscalls[syscallnr] == 0)
		goto retry;

	syscallnr = active_syscalls[syscallnr] - 1;

	if (validate_specific_syscall_silent(syscalls, syscallnr) == FALSE) {
		deactivate_syscall(syscallnr, do32);
		goto retry;
	}

	entry = get_syscall_entry(syscallnr, do32);
	if (entry->flags & EXPENSIVE) {
		if (!ONE_IN(1000))
			goto retry;
	}

	/* critical section for shm updates. */
	lock(&rec->lock);
	rec->do32bit = do32;
	rec->nr = syscallnr;
	unlock(&rec->lock);

	return TRUE;
}


bool deep_syscall(struct childdata *child, int depth)
{
 	struct syscallrecord *rec;
 	int ret = FALSE;
 	int field_count = 0;
	struct st_field** l_fields;

 	rec = &child->syscall;

 	switch (depth){
 		// case 3:
			// printf("depth: %d\n", depth);
 		// 	break;
 		case 5:
			printf("Good! depth: %d\n", depth);
 			break;
 		case 10:
			printf("Cool!! depth: %d\n", depth);
 			break;
 		case 20:
			printf("Awesome!!! depth: %d\n", depth);
 			break;
 		default:
 			break;
 	}

 	get_mutation_table();
	
	l_fields = read_field_file("", &field_count);

	for (int i = 0; i < field_count; i++) {
		u8 orig[32];
		if(l_fields[i]==NULL) continue;
		u32 start = l_fields[i]->start;

		u32 stage_cur_byte = start;

		if(l_fields[i]->start == -1) continue;
		if(l_fields[i]->size > 8) continue;

		memcpy(orig, 0x20000000+start, l_fields[i]->size);

		u8** values = l_fields[i]->markers;
		if(values==NULL) continue;

		for(int j=0; j < l_fields[i]->marker_count; j++){

			if(values[j]==NULL) continue;

			memcpy(0x20000000+start, values[j], l_fields[i]->size);

			//printf("\nstart: %d size: %d value: %llx\n", l_fields[i]->start, l_fields[i]->size, *(u64*)values[j]);
			output_syscall_prefix(rec);

			reset_taint();

			do_syscall(rec);

			stop_taint();

			if(depth < MAX_DEPTH)
				deep_syscall(child, depth+1);

			output_syscall_postfix(rec);
			memcpy(0x20000000+start, orig, l_fields[i]->size);
	  	}

		values = l_fields[i]->constraints;
		if(values==NULL) continue;

		for(int j=0; j < l_fields[i]->constraint_count; j++){

			if(values[j]==NULL) continue;

			memcpy(0x20000000+start, values[j], l_fields[i]->size);

			//printf("\nstart: %d size: %d value: %llx\n", l_fields[i]->start, l_fields[i]->size, *(u64*)values[j]);
			output_syscall_prefix(rec);

			reset_taint();

			do_syscall(rec);

			stop_taint();

			if(depth < MAX_DEPTH)
				deep_syscall(child, depth+1);

			output_syscall_postfix(rec);
			memcpy(0x20000000+start, orig, l_fields[i]->size);
	  	}

		values = l_fields[i]->interests;
		if(values==NULL) continue;

		for(int j=0; j < l_fields[i]->interest_count; j++){

			if(values[j]==NULL) continue;

			memcpy(0x20000000+start, values[j], l_fields[i]->size);

			//printf("\nstart: %d size: %d value: %llx\n", l_fields[i]->start, l_fields[i]->size, *(u64*)values[j]);
			output_syscall_prefix(rec);

			if(depth < MAX_DEPTH)
				deep_syscall(child, depth+1);
			
			reset_taint();

			do_syscall(rec);

			stop_taint();

			output_syscall_postfix(rec);
			memcpy(0x20000000+start, orig, l_fields[i]->size);
	  	}
	}

	free(l_fields);
	l_fields = NULL;

 	ret = TRUE;

	return ret;
}


bool random_syscall(struct childdata *child)
{
	struct syscallrecord *rec;
	int ret = FALSE;
	int field_count = 0;

	rec = &child->syscall;

	if (set_syscall_nr(rec) == FAIL)
		return FAIL;

	memset(rec->postbuffer, 0, POSTBUFFER_LEN);

	/* Generate arguments, print them out */
	generate_syscall_args(rec);

	output_syscall_prefix(rec);

	memset((char*)0x20000000, '\xaa', 0x6000);

	reset_taint();

	do_syscall(rec);

	stop_taint();

	output_syscall_postfix(rec);


	deep_syscall(child, 1);
	

	handle_syscall_ret(rec);

	ret = TRUE;

	return ret;
}
