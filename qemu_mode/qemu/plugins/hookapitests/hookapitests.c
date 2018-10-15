/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
This is a plugin of DECAF. You can redistribute and modify it
under the terms of BSD license but it is made available
WITHOUT ANY WARRANTY. See the top-level COPYING file for more details.

For more information about DECAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DECAF,please post it on
http://code.google.com/p/decaf-platform/
*/
/**
 * @author Xunchao Hu, Heng Yin
 * @date Jan 24 2013
 */


#include "qemu/osdep.h"
#include "cpu.h"

#include <sys/time.h>

#include "DECAF_types.h"
#include "DECAF_main.h"
#include "hookapi.h"
#include "DECAF_callback.h"
#include "shared/vmi_callback.h"
#include "utils/Output.h"
#include "custom_handlers.h"



//basic stub for plugins
static plugin_interface_t hookapitests_interface;
static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle removeproc_handle = DECAF_NULL_HANDLE;
static DECAF_Handle blockbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle ntcreatefile_handle = DECAF_NULL_HANDLE;
static DECAF_Handle VirtualAlloc_handle = DECAF_NULL_HANDLE;

static DECAF_Handle recvFrom_handle = DECAF_NULL_HANDLE;

static char targetname[512];
static uint32_t targetpid = -1;
static uint32_t targetcr3 = 0;

static void recvfrom_call(void *param)
{
	DECAF_printf("read\n");

}


static void register_hooks()
{
/*
	ntcreatefile_handle = hookapi_hook_function_byname(
			"ntdll.dll", "NtCreateFile", 1, targetcr3,
			NtCreateFile_call, NULL, 0);

	VirtualAlloc_handle = hookapi_hook_function_byname(
			"kernel32.dll", "VirtualAlloc", 1, targetcr3,
			VirtualAlloc_call, NULL, 0);
*/
//libc.so.0
/*
	recvFrom_handle = hookapi_hook_function_byname(
			"libuClibc-0.9.30.1.so", "recvfrom", 1, targetcr3,
			recvfrom_call, NULL, 0);
*/
	recvFrom_handle = hookapi_hook_function_byname(
			"httpd", "read", 1, targetcr3,
			recvfrom_call, NULL, 0);
}

static void createproc_callback(VMI_Callback_Params* params)
{
    //DECAF_printf("createproc\n");
    //DECAF_printf("params:%s\n",params->cp.name);
    if(targetcr3 != 0) //if we have found the process, return immediately
    	return;
	if (strcasecmp(targetname, params->cp.name) == 0) {
		targetpid = params->cp.pid;
		targetcr3 = params->cp.cr3;
		DECAF_printf("targetname:%s\n",targetname);
    		DECAF_printf("params:%s\n",params->cp.name);
		DECAF_printf("Process found: pid=%d, cr3=%08x\n", targetpid, targetcr3);
		register_hooks();
	}
}


static void removeproc_callback(VMI_Callback_Params* params)
{
	//Stop the test when the monitored process terminates

}


static void do_hookapitests(Monitor* mon, const QDict* qdict)
{
	if ((qdict != NULL) && (qdict_haskey(qdict, "procname"))) {
		strncpy(targetname, qdict_get_str(qdict, "procname"), 512);
	}
	targetname[511] = '\0';
	DECAF_printf("%s\n",targetname);
}


static int hookapitests_init(void)
{
	DECAF_output_init(NULL);
	DECAF_printf("Hello World\n");
	//register for process create and process remove events
	processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB,
			&createproc_callback, NULL);
	removeproc_handle = VMI_register_callback(VMI_REMOVEPROC_CB,
			&removeproc_callback, NULL);
	if ((processbegin_handle == DECAF_NULL_HANDLE)
			|| (removeproc_handle == DECAF_NULL_HANDLE)) {
		DECAF_printf(
				"Could not register for the create or remove proc events\n");
	}
	return (0);
}

static void hookapitests_cleanup(void)
{
	// procmod_Callback_Params params;

	DECAF_printf("Bye world\n");

	if (processbegin_handle != DECAF_NULL_HANDLE) {
		VMI_unregister_callback(VMI_CREATEPROC_CB,
				processbegin_handle);
		processbegin_handle = DECAF_NULL_HANDLE;
	}

	if (removeproc_handle != DECAF_NULL_HANDLE) {
		VMI_unregister_callback(VMI_REMOVEPROC_CB, removeproc_handle);
		removeproc_handle = DECAF_NULL_HANDLE;
	}
	if (blockbegin_handle != DECAF_NULL_HANDLE) {
		DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, blockbegin_handle);
		blockbegin_handle = DECAF_NULL_HANDLE;
	}

}

static mon_cmd_t hookapitests_term_cmds[] = {
#include "plugin_cmds.h"
		{ NULL, NULL, }, };

plugin_interface_t* init_plugin(void) {
	hookapitests_interface.mon_cmds = hookapitests_term_cmds;
	hookapitests_interface.plugin_cleanup = &hookapitests_cleanup;

	//initialize the plugin
	hookapitests_init();
	return (&hookapitests_interface);
}

