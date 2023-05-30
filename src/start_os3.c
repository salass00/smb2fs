/*
 * smb2-handler - SMB2 file system client
 *
 * Copyright (C) 2022 Fredrik Wikstrom <fredrik@a500.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the smb2-handler
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "smb2fs.h"
#include "smb2-handler_rev.h"

#include <bsdsocket/socketbasetags.h>
#include <proto/bsdsocket.h>
#include <SDI/SDI_compiler.h>
#include <errno.h>

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;
struct UtilityBase *UtilityBase;
#ifdef __AROS__
struct Library *aroscbase;
#endif
struct Library *FileSysBoxBase;
struct Library *SocketBase;

static const char vstring[];
static const char dosName[];
static const char utilityName[];
#ifdef __AROS__
static const char aroscName[];
#endif
static const char filesysboxName[];
static const char bsdsocketName[];

extern int setup_malloc(void);
extern int cleanup_malloc(void);

#ifdef __AROS__
AROS_UFH3(int, startup,
	AROS_UFHA(STRPTR, argstr, A0),
	AROS_UFHA(ULONG, arglen, D0),
	AROS_UFHA(struct ExecBase *, sysbase, A6)
)
{
	AROS_USERFUNC_INIT
#else
int startup(void)
{
#endif
	struct Process   *me;
	struct DosPacket *pkt = NULL;
	int               rc = RETURN_ERROR;
	struct MsgPort   *port = NULL;

#ifdef __AROS__
	SysBase = sysbase;
#else
	SysBase = *(struct ExecBase **)4;
#endif

	if (!setup_malloc())
	{
		goto cleanup;
	}

	DOSBase = (struct DosLibrary *)OpenLibrary((STRPTR)dosName, 39);
	if (DOSBase == NULL)
	{
		goto cleanup;
	}

	UtilityBase = (struct UtilityBase *)OpenLibrary((STRPTR)utilityName, 39);
	if (UtilityBase == NULL)
	{
		goto cleanup;
	}

#ifdef __AROS__
	aroscbase = OpenLibrary((STRPTR)aroscName, 41);
	if (aroscbase == NULL)
	{
		goto cleanup;
	}
#endif

	me = (struct Process *)FindTask(NULL);
	if (me->pr_CLI != 0)
	{
		PutStr((STRPTR)vstring);
		rc = RETURN_OK;
		goto cleanup;
	}

	port = &me->pr_MsgPort;
	WaitPort(port);
	struct Message *msg = GetMsg(port);
	if (msg == NULL) goto cleanup;

	if (msg->mn_Node.ln_Name == NULL)
	{
		rc = RETURN_FAIL;
		Forbid();
		ReplyMsg(msg);
		goto cleanup;
	}

	pkt = (struct DosPacket *)msg->mn_Node.ln_Name;

	FileSysBoxBase = OpenLibrary((STRPTR)filesysboxName, 54);
	if (FileSysBoxBase == NULL)
	{
		goto cleanup;
	}

	SocketBase = OpenLibrary((STRPTR)bsdsocketName, 3);
	if (SocketBase == NULL)
	{
		goto cleanup;
	}

	if (SocketBaseTags(
		SBTM_SETVAL(SBTC_BREAKMASK),     0, /* Disable CTRL-C checking in WaitSelect() */
		SBTM_SETVAL(SBTC_ERRNOLONGPTR),  &errno,
		//SBTM_SETVAL(SBTC_HERRNOLONGPTR), &h_errno // TODO
		TAG_END))
	{
		goto cleanup;
	}

	rc = smb2fs_main(pkt);

	/* Set to NULL so we don't reply the packet twice */
	pkt = NULL;

cleanup:

	if (SocketBase != NULL)
	{
		CloseLibrary(SocketBase);
		SocketBase = NULL;
	}

	if (FileSysBoxBase != NULL)
	{
		CloseLibrary(FileSysBoxBase);
		FileSysBoxBase = NULL;
	}

	if (pkt != NULL)
	{
		ReplyPkt(pkt, DOSFALSE, ERROR_INVALID_RESIDENT_LIBRARY);
		pkt = NULL;
	}

#ifdef __AROS__
	if (aroscbase != NULL)
	{
		CloseLibrary(aroscbase);
		aroscbase = NULL;
	}
#endif

	if (UtilityBase != NULL)
	{
		CloseLibrary((struct Library *)UtilityBase);
		DOSBase = NULL;
	}

	if (DOSBase != NULL)
	{
		CloseLibrary((struct Library *)DOSBase);
		DOSBase = NULL;
	}

	cleanup_malloc();

	return rc;

#ifdef __AROS__
	AROS_USERFUNC_EXIT
#endif
}

/* Disable CTRL-C signal checking in libc. */
void __chkabort(void) {}

static const TEXT USED verstag[] = VERSTAG;
static const char vstring[] = VSTRING;
static const char dosName[] = "dos.library";
static const char utilityName[] = "utility.library";
#ifdef __AROS__
static const char aroscName[] = "arosc.library";
#endif
static const char filesysboxName[] = "filesysbox.library";
static const char bsdsocketName[] = "bsdsocket.library";
