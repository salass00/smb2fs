/*
 * smb2-handler - SMB2 file system client
 *
 * Copyright (C) 2022-2023 Fredrik Wikstrom <fredrik@a500.org>
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

#define __NOLIBBASE__
#define __NOGLOBALIFACE__

#include <proto/exec.h>
#include <proto/dos.h>
#include <dos/startup.h>

static void reverse(STRPTR str)
{
	STRPTR start = str;
	STRPTR end;
	TEXT tmp;

	for (end = str; *end != '\0'; end++);

	if (end > str)
	{
		end--;
		while (end > str)
		{
			tmp = *end;
			*end = *start;
			*start = tmp;

			start++;
			end--;
		}
	}
}

static void u32toa(uint32 n, STRPTR dst)
{
	STRPTR d = dst;

	do {
		*d++ = '0' + (n % 10);
		n /= 10;
	} while (n > 0);

	*d = '\0';

	reverse(dst);
}

static void strcat(STRPTR dst, CONST_STRPTR src)
{
	STRPTR d = dst;
	CONST_STRPTR s = src;

	while (*d != '\0') d++;

	while ((*d++ = *s++) != '\0');
}

static int32 strlen(CONST_STRPTR str)
{
	CONST_STRPTR s = str;

	while (*s != '\0') s++;

	return (s - str);
}

static BOOL isspace(TEXT c)
{
	return (c == ' ' || c == '\t' || c == '\n' || c == '\r');
}

int32 _start(STRPTR argstring, int32 arglen, struct ExecBase *sysbase)
{
	struct ExecIFace *iexec = (struct ExecIFace *)sysbase->MainInterface;
	struct Library *doslib;
	struct DOSIFace *idos;
	TEXT devname[16];
	struct DosList *dl;
	uint32 n;
	CONST_STRPTR args;
	int32 len;
	STRPTR md_args;

	doslib = iexec->OpenLibrary("dos.library", 53);
	if (doslib == NULL)
	{
		iexec->Alert(AG_OpenLib | AO_DOSLib);
		return RETURN_FAIL;
	}

	idos = (struct DOSIFace *)iexec->GetInterface(doslib, "main", 1, NULL);
	if (idos == NULL)
	{
		iexec->CloseLibrary(doslib);
		iexec->Alert(AG_OpenLib | AO_DOSLib);
		return RETURN_FAIL;
	}

	if (idos->Cli() == NULL) /* WB startup not supported */
	{
		iexec->DropInterface((struct Interface *)idos);
		iexec->CloseLibrary(doslib);
		return RETURN_FAIL;
	}

	/* Generate a unique device name */
	n = 0;
	devname[0] = 'S';
	devname[1] = 'M';
	devname[2] = 'B';
	while (TRUE)
	{
		u32toa(n, &devname[3]);
		dl = idos->LockDosList(LDF_DEVICES | LDF_READ);
		dl = idos->FindDosEntry(dl, devname, LDF_DEVICES | LDF_READ);
		idos->UnLockDosList(LDF_DEVICES | LDF_READ);

		if (dl == NULL)
		{
			break;
		}
		n++; /* Increment and try again */
	}
	strcat(devname, ":");

	args = argstring;
	len = strlen(args);
	while (isspace(*args)) /* Strip leading whitespace */
	{
		args++;
		len--;
	}
	while (len > 0 && isspace(args[len - 1])) /* Strip trailing whitespace */
	{
		len--;
	}

	md_args = iexec->AllocVecTags(len + 3, TAG_END);
	if (md_args == NULL)
	{
		idos->PrintFault(ERROR_NO_FREE_STORE, NULL);
		iexec->DropInterface((struct Interface *)idos);
		iexec->CloseLibrary(doslib);
		return RETURN_ERROR;
	}
	md_args[0] = '"';
	iexec->CopyMem(args, &md_args[1], len);
	md_args[len + 1] = '"';
	md_args[len + 1] = '\0';

	if (idos->MountDeviceTags(devname, MDT_Handler,
		MD_Handler,       "L:smb2-handler",
		MD_StackSize,     65536,
		MD_GlobVec,       -1,
		MD_StartupString, md_args,
		MD_Activate,      TRUE,
		TAG_END) == FALSE)
	{
		idos->PrintFault(idos->IoErr(), "MountDevice");
		iexec->FreeVec(md_args);
		iexec->DropInterface((struct Interface *)idos);
		iexec->CloseLibrary(doslib);
		return RETURN_ERROR;
	}

	iexec->FreeVec(md_args);
	iexec->DropInterface((struct Interface *)idos);
	iexec->CloseLibrary(doslib);

	return RETURN_OK;
}

