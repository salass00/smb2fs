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

#ifndef SMB2FS_H
#define SMB2FS_H 1

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/filesysbox.h>
#include <proto/bsdsocket.h>

#define ID_SMB2_DISK (0x534D4202UL)

#ifdef __amigaos4__
struct Interface *open_interface(CONST_STRPTR name, int version);
void close_interface(struct Interface *interface);
#endif

int smb2fs_main(struct DosPacket *pkt);

#endif /* SMB2FS_H */
