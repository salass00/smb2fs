/*
 * smb2-handler - SMB2 file system client
 *
 * Copyright (C) 2022-2025 Fredrik Wikstrom <fredrik@a500.org>
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

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>

#define DEFAULT_OUTPUT_BUFFER_LENGTH 0xffff

struct pollfd {
	int fd;
	short events;
	short revents;
};

int poll(struct pollfd *fds, unsigned int nfds, int timo);

struct stat_cb_data {
	smb2_command_cb cb;
	void *cb_data;

	uint32_t status;
	struct smb2_file_basic_info *fbi;
};

static void stat_cb_1(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
	struct stat_cb_data *stat_data = private_data;

	if (stat_data->status == SMB2_STATUS_SUCCESS)
	{
		stat_data->status = status;
	}
}

static void stat_cb_2(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
	struct stat_cb_data *stat_data = private_data;
	struct smb2_query_info_reply *rep = command_data;
	struct smb2_file_basic_info *fbi = rep->output_buffer;

	if (stat_data->status == SMB2_STATUS_SUCCESS)
	{
		stat_data->status = status;
	}
	if (stat_data->status != SMB2_STATUS_SUCCESS)
	{
		return;
	}

	stat_data->fbi = fbi;
}

static void stat_cb_3(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
	struct stat_cb_data *stat_data = private_data;

	if (stat_data->status == SMB2_STATUS_SUCCESS)
	{
		stat_data->status = status;
	}

	stat_data->cb(smb2, -nterror_to_errno(stat_data->status), stat_data->fbi, stat_data->cb_data);
	free(stat_data);
}

int send_compound_stat(struct smb2_context *smb2, const char *path, smb2_command_cb cb, void *cb_data)
{
	struct stat_cb_data *stat_data;
	struct smb2_create_request cr_req;
	struct smb2_query_info_request qi_req;
	struct smb2_close_request cl_req;
	struct smb2_pdu *pdu, *next_pdu;

	stat_data = calloc(1, sizeof(*stat_data));
	if (stat_data == NULL)
	{
		smb2_set_error(smb2, "Failed to allocate stat_data");
		return -1;
	}

	stat_data->cb = cb;
	stat_data->cb_data = cb_data;

	/* CREATE command */
	bzero(&cr_req, sizeof(cr_req));
	cr_req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
	cr_req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
	cr_req.desired_access = SMB2_FILE_READ_ATTRIBUTES | SMB2_FILE_READ_EA;
	cr_req.file_attributes = 0;
	cr_req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
	cr_req.create_disposition = SMB2_FILE_OPEN;
	cr_req.create_options = 0;
	cr_req.name = path;

	pdu = smb2_cmd_create_async(smb2, &cr_req, stat_cb_1, stat_data);
	if (pdu == NULL)
	{
		smb2_set_error(smb2, "Failed to create create command");
		free(stat_data);
		return -1;
	}

	/* QUERY INFO command */
	bzero(&qi_req, sizeof(qi_req));
	qi_req.info_type = SMB2_0_INFO_FILE;
	qi_req.file_info_class = SMB2_FILE_BASIC_INFORMATION;
	qi_req.output_buffer_length = DEFAULT_OUTPUT_BUFFER_LENGTH;
	qi_req.additional_information = 0;
	qi_req.flags = 0;
	memcpy(qi_req.file_id, compound_file_id, SMB2_FD_SIZE);

	next_pdu = smb2_cmd_query_info_async(smb2, &qi_req, stat_cb_2, stat_data);
	if (next_pdu == NULL)
	{
		smb2_set_error(smb2, "Failed to create query command");
		free(stat_data);
		smb2_free_pdu(smb2, pdu);
		return -1;
	}
	smb2_add_compound_pdu(smb2, pdu, next_pdu);

	/* CLOSE command */
	bzero(&cl_req, sizeof(cl_req));
	cl_req.flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
	memcpy(cl_req.file_id, compound_file_id, SMB2_FD_SIZE);

	next_pdu = smb2_cmd_close_async(smb2, &cl_req, stat_cb_3, stat_data);
	if (next_pdu == NULL)
	{
		smb2_set_error(smb2, "Failed to create close command");
		free(stat_data);
		smb2_free_pdu(smb2, pdu);
		return -1;
	}
	smb2_add_compound_pdu(smb2, pdu, next_pdu);

	smb2_queue_pdu(smb2, pdu);

	return 0;
}

struct set_cb_data {
	smb2_command_cb cb;
	void *cb_data;

	uint32_t status;
};

static void set_cb_1(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
	struct set_cb_data *set_data = private_data;

	if (set_data->status == SMB2_STATUS_SUCCESS)
	{
		set_data->status = status;
	}
}

static void set_cb_2(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
	struct set_cb_data *set_data = private_data;

	if (set_data->status == SMB2_STATUS_SUCCESS)
	{
		set_data->status = status;
	}
}

static void set_cb_3(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
	struct set_cb_data *set_data = private_data;

	if (set_data->status == SMB2_STATUS_SUCCESS)
	{
		set_data->status = status;
	}

	set_data->cb(smb2, -nterror_to_errno(set_data->status), NULL, set_data->cb_data);
	free(set_data);
}

int send_compound_set(struct smb2_context *smb2, const char *path, struct smb2_file_basic_info *fbi,
                      smb2_command_cb cb, void *cb_data)
{
	struct set_cb_data *set_data;
	struct smb2_create_request cr_req;
	struct smb2_set_info_request si_req;
	struct smb2_close_request cl_req;
	struct smb2_pdu *pdu, *next_pdu;

	set_data = calloc(1, sizeof(*set_data));
	if (set_data == NULL)
	{
		smb2_set_error(smb2, "Failed to allocate setinfo_data");
		return -1;
	}

	set_data->cb = cb;
	set_data->cb_data = cb_data;

	/* CREATE command */
	bzero(&cr_req, sizeof(cr_req));
	cr_req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
	cr_req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
	cr_req.desired_access = SMB2_FILE_WRITE_ATTRIBUTES | SMB2_FILE_WRITE_EA;
	cr_req.file_attributes = 0;
	cr_req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
	cr_req.create_disposition = SMB2_FILE_OPEN;
	cr_req.create_options = 0;
	cr_req.name = path;

	pdu = smb2_cmd_create_async(smb2, &cr_req, set_cb_1, set_data);
	if (pdu == NULL)
	{
		smb2_set_error(smb2, "Failed to create create command");
		free(set_data);
		return -1;
	}

	/* SET INFO command */
	bzero(&si_req, sizeof(si_req));
	si_req.info_type = SMB2_0_INFO_FILE;
	si_req.file_info_class = SMB2_FILE_BASIC_INFORMATION;
	si_req.additional_information = 0;
	memcpy(si_req.file_id, compound_file_id, SMB2_FD_SIZE);
	si_req.input_data = fbi;

	next_pdu = smb2_cmd_set_info_async(smb2, &si_req, set_cb_2, set_data);
	if (next_pdu == NULL)
	{
		smb2_set_error(smb2, "Failed to create set command");
		free(set_data);
		smb2_free_pdu(smb2, pdu);
		return -1;
	}
	smb2_add_compound_pdu(smb2, pdu, next_pdu);

	/* CLOSE command */
	bzero(&cl_req, sizeof(cl_req));
	cl_req.flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
	memcpy(cl_req.file_id, compound_file_id, SMB2_FD_SIZE);

	next_pdu = smb2_cmd_close_async(smb2, &cl_req, set_cb_3, set_data);
	if (next_pdu == NULL)
	{
		smb2_set_error(smb2, "Failed to create close command");
		free(set_data);
		smb2_free_pdu(smb2, pdu);
		return -1;
	}
	smb2_add_compound_pdu(smb2, pdu, next_pdu);

	smb2_queue_pdu(smb2, pdu);

	return 0;
}

struct sync_cb_data {
	int is_finished;
	int status;
	void *ptr;
};

static void generic_status_cb(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
	struct sync_cb_data *cb_data = private_data;

	cb_data->is_finished = 1;
	cb_data->status = status;
	cb_data->ptr = command_data;
}

static int wait_for_reply(struct smb2_context *smb2, struct sync_cb_data *cb_data)
{
	while (!cb_data->is_finished)
	{
		struct pollfd pfd;

		pfd.fd = smb2_get_fd(smb2);
		pfd.events = smb2_which_events(smb2);

		if (poll(&pfd, 1, 1000) < 0)
		{
			smb2_set_error(smb2, "Poll failed");
			return -1;
		}
		if (pfd.revents == 0)
		{
			continue;
		}
		if (smb2_service(smb2, pfd.revents) < 0)
		{
			smb2_set_error(smb2, "smb2_service failed with : %s\n", smb2_get_error(smb2));
			return -1;
		}
	}

	return 0;
}

int smb2_utimens(struct smb2_context *smb2, const char *path, const struct timespec tv[2])
{
	struct sync_cb_data *cb_data;
	struct smb2_file_basic_info fbi;
	int status;
	int rc;

	cb_data = calloc(1, sizeof(*cb_data));
	if (cb_data == NULL)
	{
		smb2_set_error(smb2, "Failed to allocate sync_cb_data");
		return -ENOMEM;
	}

	if (send_compound_stat(smb2, path, generic_status_cb, cb_data) != SMB2_STATUS_SUCCESS)
	{
		return -1;
	}

	rc = wait_for_reply(smb2, cb_data);
	if (rc < 0)
	{
		cb_data->status = SMB2_STATUS_CANCELLED;
		return -1;
	}

	status = cb_data->status;
	if (status != SMB2_STATUS_SUCCESS)
	{
		free(cb_data);
		return status;
	}

	memcpy(&fbi, cb_data->ptr, sizeof(fbi));
	smb2_free_data(smb2, cb_data->ptr);
	free(cb_data);

	/* FIXME: Which timeval should be set to tv[0] and which to tv[1]?
	 * Difference is mainly semantic at the moment as filesysbox always
	 * sets both to the same value, but this may matter in the future.
     */
	fbi.last_write_time.tv_sec = tv[0].tv_sec;
	fbi.last_write_time.tv_usec = tv[0].tv_nsec / 1000;
	fbi.change_time.tv_sec = tv[0].tv_sec;
	fbi.change_time.tv_usec = tv[0].tv_nsec / 1000;

	cb_data = calloc(1, sizeof(*cb_data));
	if (cb_data == NULL)
	{
		smb2_set_error(smb2, "Failed to allocate sync_cb_data");
		return -ENOMEM;
	}

	if (send_compound_set(smb2, path, &fbi, generic_status_cb, cb_data) != SMB2_STATUS_SUCCESS)
	{
		return -1;
	}

	rc = wait_for_reply(smb2, cb_data);
	if (rc < 0)
	{
		cb_data->status = SMB2_STATUS_CANCELLED;
		return -1;
	}

	status = cb_data->status;
	free(cb_data);
	return status;
}

