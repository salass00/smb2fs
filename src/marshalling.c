/*
 * smb2-handler - SMB2 file system client
 *
 * Copyright (C) 2022-2025 Fredrik Wikstrom <fredrik@a500.org>
 * Copyright (C) 2024 Walter Licht https://github.com/sirwalt
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

#include "marshalling.h"

//#include <debuglib.h>
#include <stdlib.h>
#include <string.h>

struct PointerHandleRegistry* AllocateNewRegistry(uint32_t incarnation) {
    //ASSERT(incarnation != 0)

    struct PointerHandleRegistry* registry = calloc(1, sizeof(struct PointerHandleRegistry));
    if(registry == NULL)
        return NULL;

    registry->size = 0;
    registry->capacity = GROWSIZE;
    registry->pointers = calloc(registry->capacity, sizeof(void*));
    registry->incarnation = incarnation & ((1 << INCARNATION_BITS) - 1);
    registry->freeHead = NULL;  // No free indicies to start with

    if(registry->pointers == NULL)
    {
        free(registry);
        return NULL;
    }

    return registry;
}

void FreeRegistry(struct PointerHandleRegistry* registry) {
    struct FreeIndexNode* current = registry->freeHead;
    while (current != NULL) {
        struct FreeIndexNode* temp = current;
        current = current->next;
        free(temp);
    }

    free(registry->pointers);
    free(registry);
}


uint32_t AllocateHandleForPointer(struct PointerHandleRegistry* registry, void* ptr) {
    size_t index;

    if (registry->freeHead) {
        // reuse index if available
        index = registry->freeHead->index;
        registry->pointers[index] = ptr;

        struct FreeIndexNode* temp = registry->freeHead;
        registry->freeHead = registry->freeHead->next;
        free(temp);
    } else {
        //we cannot have more than 2^22 handles
        if(registry->size == MAX_INDEX)
            return 0;

        if (registry->size == registry->capacity) {
            // extend the array if necessary
            size_t new_capacity = registry->capacity + GROWSIZE;
            
            void* new_pointers = calloc(new_capacity, sizeof(void*));
            if(new_pointers == NULL) return 0;

            memcpy(new_pointers, registry->pointers, registry->capacity * sizeof(void*));
            free(registry->pointers);
            registry->pointers = new_pointers;
            registry->capacity = new_capacity;
        }

        index = registry->size;
        registry->pointers[index] = ptr;
        registry->size++;
    }

    return (registry->incarnation << INDEX_BITS) | (uint32_t)(index);
}

void RemoveHandle(struct PointerHandleRegistry* registry, uint32_t handle) {
    uint32_t index = handle & MAX_INDEX;

    if (index < registry->size && registry->pointers[index] != NULL) {
        // set pointer entry to NULL
        registry->pointers[index] = NULL;

        // Add index to list of free indicies
        struct FreeIndexNode* newFree = calloc(1, sizeof(struct FreeIndexNode));
        // if we cannot allocate memory, we loose a free index - will get worse anyhow
        if(newFree != NULL)
        {
            newFree->index = index;
            newFree->next = registry->freeHead;
            registry->freeHead = newFree;
        }
    }
}

void* HandleToPointer(struct PointerHandleRegistry* registry, uint32_t handle) {
    uint32_t index = handle & MAX_INDEX;
    uint32_t incarnation = handle >> INDEX_BITS;

    if (incarnation == registry->incarnation && index < registry->size) {
        return registry->pointers[index];
    }

    return NULL;
}


