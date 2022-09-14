// Copyright Epic Games, Inc. All Rights Reserved.

#pragma once

#include <stdlib.h>

#include "CoreMinimal.h"
#include "Modules/ModuleManager.h"


#ifdef __cplusplus
extern "C" {
#endif

void loli_index_custom_alloc(void* addr, size_t size, int index);
void *loli_index_malloc(size_t size, int index);
void *loli_index_calloc(int n, int size, int index);
void *loli_index_memalign(size_t alignment, size_t size, int index);
int loli_index_posix_memalign(void** ptr, size_t alignment, size_t size, int index);
void *loli_index_realloc(void *ptr, size_t new_size, int index);

#ifdef __cplusplus
}  // extern "C"
#endif

class FHookDumpModule : public IModuleInterface
{
public:

	/** IModuleInterface implementation */
	virtual void StartupModule() override;
	virtual void ShutdownModule() override;
};
