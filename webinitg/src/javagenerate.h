#ifndef JAVAGENERATE_H
#define JAVAGENERATE_H

#include "cjsonconfig.h"
#include "wpk/wpk_uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

int JavaGenerate(const WebinitConfig *config,const char* file_java,const char* file_c,const char *password,const wpk_uuid_t uuid);

#ifdef __cplusplus
}
#endif

#endif