/*
 * Copyright (C) 2026 The pgexporter community
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may
 * be used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* pgexporter */
#include <pgexporter.h>
#include <extension.h>
#include <fips.h>
#include <logging.h>
#include <queries.h>
#include <utils.h>

/* system */
#include <stdio.h>

/* OpenSSL */
#include <openssl/crypto.h>
#include <openssl/evp.h>

static int query_fips_mode(int server, struct query** query);
static int read_system_fips_status(bool* status);

bool
pgexporter_fips_openssl(void)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
   // OpenSSL 3.0+
   return EVP_default_properties_is_fips_enabled(NULL) == 1;
#else
   return false;
#endif
}

int
pgexporter_fips_mode(int server, bool* status)
{
   int ret;
   struct query* query = NULL;
   struct tuple* current = NULL;
   struct configuration* config;

   config = (struct configuration*)shmem;

   // Return cached value if already checked
   if (config->servers[server].fips_checked)
   {
      *status = config->servers[server].fips_enabled;
      return 0;
   }

   *status = false;

   // PostgreSQL 18+: Use fips_mode() function from pgcrypto
   if (config->servers[server].version >= 18)
   {
      if (!pgexporter_extension_is_enabled(config, server, "pgcrypto"))
      {
         goto done;
      }

      ret = query_fips_mode(server, &query);
      if (ret != 0)
      {
         pgexporter_log_error("FIPS: Failed to query fips_mode() for server %s",
                              config->servers[server].name);
         goto error;
      }

      current = query->tuples;
      if (current == NULL)
      {
         goto done;
      }

      *status = strcmp(pgexporter_get_column(0, current), "1") == 0;
   }
   // PostgreSQL 14-17: Read system-level FIPS status
   else if (config->servers[server].version >= 14)
   {
      ret = read_system_fips_status(status);
      if (ret != 0)
      {
         pgexporter_log_debug("FIPS: Failed to read system FIPS status for server %s",
                              config->servers[server].name);
         goto error;
      }
   }

done:
   config->servers[server].fips_enabled = *status;
   config->servers[server].fips_checked = true;

   pgexporter_free_query(query);
   return 0;

error:
   config->servers[server].fips_enabled = false;
   config->servers[server].fips_checked = true;

   pgexporter_free_query(query);
   return 1;
}

static int
query_fips_mode(int server, struct query** query)
{
   return pgexporter_query_execute(server, "SELECT CASE WHEN fips_mode() THEN 1 ELSE 0 END AS fips_mode;",
                                   "pg_fips_mode", query);
}

static int
read_system_fips_status(bool* status)
{
   FILE* fp = NULL;
   char buffer[2];

   *status = false;

#if defined(__linux__)
   fp = fopen("/proc/sys/crypto/fips_enabled", "r");
   if (fp == NULL)
   {
      // File does not exist or can not be read
      return 0;
   }

   if (fread(buffer, 1, 1, fp) == 1)
   {
      *status = (buffer[0] == '1');
   }

   fclose(fp);

#elif defined(__FreeBSD__)
   fp = popen("sysctl -n kern.fips_enabled 2>/dev/null", "r");
   if (fp == NULL)
   {
      return 0;
   }

   if (fread(buffer, 1, 1, fp) == 1)
   {
      *status = (buffer[0] == '1');
   }

   pclose(fp);

#else
   return 0;
#endif

   return 0;
}
