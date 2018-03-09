// Copyright (c) 2012-2018 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#include <glib.h>
#include <locale.h>
#include <string.h>

#include "utils.h"

#define SYSTEM_LOCALE_US "en-US"
#define SYSTEM_LOCALE_KR "ko-KR"

#define SSID_UTF_8_ENCODED_LEN 12

const char ssid_utf8_encoded[SSID_UTF_8_ENCODED_LEN] =
{
	0x4d, 0x59, 0x5f, 0x54, 0x45, 0x53, 0x54, 0x5f,
	0x53, 0x53, 0x49, 0x44
};

#define SSID_ENC_KR_ENCODED_LEN 6

const char ssid_enc_kr_encoded[SSID_ENC_KR_ENCODED_LEN] =
{
	0xb3, 0xb2, 0xbc, 0xf6, 0xc7, 0xf6
};

#define SSID_ENC_KR_CONVERTED_LEN 9

const char ssid_enc_kr_converted[SSID_ENC_KR_CONVERTED_LEN] =
{
	0xeb, 0x82, 0xa8, 0xec, 0x88, 0x98, 0xed, 0x98,
	0x84
};

/**
 * @brief Check if the convert_ssid_to_utf8 method still works as it should with passing
 * invalid parameters.
 */

static void test_with_invalid_arguments(void)
{
	char *result = NULL;

	result = convert_ssid_to_utf8(NULL, 0, NULL);
	g_assert(result == NULL);

	g_free(result);

	result = convert_ssid_to_utf8(NULL, 10, SYSTEM_LOCALE_US);
	g_assert(result == NULL);

	g_free(result);

	result = convert_ssid_to_utf8("test", 0, SYSTEM_LOCALE_US);
	g_assert(result == NULL);

	g_free(result);

	result = convert_ssid_to_utf8("test", 3, SYSTEM_LOCALE_US);
	g_assert(result != NULL);

	g_free(result);

	result = convert_ssid_to_utf8("test", 10, SYSTEM_LOCALE_US);
	g_assert(result != NULL);

	g_free(result);

	result = convert_ssid_to_utf8("test", 4, SYSTEM_LOCALE_US);
	g_assert(result != NULL);

	g_free(result);
}

/**
 * @brief. Check if the convert_ssid_to_utf8 method returns valid UTF-8 when it's filled
 * with already valid UTF-8 data.
 */

static void test_with_valid_utf8(void)
{
	char *result = NULL;

	result = convert_ssid_to_utf8(ssid_utf8_encoded, SSID_UTF_8_ENCODED_LEN,
	                              SYSTEM_LOCALE_US);
	g_assert(result != NULL);
	g_assert(g_utf8_validate(result, -1, NULL) == TRUE);
	g_assert(strncmp(ssid_utf8_encoded, result, SSID_UTF_8_ENCODED_LEN) == 0);

	g_free(result);

	result = convert_ssid_to_utf8(ssid_utf8_encoded, SSID_UTF_8_ENCODED_LEN, NULL);
	g_assert(result != NULL);
	g_assert(g_utf8_validate(result, -1, NULL) == TRUE);
	g_assert(strncmp(ssid_utf8_encoded, result, SSID_UTF_8_ENCODED_LEN) == 0);

	g_free(result);
}

/**
 * @brief Check if convert_ssid_to_utf8 method can handle EUC-KR encoded input data
 * correctly and returns what it is expected for.
 */

static void test_with_enc_kr(void)
{
	char *result = NULL;

	g_assert(g_utf8_validate(ssid_enc_kr_encoded, -1, NULL) == FALSE);

	result = convert_ssid_to_utf8(ssid_enc_kr_encoded, SSID_ENC_KR_ENCODED_LEN,
	                              SYSTEM_LOCALE_KR);
	g_assert(result != NULL);
	g_assert(strncmp(ssid_enc_kr_converted, result,
	                 SSID_ENC_KR_CONVERTED_LEN) == 0);

	g_free(result);


	result = convert_ssid_to_utf8(ssid_enc_kr_encoded, SSID_ENC_KR_ENCODED_LEN,
	                              SYSTEM_LOCALE_US);
	g_assert(result != NULL);
	g_assert(strncmp(ssid_enc_kr_converted, result,
	                 SSID_ENC_KR_CONVERTED_LEN) != 0);

	g_free(result);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/convert_ssid_to_utf8/invalid_arguments",
	                test_with_invalid_arguments);
	g_test_add_func("/convert_ssid_to_utf8/with_valid_utf8",
	                test_with_valid_utf8);
	g_test_add_func("/convert_ssid_to_utf8/with_enc_kr",
	                test_with_enc_kr);

	return g_test_run();
}
