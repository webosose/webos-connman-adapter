// Copyright (c) 2016-2018 LG Electronics, Inc.
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


#include <pbnjson/c/jtypes.h>
#include "json_utils.h"

static char* convert_jobject_to_native_valist(jvalue_ref json, va_list *valist)
{
	jvalue_ref valueObj;
	JsonValueType type;
	const char* key;
	void *destination;
	gboolean mandatory;
	ConversionResultFlags json_error;
	int64_t int_value;

	while (true)
	{
		type = va_arg(*valist, JsonValueType);

		if (type == json_object_end)
		{
			//Object finished, return success
			break;
		}

		// This is field, get base params
		key = va_arg(*valist, char*);
		destination = va_arg(*valist, void*);
		mandatory = va_arg(*valist, gboolean);

		if (!key)
		{
			return g_strdup("Key is null");
		}

		if (!destination)
		{
			return g_strdup("Destination pointer is null");
		}

		valueObj = jobject_get(json, j_cstr_to_buffer(key));

		if (!jis_valid(valueObj))
		{
			if (!mandatory)
				continue;
			else
			{
				return g_strdup_printf("Mandatory field %s missing", key);
			}
		}

		// Ok, now we have a non-null value and need to parse it
		switch (type)
		{
			case json_type_jvalue_ref:
				*((jvalue_ref*)destination) = valueObj;
				break;
			case json_type_jvalue_ref_array:
				if (!jis_array(valueObj))
				{
					return g_strdup_printf("Field %s not an array", key);
				}

				*((jvalue_ref*)destination) = valueObj;
				break;
			case json_type_jvalue_ref_object:
				if (!jis_object(valueObj))
				{
					return g_strdup_printf("Field %s not a object", key);
				}

				*((jvalue_ref*)destination) = valueObj;
				break;
			case json_type_string:
				if (!jis_string(valueObj))
				{
					return g_strdup_printf("Field %s not a string", key);
				}

				*((const char**)destination) = jstring_get_fast(valueObj).m_str;
				break;
			case json_type_boolean:
				if (!jis_boolean(valueObj))
				{
					return g_strdup_printf("Field %s is not a boolean", key);
				}

				jboolean_get(valueObj, (bool*)destination);
				break;
			case json_type_uint8:
				if (!jis_number(valueObj))
				{
					return g_strdup_printf("Field %s not a number", key);
				}

				json_error = jnumber_get_i64(valueObj, &int_value);
				if (json_error || int_value < 0 || int_value >= (2<<8))
				{
					return g_strdup_printf("Field %s number of out range of uint8", key);
				}

				*((guint8*)destination) = (guint8)int_value;
				break;
			case json_type_uint16:
				if (!jis_number(valueObj))
				{
					return g_strdup_printf("Field %s not a number", key);
				}

				json_error = jnumber_get_i64(valueObj, &int_value);
				if (json_error || int_value < 0 || int_value >= (2<<16))
				{
					return g_strdup_printf("Field %s number of out range of uint16", key);
				}

				*((guint16*)destination) = (guint16)int_value;
				break;
			case json_type_uint32:
				if (!jis_number(valueObj))
				{
					return g_strdup_printf("Field %s not a number", key);
				}

				json_error = jnumber_get_i64(valueObj, &int_value);
				if (json_error || int_value < 0 || int_value >= (((guint64)2)<<32))
				{
					return g_strdup_printf(
							"Field %s number of out range of uint32",
							key);
				}

				*((guint32*)destination) = (guint32)int_value;
				break;
			case json_type_int32:
				if (!jis_number(valueObj))
				{
					return g_strdup_printf("Field %s not a number", key);
				}

				gint32 int32_value;
				json_error = jnumber_get_i32(valueObj, &int32_value);
				if (json_error)
				{
					return g_strdup_printf("Field %s number of out range of int32", key);
				}

				*((gint32*)destination) = int32_value;
				break;
			default:
				//TODO: not implemented subobjects and arrays
				return g_strdup_printf("Invalid or unsupported type %i", type);

		}
	}

	return NULL;
}

char* generate_jobject_from_native_valist(jvalue_ref* result, va_list* valist)
{
	JsonValueType type;
	const char* key;
	const char* str_value;
	bool bool_value;
	guint8 u8_value;
	guint16 u16_value;
	guint32 u32_value;
	gint32 i32_value;
	bool need_to_add;

	jvalue_ref obj = jobject_create();
	jvalue_ref sub_obj = NULL;

	while (true)
	{
		type = va_arg(*valist, JsonValueType);

		if (type == json_object_end)
		{
			break;
		}

		// This is a field, get base params
		key = va_arg(*valist, char*);

		if (!key)
		{
			j_release(&obj);
			return g_strdup("Key is null");
		}

		switch (type)
		{
			case json_type_jvalue_ref_array:
				sub_obj = va_arg(*valist, jvalue_ref);
				if (!jis_array(sub_obj ))
				{
					j_release(&obj);
					return g_strdup_printf("Field %s not an array", key);
				}
				need_to_add = va_arg(*valist, int);
				break;
			case json_type_jvalue_ref_object:
				sub_obj = va_arg(*valist, jvalue_ref);
				if (!jis_object(sub_obj))
				{
					j_release(&obj);
					return g_strdup_printf("Field %s not a object", key);
				}
				need_to_add = va_arg(*valist, int);
				break;
			case json_type_jvalue_ref:
				sub_obj = va_arg(*valist, jvalue_ref);
				if (!jis_valid(sub_obj))
				{
					j_release(&obj);
					return g_strdup_printf("Field %s not a jvalue", key);
				}
				need_to_add = va_arg(*valist, int);
				break;
			case json_type_string:
				str_value = va_arg(*valist, const char*);
				need_to_add = va_arg(*valist, int);

				if (need_to_add)
				{
					sub_obj = jstring_create(str_value);
				}
				break;
			case json_type_boolean:
				bool_value = va_arg(*valist, int); // args smaller than int are promoted to int
				need_to_add = va_arg(*valist, int);

				if (need_to_add)
				{
					sub_obj = jboolean_create(bool_value);
				}
				break;
			case json_type_uint8:
				u8_value = va_arg(*valist, int); // args smaller than int are promoted to int
				need_to_add = va_arg(*valist, int);

				if (need_to_add)
				{
					sub_obj = jnumber_create_i32(u8_value);
				}
				break;
			case json_type_uint16:
				u16_value = va_arg(*valist, int); // args smaller than int are promoted to int
				need_to_add = va_arg(*valist, int);

				if (need_to_add)
				{
					sub_obj = jnumber_create_i32(u16_value);
				}
				break;
			case json_type_uint32:
				u32_value = va_arg(*valist, guint32);
				need_to_add = va_arg(*valist, int);

				if (need_to_add)
				{
					sub_obj = jnumber_create_i64(u32_value);
				}
				break;
			case json_type_int32:
				i32_value = va_arg(*valist, gint32);
				need_to_add = va_arg(*valist, int);

				if (need_to_add)
				{
					sub_obj = jnumber_create_i32(i32_value);
				}
				break;
			default:
				//TODO: not implemented subobjects and arrays
				j_release(&obj);
				return g_strdup_printf("Invalid or unsupported type %i", type);
		}

		if (need_to_add)
		{
			if (!jobject_put(obj, jstring_create(key), sub_obj))
			{
				return g_strdup_printf("Not failed to add json object for field %s, invalid joson object?", key);
			}
		}
	}

	*result = obj;

	return NULL;
}


char* json_convert_to_native_valist(jvalue_ref json, va_list *valist)
{
	JsonValueType type = va_arg(*valist, JsonValueType);

	if (type == json_object_start)
	{
		return convert_jobject_to_native_valist(json, valist);
	}

	return g_strdup("Invalid params list");
}

char* json_generate_from_native_valist(jvalue_ref* result, va_list* valist)
{
	JsonValueType type = va_arg(*valist, JsonValueType);

	if (type == json_object_start)
	{
		return generate_jobject_from_native_valist(result, valist);
	}

	return g_strdup("Invalid params list");
}
