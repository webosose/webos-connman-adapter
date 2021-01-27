/* @@@LICENSE
*
*      Copyright (c) 2021 LG Electronics, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

#ifndef __WFDINFOELEMWRAPPER_H
#define __WFDINFOELEMWRAPPER_H
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct InformationElement InformationElement;

InformationElement* newInformationElement();
InformationElement* newInformationElementArray(InformationElementArray* array);

void wfdinfoelem_add_subelement(InformationElement* wfdinfoelem, Subelement* subelement);
DeviceType wfdinfoelem_get_device_type(InformationElement* wfdinfoelem);
int wfdinfoelem_get_rtsp_port(InformationElement* wfdinfoelem);
bool wfdinfoelem_is_session_available(InformationElement* wfdinfoelem);
bool wfdinfoelem_is_cp_supported(InformationElement* wfdinfoelem);
InformationElementArray* wfdinfoelem_serialize (InformationElement* wfdinfoelem);
void deleteInformationElement(InformationElement* v);
void deleteInformationElementArray(InformationElementArray* v);

InformationElementArray* serialize (InformationElement* wfdinfoelem);
InformationElementArray* wfdinfoelem_serialize (InformationElement* wfdinfoelem);

#ifdef __cplusplus
}
#endif
#endif // __WFDINFOELEMWRAPPER_H
