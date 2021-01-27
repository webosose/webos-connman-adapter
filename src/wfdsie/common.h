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

#ifndef _INFORMATION_ELEMENT_COMMON_H_
#define _INFORMATION_ELEMENT_COMMON_H_

#include <stdint.h>

typedef enum DeviceType {
    SOURCE,
    PRIMARY_SINK,
    SECONDARY_SINK,
    DUAL_ROLE
}DeviceType;

typedef enum SubelementId {
    DEVICE_INFORMATION,
    ASSOCIATED_BSSID,
    AUDIO_FORMATS,
    VIDEO_FORMATS,
    FORMATS_3D,
    CONTENT_PROTECTION,
    COUPLED_SINK_INFORMATION,
    EXTENDED_CAPABILITY,
    LOCAL_IP_ADDRESS,
    SESSION_INFORMATION,
    ALTERNATIVE_MAC,
} SubelementId;

typedef struct InformationElementArray {
    uint8_t *bytes;
    uint length;
}InformationElementArray;

typedef struct __attribute__ ((packed)) Subelement {
    uint8_t id;
    uint16_t length;
}Subelement;

typedef struct __attribute__ ((packed)) DeviceinformationBits1 {
    unsigned device_type : 2; // DeviceType
    unsigned coupled_sink_support_at_source : 1;
    unsigned coupled_sink_support_at_sink : 1;
    unsigned session_availability : 1;
    unsigned reserved : 1;
    unsigned service_discovery_support : 1;
    unsigned preferred_connectivity : 1;
}DeviceinformationBits1;

typedef struct __attribute__ ((packed)) DeviceinformationBits2 {
    unsigned hdcp_support : 1;
    unsigned time_synchronization_support : 1;
    unsigned audio_unsupport_at_primary_sink : 1;
    unsigned audio_only_support_at_source : 1;
    unsigned tdls_persistent_group : 1;
    unsigned tdls_persistent_group_reinvoke : 1;
    unsigned reserved2 : 2;
}DeviceinformationBits2;

typedef struct __attribute__ ((packed)) DeviceInformationSubelement {
    uint8_t id;
    uint16_t length;
    DeviceinformationBits2 field2;
    DeviceinformationBits1 field1;
    uint16_t session_management_control_port;
    uint16_t maximum_throughput;
}DeviceInformationSubelement;

typedef struct __attribute__ ((packed)) AssociatedBSSIDSubelement {
    uint8_t id;
    uint16_t length;
    uint8_t bssid[6];
}AssociatedBSSIDSubelement;

typedef struct __attribute__ ((packed)) CoupledSinkStatus {
    unsigned status : 2;
    unsigned reserved : 6;
}CoupledSinkStatus;

typedef struct __attribute__ ((packed)) CoupledSinkInformationSubelement {
    uint8_t id;
    uint16_t length;
    CoupledSinkStatus status;
    uint8_t mac_address[6];
}CoupledSinkInformationSubelement;

#ifdef __cplusplus
extern "C" {
#endif
Subelement* new_subelement (SubelementId id);
void delete_subelement(Subelement* subelement);
#ifdef __cplusplus
}
#endif

void InitializeArray(InformationElementArray *infoelementarray, uint len);
void InitializeArrayinBytes(InformationElementArray *infoelementarray, uint len, uint8_t* in_bytes);
void DeleteArray(InformationElementArray *infoelementarray);

#endif // _INFORMATION_ELEMENT_COMMON_H_
