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

#include "information-element.h"
#include "wfdinfoelemwrapper.h"

extern "C" {
        InformationElement* newInformationElement() {
            return new InformationElement();
        }

        InformationElement* newInformationElementArray(InformationElementArray* array) {
            return new InformationElement(array);
        }

        void wfdinfoelem_add_subelement(InformationElement* wfdinfoelem, Subelement* subelement) {
            wfdinfoelem->add_subelement(subelement);
        }

        DeviceType wfdinfoelem_get_device_type(InformationElement* wfdinfoelem) {
            return wfdinfoelem->get_device_type();
        }

        int wfdinfoelem_get_rtsp_port(InformationElement* wfdinfoelem) {
            return wfdinfoelem->get_rtsp_port();
        }

        bool wfdinfoelem_is_session_available(InformationElement* wfdinfoelem) {
            return wfdinfoelem->is_session_available();
        }

        bool wfdinfoelem_is_cp_supported(InformationElement* wfdinfoelem) {
            return wfdinfoelem->is_cp_supported();
        }

        InformationElementArray* wfdinfoelem_serialize (InformationElement* wfdinfoelem) {
            return wfdinfoelem->serialize();
        }

        void deleteInformationElement(InformationElement* v) {
            delete v;
        }

        void deleteInformationElementArray(InformationElementArray* v) {
            DeleteArray(v);
            delete v;
        }
}
