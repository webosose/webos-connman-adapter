/*
 * This file is part of Wireless Display Software for Linux OS
 *
 * Copyright (C) 2021 Intel Corporation.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef INFORMATION_ELEMENT_H_
#define INFORMATION_ELEMENT_H_

#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <stdint.h>
#include "common.h"

class InformationElement {
public:
	InformationElement();
	InformationElement(InformationElementArray *array);
	virtual ~InformationElement();

	void add_subelement(Subelement* subelement);
	DeviceType get_device_type() const;
	int get_rtsp_port() const;
	bool is_session_available() const;
	bool is_cp_supported() const;

	InformationElementArray* serialize () const;
	std::string to_string() const;

private:

	uint length_;
	std::map<SubelementId, Subelement*> subelements_;
};

#endif // INFORMATION_ELEMENT_H_
