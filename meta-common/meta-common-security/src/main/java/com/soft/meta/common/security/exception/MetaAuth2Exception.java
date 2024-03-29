/*
 * Copyright (c) 2020 meta4cloud Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.soft.meta.common.security.exception;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.soft.meta.common.security.component.MetaAuth2ExceptionSerializer;
import lombok.Getter;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

/**
 * @author lengleng
 * @date 2019/2/1 自定义OAuth2Exception
 */
@JsonSerialize(using = MetaAuth2ExceptionSerializer.class)
public class MetaAuth2Exception extends OAuth2Exception {

	@Getter
	private String errorCode;

	public MetaAuth2Exception(String msg) {
		super(msg);
	}

	public MetaAuth2Exception(String msg, String errorCode) {
		super(msg);
		this.errorCode = errorCode;
	}

}
