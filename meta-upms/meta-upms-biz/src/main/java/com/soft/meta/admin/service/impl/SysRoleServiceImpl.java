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

package com.soft.meta.admin.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.soft.meta.admin.api.entity.SysRole;
import com.soft.meta.admin.api.entity.SysRoleMenu;
import com.soft.meta.admin.mapper.SysRoleMapper;
import com.soft.meta.admin.mapper.SysRoleMenuMapper;
import com.soft.meta.admin.service.SysRoleService;
import com.soft.meta.common.core.constant.CacheConstants;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * <p>
 * 服务实现类
 * </p>
 *
 * @author lengleng
 * @since 2019/2/1
 */
@Service
@RequiredArgsConstructor
public class SysRoleServiceImpl extends ServiceImpl<SysRoleMapper, SysRole> implements SysRoleService {

	private final SysRoleMenuMapper sysRoleMenuMapper;

	/**
	 * 通过角色ID，删除角色,并清空角色菜单缓存
	 * @param id
	 * @return
	 */
	@Override
	@Transactional(rollbackFor = Exception.class)
	@CacheEvict(value = CacheConstants.MENU_DETAILS, allEntries = true)
	public Boolean removeRoleById(Long id) {
		sysRoleMenuMapper.delete(Wrappers.<SysRoleMenu>update().lambda().eq(SysRoleMenu::getRoleId, id));
		return this.removeById(id);
	}

}
