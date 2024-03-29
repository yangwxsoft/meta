package com.soft.meta.common.security.component;

import com.soft.meta.common.core.constant.CacheConstants;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * @author lengleng
 * @date 2021/10/16
 */
public class MetaTokenStoreAutoConfiguration {

	@Bean
	public TokenStore tokenStore(RedisConnectionFactory redisConnectionFactory) {
		MetaRedisTokenStore tokenStore = new MetaRedisTokenStore(redisConnectionFactory);
		tokenStore.setPrefix(CacheConstants.PROJECT_OAUTH_ACCESS);
		return tokenStore;
	}

}
