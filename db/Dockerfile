FROM mysql:8.0.27

MAINTAINER lengleng(wangiegie@gmail.com)

ENV TZ=Asia/Shanghai

RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

COPY ./meta.sql /docker-entrypoint-initdb.d

COPY ./meta_codegen.sql /docker-entrypoint-initdb.d

COPY ./meta_config.sql /docker-entrypoint-initdb.d

COPY ./meta_job.sql /docker-entrypoint-initdb.d
