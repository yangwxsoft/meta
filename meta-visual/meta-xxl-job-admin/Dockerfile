FROM moxm/java:1.8-full

RUN mkdir -p /meta-xxl-job-admin

WORKDIR /meta-xxl-job-admin

ARG JAR_FILE=target/meta-xxl-job-admin.jar

COPY ${JAR_FILE} app.jar

EXPOSE 5004

ENV TZ=Asia/Shanghai JAVA_OPTS="-Xms128m -Xmx256m -Djava.security.egd=file:/dev/./urandom"

CMD sleep 60; java -jar app.jar $JAVA_OPTS
