FROM moxm/java:1.8-full

RUN mkdir -p /meta-sentinel-dashboard

WORKDIR /meta-sentinel-dashboard

ARG JAR_FILE=target/meta-sentinel-dashboard.jar

COPY ${JAR_FILE} app.jar

EXPOSE 5003

ENV TZ=Asia/Shanghai JAVA_OPTS="-Xms128m -Xmx256m -Djava.security.egd=file:/dev/./urandom"

CMD sleep 60; java -jar app.jar $JAVA_OPTS
