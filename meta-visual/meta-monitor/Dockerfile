FROM moxm/java:1.8-full

RUN mkdir -p /meta-monitor

WORKDIR /meta-monitor

ARG JAR_FILE=target/meta-monitor.jar

COPY ${JAR_FILE} app.jar

EXPOSE 5001

ENV TZ=Asia/Shanghai JAVA_OPTS="-Xms128m -Xmx256m -Djava.security.egd=file:/dev/./urandom"

CMD sleep 60; java -jar app.jar $JAVA_OPTS
