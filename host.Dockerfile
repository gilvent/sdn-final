FROM ubuntu:22.04
RUN apt-get update -y \
&& apt-get install -y traceroute \
&& apt-get install -y net-tools \
&& apt-get install -y iproute2 \
&& apt-get install -y iputils-ping \
&& apt-get install -y dnsutils \
&& apt-get install -y curl \
&& apt-get install -y tcpdump

CMD ["sleep","infinity"]
