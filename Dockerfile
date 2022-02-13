 
FROM ubuntu:focal

ENV DEBIAN_FRONTEND noninteractive
RUN apt -y update
RUN apt -y install iproute2 iputils-ping net-tools build-essential tcpdump libjansson-dev hping3 inetutils-traceroute



CMD ["/bin/bash"]