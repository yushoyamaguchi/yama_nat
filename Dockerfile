 
FROM ubuntu:focal
RUN apt -y update
RUN apt -y install iproute2 iputils-ping net-tools build-essential tcpdump libjansson-dev



CMD ["/bin/bash"]