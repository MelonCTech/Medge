FROM melonc/melon
WORKDIR /root
RUN apt-get update && \
    apt-get -y install make git gcc && \
    git clone https://github.com/Water-Melon/Medge.git && cd Medge && ./configure && make && make install && \
    cd ../ && rm -fr Medge
CMD /usr/bin/medge -w `cat /proc/cpuinfo |grep processor|wc -l`
