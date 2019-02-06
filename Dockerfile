FROM fedora:28

RUN dnf install -y python3 python3-pip && \
   dnf install -y procps-ng && dnf clean all

RUN python3 -m pip install --upgrade pip
RUN mkdir /install
COPY wheels/*.whl /install/
RUN ls /install/
RUN pip3 install flask
RUN pip3 install requests
RUN pip3 install pika
RUN pip3 install dpkt
RUN pip3 install pyja3

RUN pip3 install /install/*
RUN rm -rf /install/


COPY src/ja3-window.py /usr/local/bin/

CMD /usr/local/bin/ja3-window.py

