FROM python:3.8
RUN apt-get update && apt-get -y install nmap
ENV OS_CONFIG_FOLDER /data/config/tcpprobe/
ADD . /code
WORKDIR /code
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "tcpprobe.py"]
