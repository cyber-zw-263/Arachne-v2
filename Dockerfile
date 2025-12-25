FROM python:3.11-slim
WORKDIR /arachne
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "arachne_core.py"]