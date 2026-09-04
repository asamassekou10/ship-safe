FROM python:3.12-slim
RUN pip install hermes-agent==0.21.0
COPY .hermes /root/.hermes
ENTRYPOINT ["hermes", "gateway"]
