# --- Stage 1: build the DPI engine binary ---
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends g++ && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY include ./include
COPY src ./src
RUN g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp src/pcap_reader.cpp src/packet_parser.cpp \
    src/sni_extractor.cpp src/types.cpp

# --- Stage 2: run the web wrapper ---
FROM python:3.12-slim
WORKDIR /app
COPY webapp/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY webapp/app.py .
COPY webapp/static ./static
COPY webapp/sample ./sample
COPY --from=build /src/dpi_simple .
RUN chmod +x dpi_simple

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
