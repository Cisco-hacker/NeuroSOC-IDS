# NeuroSOC-IDS

Machine Learning Powered Security Operations Center (SOC) built with XGBoost, FastAPI, Elasticsearch and Kibana for network intrusion detection.

## Overview

NeuroSOC-IDS is a lightweight SOC platform that combines machine learning-based intrusion detection with real-time security monitoring.

The system uses a trained XGBoost model on CICIDS2017 network flow features to classify traffic as Benign or Attack. Predictions are stored in Elasticsearch and visualized through Kibana dashboards.

## Features

- XGBoost-based intrusion detection
- FastAPI inference server
- Elasticsearch event storage
- Kibana SOC dashboard
- Batch prediction API
- CICIDS2017 replay engine
- Dockerized deployment
- Confidence scoring for predictions

## Architecture

```text
CICIDS2017 Dataset
        │
        ▼
Replay Engine
(cicids_replay.py)
        │
        ▼
FastAPI Model Server
(XGBoost)
        │
        ▼
Elasticsearch
        │
        ▼
Kibana Dashboard
```

## Tech Stack

- Python 3.11
- XGBoost
- FastAPI
- Pandas
- Elasticsearch 8.x
- Kibana 8.x
- Docker Compose

## Project Structure

```text
NeuroSOC-IDS/
│
├── README.md
├── docker-compose.yml
├── .gitignore
│
├── dashboards/
├── docs/
│
├── replay/
│   └── cicids_replay.py
│
└── model-server/
    ├── Dockerfile
    ├── main.py
    ├── requirements.txt
    └── ids_model/
```

## Running the Project

### Clone Repository

```bash
git clone https://github.com/Cisco-hacker/NeuroSOC-IDS.git
cd NeuroSOC-IDS
```

### Start Services

```bash
docker compose up -d
```

### Verify Services

FastAPI:

```text
http://localhost:8000/docs
```

Elasticsearch:

```text
http://localhost:9200
```

Kibana:

```text
http://localhost:5601
```

## Replay Engine

The replay engine reads CICIDS2017 CSV flows, submits them to the FastAPI model server, receives predictions, and stores results in Elasticsearch for dashboard visualization.

Example:

```bash
python replay/cicids_replay.py
```

## API Endpoints

### Health Check

```http
GET /health
```

### Feature List

```http
GET /features
```

### Single Prediction

```http
POST /predict
```

### Batch Prediction

```http
POST /predict/batch
```

### Model Statistics

```http
GET /stats
```

## Dashboard

The Kibana dashboard provides:

- Prediction distribution
- Attack timeline
- Top source IPs
- Confidence monitoring
- Alert statistics

Dashboard screenshot:

![Dashboard](docs/dashboard.png)

## Dataset

This project was developed using the CICIDS2017 dataset.

Download:

https://www.unb.ca/cic/datasets/ids-2017.html

Place the desired CSV file in the project root before running the replay engine.

## Future Improvements

- Real-time packet capture
- Zeek integration
- Suricata integration
- Automated alerting
- Threat intelligence enrichment
- SIEM correlation rules

## Disclaimer

This project is intended for educational and research purposes only.