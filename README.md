# DDoS Detection System

A Distributed Denial of Service Attack detection system applying Machine Learning techniques.


## Architecture

The system is structured into three main files:
- `captura.py`: Handles data capture of network traffic.
- `analisis.py`: Performs data analysis and model prediction of each capture.
- `monitor.py`: Monitors the entire system and coordinates the two previous scripts.
 
[![Architecture](https://i.postimg.cc/BbTBT2nT/Arquitectura-TFG-drawio-4.png)](https://postimg.cc/jnjfKwN2)
## Run Locally

Clone the project

```bash
  git clone https://github.com/dacostaluna/DDoS_Detection_ML
```

Go to the project directory

```bash
  cd DDoS_Detection_ML
```



## Configuration

To install and configure the system, follow the steps below:

### Database Configuration

Edit `analisis.py`:
   - You need to modify the database configuration parameters to connect to your own PostgreSQL database.

### Pre-trained Model

- The pre-trained model, along with the StandardScaler and LabelEncoder, are included in the `models` directory.
- If you wish to use the pre-compiled model, no further action is needed.

### Training Your Own Model

If you prefer to train your own model instead of using the pre-trained one:
   - The code to train the model is provided in `training.ipynb`.
   - Modify the initial path in the notebook to point to your CSV dataset files.
   - Download the [dataset](https://www.unb.ca/cic/datasets/ddos-2019.html) and ensure the path is correctly set.

### Grafana for Data Visualization

To visualize the data using Grafana:

1. Install PostgreSQL:
- Install and configure a PostgreSQL database locally or remotely.

2. Edit `analisis.py`:
- Ensure the database configuration parameters are set correctly to connect to your PostgreSQL database.

3. Install and Configure Grafana:
- Install [Grafana](https://grafana.com/) on your system.
- Import the provided dashboard configuration file (`grafana_dashboard.json`) into Grafana. This file contains the pre-configured panels and settings.
- Connect the PostgreSQL database with Grafana in the configuration
## Usage

1. Run `captura.py` to start data capture.
2. Run `monitor.py` to start the analysis for each capture.
3. Access Grafana to visualize the predictions, monitor system performance and be alert to DDoS attacks.
## Authors

- [@dacostaluna](https://www.github.com/dacostaluna)

