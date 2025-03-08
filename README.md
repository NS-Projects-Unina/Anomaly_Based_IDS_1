# Docker Network Project

This project sets up different networks of Docker containers for tesing an AI-Powered NIDS (Network Intrusion Detection System). There are four different subprojects: each of them with different approach.

## Project Structure

```
docker-network-project
├── project-fakeTraffic
├── project-realTraffic
├── catturaTraffico
├── datasetGenerato
├── machineLearning
└── README.md
```

## Getting Started

### Prerequisites

- Docker
- Docker Compose

### Building the Containers

To build the Docker images for the clients and server, run the following command in the root directory of the project:

```
docker-compose build
```

### Running the Containers

To start the containers, use the following command:

```
docker-compose up
```

This will start the server and both clients. The server will listen for incoming packets and display them in the console.

### Stopping the Containers

To stop the running containers, press `Ctrl + C` in the terminal where the containers are running, or run:

```
docker-compose down
```

## License

This project is licensed under the MIT License.
