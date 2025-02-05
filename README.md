# Docker Network Project

This project sets up a network of Docker containers consisting of two clients and one server. The clients generate network traffic and send packets to the server, which displays the received packets and predicts the type of traffic by machine learning.

## Project Structure

```
docker-network-project
├── project-fakeTraffic
├── project-realTraffic
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
