# Docker Network Project

This project sets up a network of Docker containers consisting of two clients and one server. The clients generate network traffic and send packets to the server, which displays the received packets.

## Project Structure

```
docker-network-project
├── client1
│   ├── Dockerfile
│   └── app
│       └── client1.py
├── client2
│   ├── Dockerfile
│   └── app
│       └── client2.py
├── server
│   ├── Dockerfile
│   └── app
│       └── server.py
├── docker-compose.yml
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

## Client Implementation

- **client1/app/client1.py**: This script generates network traffic and sends packets to the server.
- **client2/app/client2.py**: This script also generates network traffic and sends packets to the server.

## Server Implementation

- **server/app/server.py**: This script listens for incoming packets from the clients and displays the received network packets.

## License

This project is licensed under the MIT License.