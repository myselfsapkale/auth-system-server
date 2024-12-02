# Bus-Ticket-Booking

## Description

This project is created for learning purposes. It is a bus ticket booking application where users can book tickets for bus journeys. The project uses the latest version of Angular for the front-end and Node.js for the back-end. Additionally, it utilizes WebSockets for real-time updates and MySQL for the database.

Current service is AUTH service which we use to authenticate and authorize users


## ## With Docker
## Prerequisites

1. Docker should be installed

2. Install all the dependencies from root directory run this command:
    ```bash
    docker-compose up
    ```


## ## Without Docker
## Prerequisites

- Node.js (latest version)
- MySQL installed on your machine
- Redis installed on your machine


## Project Setup


1. Install the dependencies:
    ```bash
    npm i
    ```

2. Create a `.env` file and take reference from `/installation_help/env.js`.

3. Import the `mysqldemo.sql` file into your MySQL database file path `/installation_help/mysqldemo.sql`.

4. Start MySQL and Redis server

5. Start the server:
    ```bash
    npm start
    ```

## Additional Information

- Ensure MySQL is running and properly configured.
- Ensure Redis is running and properly configured.
- Make sure to set up the database schema as required by the application.
- For any issues, please check the logs or reach out to the support team.

Support Email - dev.psapkale@gmail.com