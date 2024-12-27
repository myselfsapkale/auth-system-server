# Use the official Node.js image as the base
FROM node:22

# Set the working directory inside the container
WORKDIR /app

# Copy the package.json and package-lock.json to install dependencies
COPY package*.json ./

# Install development dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Expose the port the application will run on
EXPOSE 8000

# Command to run the application in development mode
CMD ["npm", "run", "dev"]
