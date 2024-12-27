# Stage 1: Build
FROM node:22-slim AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the package.json and package-lock.json to install dependencies
COPY package*.json ./

# Install development dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Creating build of typescript project
RUN npm run build

# Remove unwanted stuff
RUN rm -rf installation_help src tsconfig.json node_modules


## Stage 2: Production
FROM node:22-slim

# Set the working directory
WORKDIR /app

# Copy only the necessary build artifacts and dependencies from the builder
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/.env ./.env

# Install only production dependencies
RUN npm install --production

# Expose the port the application will run on
EXPOSE 8000

# Command to run the application in development mode
CMD ["npm", "run", "start"]
