# Use explicit Node version
FROM node:20-alpine AS builder

WORKDIR /usr/src/app

COPY package*.json ./

# Install all dependencies (including dev for any build scripts if necessary)
RUN npm ci

COPY . .

# Separate production stage
FROM node:20-alpine

WORKDIR /usr/src/app

# Set production env
ENV NODE_ENV=production

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --omit=dev

# Copy source code and scripts from builder
COPY --from=builder /usr/src/app/src ./src
COPY --from=builder /usr/src/app/scripts ./scripts

# Set basic permissions and ownership
RUN chown -R node:node /usr/src/app

# Switch to non-root user
USER node

# Expose port (default 3000)
EXPOSE 3000

# Command to run
CMD ["node", "src/server.js"]
