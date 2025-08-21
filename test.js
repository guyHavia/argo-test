// AWS IMDSv2 Client for Node.js
const http = require('http');

class IMDSv2Client {
    constructor(tokenTTL = 21600) { // 6 hours default
        this.baseURL = 'http://169.254.169.254';
        this.tokenTTL = tokenTTL;
        this.token = null;
        this.tokenExpiry = null;
    }

    // Make HTTP request helper
    makeRequest(options, data = null) {
        return new Promise((resolve, reject) => {
            const req = http.request(options, (res) => {
                let body = '';
                
                res.on('data', (chunk) => {
                    body += chunk;
                });
                
                res.on('end', () => {
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        resolve(body);
                    } else {
                        reject(new Error(`HTTP ${res.statusCode}: ${body}`));
                    }
                });
            });

            req.on('error', (err) => {
                reject(err);
            });

            req.setTimeout(5000, () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            if (data) {
                req.write(data);
            }
            
            req.end();
        });
    }

    // Get session token
    async getToken() {
        const options = {
            hostname: '169.254.169.254',
            path: '/latest/api/token',
            method: 'PUT',
            headers: {
                'X-aws-ec2-metadata-token-ttl-seconds': this.tokenTTL.toString()
            },
            timeout: 5000
        };

        try {
            this.token = await this.makeRequest(options);
            this.tokenExpiry = Date.now() + (this.tokenTTL * 1000);
            console.log('✓ IMDSv2 token acquired successfully');
            return this.token;
        } catch (error) {
            throw new Error(`Failed to get IMDS token: ${error.message}`);
        }
    }

    // Check if token is valid
    isTokenValid() {
        return this.token && this.tokenExpiry && Date.now() < this.tokenExpiry;
    }

    // Ensure we have a valid token
    async ensureToken() {
        if (!this.isTokenValid()) {
            await this.getToken();
        }
    }

    // Get metadata from IMDS
    async getMetadata(path) {
        await this.ensureToken();

        const options = {
            hostname: '169.254.169.254',
            path: `/latest/meta-data${path}`,
            method: 'GET',
            headers: {
                'X-aws-ec2-metadata-token': this.token
            },
            timeout: 5000
        };

        try {
            return await this.makeRequest(options);
        } catch (error) {
            throw new Error(`Failed to get metadata from ${path}: ${error.message}`);
        }
    }

    // Get user data
    async getUserData() {
        await this.ensureToken();

        const options = {
            hostname: '169.254.169.254',
            path: '/latest/user-data',
            method: 'GET',
            headers: {
                'X-aws-ec2-metadata-token': this.token
            },
            timeout: 5000
        };

        try {
            return await this.makeRequest(options);
        } catch (error) {
            throw new Error(`Failed to get user data: ${error.message}`);
        }
    }

    // Get instance identity document
    async getInstanceIdentity() {
        await this.ensureToken();

        const options = {
            hostname: '169.254.169.254',
            path: '/latest/dynamic/instance-identity/document',
            method: 'GET',
            headers: {
                'X-aws-ec2-metadata-token': this.token
            },
            timeout: 5000
        };

        try {
            const data = await this.makeRequest(options);
            return JSON.parse(data);
        } catch (error) {
            throw new Error(`Failed to get instance identity: ${error.message}`);
        }
    }

    // Get IAM credentials
    async getCredentials(roleName = null) {
        try {
            if (!roleName) {
                // Get the role name first
                const roles = await this.getMetadata('/iam/security-credentials/');
                roleName = roles.trim();
            }

            const credData = await this.getMetadata(`/iam/security-credentials/${roleName}`);
            return JSON.parse(credData);
        } catch (error) {
            throw new Error(`Failed to get IAM credentials: ${error.message}`);
        }
    }

    // Convenience methods for common metadata
    async getInstanceId() {
        return await this.getMetadata('/instance-id');
    }

    async getInstanceType() {
        return await this.getMetadata('/instance-type');
    }

    async getAvailabilityZone() {
        return await this.getMetadata('/placement/availability-zone');
    }

    async getRegion() {
        return await this.getMetadata('/placement/region');
    }

    async getPublicIPv4() {
        return await this.getMetadata('/public-ipv4');
    }

    async getPrivateIPv4() {
        return await this.getMetadata('/local-ipv4');
    }

    async getAMIId() {
        return await this.getMetadata('/ami-id');
    }

    async getHostname() {
        return await this.getMetadata('/hostname');
    }
}

// Usage example and demo
async function demo() {
    const client = new IMDSv2Client();

    try {
        console.log('🚀 Starting AWS IMDSv2 Demo...\n');

        // Get basic instance information
        console.log('📋 Basic Instance Information:');
        console.log(`Instance ID: ${await client.getInstanceId()}`);
        console.log(`Instance Type: ${await client.getInstanceType()}`);
        console.log(`Availability Zone: ${await client.getAvailabilityZone()}`);
        console.log(`Region: ${await client.getRegion()}`);
        console.log(`AMI ID: ${await client.getAMIId()}`);

        // Get network information
        console.log('\n🌐 Network Information:');
        try {
            console.log(`Public IPv4: ${await client.getPublicIPv4()}`);
        } catch (e) {
            console.log('Public IPv4: Not available (private instance)');
        }
        console.log(`Private IPv4: ${await client.getPrivateIPv4()}`);
        console.log(`Hostname: ${await client.getHostname()}`);

        // Get instance identity document
        console.log('\n🆔 Instance Identity Document:');
        const identity = await client.getInstanceIdentity();
        console.log(JSON.stringify(identity, null, 2));

        // Try to get IAM credentials
        console.log('\n🔐 IAM Credentials:');
        try {
            const credentials = await client.getCredentials();
            console.log(`Access Key ID: ${credentials.AccessKeyId}`);
            console.log(`Secret Access Key: ${credentials.SecretAccessKey.substring(0, 10)}...`);
            console.log(`Token: ${credentials.Token.substring(0, 20)}...`);
            console.log(`Expiration: ${credentials.Expiration}`);
        } catch (e) {
            console.log('IAM credentials not available (no IAM role attached)');
        }

        // Try to get user data
        console.log('\n📄 User Data:');
        try {
            const userData = await client.getUserData();
            console.log(userData || 'No user data available');
        } catch (e) {
            console.log('No user data available');
        }

    } catch (error) {
        console.error('❌ Error:', error.message);
        
        if (error.message.includes('ECONNREFUSED') || error.message.includes('timeout')) {
            console.log('\n💡 This script must be run from an EC2 instance to access IMDS.');
        }
    }
}

// Browser version (for completeness, though IMDS won't work in browser due to CORS)
const browserIMDSClient = `
class BrowserIMDSv2Client {
    constructor(tokenTTL = 21600) {
        this.baseURL = 'http://169.254.169.254';
        this.tokenTTL = tokenTTL;
        this.token = null;
        this.tokenExpiry = null;
    }

    async getToken() {
        const response = await fetch('http://169.254.169.254/latest/api/token', {
            method: 'PUT',
            headers: {
                'X-aws-ec2-metadata-token-ttl-seconds': this.tokenTTL.toString()
            }
        });

        if (!response.ok) {
            throw new Error('Failed to get IMDS token');
        }

        this.token = await response.text();
        this.tokenExpiry = Date.now() + (this.tokenTTL * 1000);
        return this.token;
    }

    async getMetadata(path) {
        if (!this.token || Date.now() >= this.tokenExpiry) {
            await this.getToken();
        }

        const response = await fetch(\`http://169.254.169.254/latest/meta-data\${path}\`, {
            headers: {
                'X-aws-ec2-metadata-token': this.token
            }
        });

        if (!response.ok) {
            throw new Error(\`Failed to get metadata from \${path}\`);
        }

        return await response.text();
    }
}

// Note: Browser version won't work due to CORS restrictions
// IMDS is designed to be accessed only from the EC2 instance itself
`;

// Export for use as module
module.exports = IMDSv2Client;

// Run demo if script is executed directly
if (require.main === module) {
    demo();
}
