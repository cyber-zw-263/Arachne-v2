#!/bin/bash
# Deploy Arachne to AWS/Azure/GCP

set -e

echo "Deploying Arachne v2.0 to cloud..."

# Configuration
CLOUD_PROVIDER=${1:-aws}
REGION=${2:-us-east-1}
INSTANCE_TYPE=${3:-t3.xlarge}

case $CLOUD_PROVIDER in
    aws)
        echo "Deploying to AWS..."
        # Create security group
        aws ec2 create-security-group --group-name arachne-sg --description "Arachne Security Group"
        aws ec2 authorize-security-group-ingress --group-name arachne-sg --protocol tcp --port 22 --cidr 0.0.0.0/0
        aws ec2 authorize-security-group-ingress --group-name arachne-sg --protocol tcp --port 8080 --cidr 0.0.0.0/0
        
        # Launch instance
        INSTANCE_ID=$(aws ec2 run-instances \
            --image-id ami-0c55b159cbfafe1f0 \
            --instance-type $INSTANCE_TYPE \
            --key-name arachne-key \
            --security-groups arachne-sg \
            --user-data file://scripts/cloud_init.sh \
            --query 'Instances[0].InstanceId' \
            --output text)
        
        echo "Instance $INSTANCE_ID launching..."
        ;;
    
    azure)
        echo "Deploying to Azure..."
        az vm create \
            --resource-group arachne-rg \
            --name arachne-vm \
            --image Ubuntu2204 \
            --admin-username arachne \
            --generate-ssh-keys \
            --size $INSTANCE_TYPE \
            --custom-data scripts/cloud_init.sh
        ;;
    
    gcp)
        echo "Deploying to GCP..."
        gcloud compute instances create arachne-vm \
            --zone=${REGION}-a \
            --machine-type=$INSTANCE_TYPE \
            --image-family=ubuntu-2204-lts \
            --image-project=ubuntu-os-cloud \
            --metadata-from-file startup-script=scripts/cloud_init.sh
        ;;
esac

echo "Deployment initiated. Access dashboard at http://<IP>:8080 after provisioning."